# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The context path: the wire, the ingress caps, safe extraction, policy.

Every test here sends real bytes over a real socket. That is deliberate
and it is what the previous skeleton could not do: the caps of ADR 0019
decision 8 are specified as *streaming*, and a cap can only be shown to
be streaming by being fed something that would be fatal if it were not.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
from dataclasses import replace
from pathlib import Path

import pytest
import zstandard

from mcuhome_buildserver import contextstore, protocol, sessions
from mcuhome_buildserver.app import ServerState, create_app
from mcuhome_buildserver.config import Config
from tests.conftest import (
    CONTEXT_YAML,
    IMAGE_LABELS,
    IMAGE_REFERENCE_FORMAT3,
    auth,
    base_context,
    call,
    make_archive,
    make_archive_from,
    send_archive,
)

MODEL = b'{"device": {"board": "nrf7002dk/nrf5340/cpuapp"}}'
PATCH = b"--- a/x\n+++ b/x\n"


async def open_session(ws) -> str:
    frame = await call(
        ws, "open-session", {"protocol_version": sessions.SESSION_PROTOCOL_VERSION}, frame_id="o"
    )
    return frame["payload"]["session"]["id"]


async def serve(aiohttp_client, config: Config, **overrides):
    """A client and its state, for a server configured differently."""
    state = ServerState(replace(config, **overrides))
    return await aiohttp_client(create_app(state)), state


# --------------------------------------------------------------------------
# send-context: the wire E41 settled
# --------------------------------------------------------------------------


async def test_send_context_accepts_a_base_context_and_answers_its_pins(client) -> None:
    """The happy path, and the shape of the answer.

    ADR 0019 §2 spells ``send-context(archive)`` and that one word is the
    whole wire specification the verb set gives it; the rest is E41 —
    the JSON payload announces the compressed size and the SHA-256, the
    bytes follow as BINARY frames, and the verb's own result frame is
    the acknowledgement. What comes back is what this server decided:
    the pins it accepted and where the context now stands.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(
            ws, "send-context", session_id, base_context(**{"model/device-model.json": MODEL})
        )

    assert frame["type"] == "result", frame
    body = frame["payload"]
    assert body["session_id"] == session_id
    assert body["context"] == {
        "state": sessions.CONTEXT_UNLOCKED,
        "format": sessions.CONTEXT_FORMAT_MAX,
    }
    assert body["pins"]["mcuhome"]["package"]["sha256"] == "a" * 64
    # Format 3: the client pins the build environment with full reference + digest
    assert body["pins"]["build_environment"].startswith(
        "ghcr.io/mcu-home/build-container:zephyr-4.4.0-r10@sha256:"
    )
    assert body["pins"]["target"] == {"board": "nrf7002dk/nrf5340/cpuapp"}


async def test_send_context_answers_the_serving_container(client) -> None:
    """ADR 0019's amendment gives ``send-context`` the container half of
    the discovery payload — the serving build container's contract
    version and its command set — because only the context determines
    it: the requirement arrives with the pins, and ``open-session``
    therefore cannot answer it truthfully.

    Since E61 the block is a **resolution**: the context named no image,
    so ``image``, ``tag`` and ``digest`` are what this server chose for
    the Zephyr line it was asked for, and they are the same three names
    ``manifest.yaml`` will carry. The rest comes from ``describe`` rather
    than from the image labels — ``describe`` is authoritative about what
    a program can do; the labels are a pre-start hint the backend
    cross-checks against it and must not rely on where the two disagree.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, base_context())

    assert set(frame["payload"]) == {"session_id", "context", "pins", "container"}
    serving = frame["payload"]["container"]
    # Format 3: the serving container is named by build_environment (reference with digest)
    # The server normalizes to just repository@digest, the digest is what identifies the image
    assert serving["build_environment"] == f"ghcr.io/mcu-home/build-container@sha256:{'b' * 64}"
    assert serving["contract"] == 1
    assert serving["program"] == "org.mcuhome.build-container"
    assert serving["actions"] == ["describe", "verify", "build"]


async def test_a_context_requiring_a_line_this_host_lacks_is_refused(client, docker) -> None:
    """``version.builder-unsatisfiable``, at the moment the pins arrive.

    Format 3: the client pins the build environment with a full reference.
    The server looks for the pinned image in its local inventory. If not
    found, it is a final answer (not retryable) rather than a fetch this
    server declined to make. Refusing at ``send-context`` is the useful
    moment: the client can go to a server that serves the image, without
    having paid for a lock.

    The details name both sides: the reference required (what the client
    pinned) and the references this server actually has.
    """
    docker.images.clear()
    docker.listed = []
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, base_context())

    error = frame["error"]
    assert error["code"] == "version.builder-unsatisfiable"
    assert error["retryable"] is False
    assert (
        error["details"]["required"]
        == f"ghcr.io/mcu-home/build-container:zephyr-4.4.0-r10@sha256:{'b' * 64}"
    )
    assert error["details"]["available"] == []


async def test_a_context_requiring_another_line_than_the_inventory_serves(client, docker) -> None:
    """Format 3: the client pins a specific image digest.

    When this host has images of the same repository but with different
    digests (different releases), and the pinned digest is not available,
    the server refuses. The offered references travel in the details so the
    client or operator can see what is actually available.
    """
    # Clear all images and add only a different release
    docker.images.clear()
    docker.listed = []

    other_digest = "sha256:" + "e" * 64
    other_tag = "zephyr-4.4.2-r1"
    other_ref = f"ghcr.io/mcu-home/build-container:{other_tag}"
    other_digest_ref = f"ghcr.io/mcu-home/build-container@{other_digest}"

    docker.images[other_digest_ref] = {
        "Id": "sha256:" + "d" * 64,
        "RepoTags": [other_ref],
        "RepoDigests": [other_digest_ref],
        "Config": {"Labels": dict(IMAGE_LABELS)},
    }
    docker.images[other_ref] = docker.images[other_digest_ref]
    docker.listed = [other_ref]

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, base_context())

    error = frame["error"]
    assert error["code"] == "version.builder-unsatisfiable"
    # The required field contains the full reference the client pinned (with tag and digest)
    assert (
        error["details"]["required"]
        == f"ghcr.io/mcu-home/build-container:zephyr-4.4.0-r10@sha256:{'b' * 64}"
    )
    # Available should list what references the server has
    assert len(error["details"]["available"]) > 0


async def test_a_container_runtime_that_is_down_is_retryable(client, docker) -> None:
    """``builder.runtime-unavailable`` — and it is the retryable one.

    Nothing about the context is wrong, the session is untouched, and
    the same command works once the daemon is up. That is exactly what
    ``retryable: true`` promises, and it is why a missing *image* does
    not share the code: an image that is not on this host will not
    appear on its own.
    """
    docker.version_status = 1
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, base_context())

    error = frame["error"]
    assert error["code"] == "builder.runtime-unavailable"
    assert error["retryable"] is True


async def test_the_context_lands_in_a_directory_the_server_owns(client, state) -> None:
    """ "Into a per-session directory the server owns" (decision 8).

    Named by session id under the configured context root, and not
    readable by anyone else on the host: the context carries a device's
    commissioning credentials for as long as the session lives.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws, "send-context", session_id, base_context(**{"model/device-model.json": MODEL})
        )
        paths = state.sessions.require(session_id).paths

    assert paths is not None
    assert paths.root.parent == state.config.context_root
    assert paths.root.name == session_id
    assert (paths.context / "model/device-model.json").read_bytes() == MODEL
    assert paths.root.stat().st_mode & 0o077 == 0


async def test_a_second_base_context_is_refused_rather_than_replacing_the_pins(client) -> None:
    """E43: ``context.exists``, and the message says which verb was meant.

    Not ``context.locked`` — nothing is frozen yet — and not a silent
    replacement: the pins were accepted and answered, and replacing them
    mid-session is the one thing the format forbids for a session's
    lifetime.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, base_context())
        frame = await send_archive(ws, "send-context", session_id, base_context())

    assert frame["error"]["code"] == "context.exists"
    assert frame["error"]["details"]["context_state"] == sessions.CONTEXT_UNLOCKED


async def test_a_base_context_without_context_yaml_is_refused(client, state) -> None:
    """The pin document is required even for an empty context.

    Two of the three inputs of the context ID live in it, so a context
    without one has no identity to freeze. "Empty" in ADR 0019's "a
    context that was sent but is empty may be locked" means no *content*
    files, which is a different thing.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(
            ws, "send-context", session_id, make_archive({"model/device-model.json": MODEL})
        )
        session = state.sessions.require(session_id)

    # The message, not only the code: `bad_request` is also what a
    # `context.yaml` that cannot be *read* produces, so a test that
    # asserted the code alone passed with the rule it names deleted —
    # the missing file simply failed one line further down, in the
    # parser's own stat().
    assert frame["error"]["code"] == "bad_request"
    assert "carries no context.yaml" in frame["error"]["message"]
    assert session.context_state == sessions.CONTEXT_NONE


async def test_a_declared_archive_hash_that_disagrees_is_an_integrity_mismatch(client) -> None:
    """ "Never trust client-declared hashes … the bytes decide."

    The archive hash is the one hash a client declares about the
    transport itself, and it gets the same treatment as every other
    declared value: recomputed from what arrived, and the upload refused
    on a disagreement rather than repaired.
    """
    archive = base_context()
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await ws.send_json(
            {
                "id": "u",
                "type": "send-context",
                "payload": {
                    "session_id": session_id,
                    "archive": {"size": len(archive), "sha256": "c" * 64},
                },
            }
        )
        await ws.send_bytes(archive)
        while (frame := await ws.receive_json(timeout=15)).get("id") != "u":
            pass

    assert frame["error"]["code"] == "context.integrity-mismatch"
    assert frame["error"]["details"]["declared"] == "c" * 64
    assert frame["error"]["details"]["computed"] == hashlib.sha256(archive).hexdigest()


async def test_more_bytes_than_announced_are_cut_off(client) -> None:
    """The announcement bounds the transfer, in both directions.

    Under-declaring is the interesting half: a client that announces a
    kilobyte and then streams a gigabyte would be sending bytes no cap
    had budgeted for, so the count that actually arrives is checked
    against the declaration on every frame.
    """
    archive = base_context()
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await ws.send_json(
            {
                "id": "u",
                "type": "send-context",
                "payload": {
                    "session_id": session_id,
                    "archive": {"size": 8, "sha256": hashlib.sha256(archive).hexdigest()},
                },
            }
        )
        await ws.send_bytes(archive)
        while (frame := await ws.receive_json(timeout=15)).get("id") != "u":
            pass

    assert frame["error"]["code"] == "bad_request"
    assert "announced 8 bytes" in frame["error"]["message"]


async def test_binary_frames_outside_an_announced_upload_are_still_refused(client) -> None:
    """ "The ws layer must accept BINARY frames only while an upload is
    announced, and keep refusing them otherwise" (E41).

    The frame cannot say what it is — it carries no id and no session —
    so the announcement is the only thing that can, and outside one this
    endpoint speaks JSON text frames only, exactly as before.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await open_session(ws)
        await ws.send_bytes(b"\x00\x01\x02")
        frame = await ws.receive_json(timeout=15)
        assert frame["error"]["code"] == "bad_request"
        assert "JSON text frames only" in frame["error"]["message"]
        assert (await call(ws, "capabilities"))["type"] == "result"


async def test_a_body_that_is_not_an_archive_is_a_bad_request(client) -> None:
    """No registry code means "these bytes are not an archive".

    The typed registry describes a session's refusals — a cap, a
    forbidden path, a hash that disagrees — and none of its entries says
    this. Adding one is a protocol decision rather than an
    implementation choice, so the answer is the envelope's own
    pre-registry code instead of an invented one.
    """
    body = b"this is not zstd" * 8
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, body)

    assert frame["error"]["code"] == "bad_request"
    assert "tar.zst" in frame["error"]["message"]


async def test_an_announcement_needs_both_of_its_two_values(client) -> None:
    """Two values and no third: no ``format`` field, and neither optional.

    The format is tar.zst, fixed; a field whose only legal value is the
    default is a negotiation nobody asked for. The two that remain are
    what the caps and the integrity check are made of, so a client that
    omits either is asking for an unbounded, unverifiable transfer.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await call(ws, "send-context", {"session_id": session_id}, frame_id="a")
        assert frame["error"]["code"] == "bad_request"
        frame = await call(
            ws,
            "send-context",
            {"session_id": session_id, "archive": {"size": 10}},
            frame_id="b",
        )
        assert frame["error"]["code"] == "bad_request"


async def test_an_archive_hash_in_the_wrong_spelling_is_refused(client) -> None:
    """One spelling per hash, everywhere (contract §3.3.1).

    The archive hash is not part of any context identity, so nothing
    breaks if it is uppercase — which is exactly why it is worth
    refusing here: a server that accepted two spellings in one place and
    one in another would be teaching clients that the rule is a matter
    of where they are standing.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await call(
            ws,
            "send-context",
            {"session_id": session_id, "archive": {"size": 10, "sha256": "A" * 64}},
            frame_id="a",
        )
    assert frame["error"]["code"] == "bad_request"
    assert "64 lowercase hex" in frame["error"]["message"]


# --------------------------------------------------------------------------
# The five ingress caps
# --------------------------------------------------------------------------


async def test_the_compressed_cap_refuses_before_a_byte_is_accepted(aiohttp_client, config) -> None:
    """A declared size over the budget never starts.

    The compressed cap is checked twice and this is the cheap half:
    refusing the announcement costs nothing, and the expensive half —
    counting what actually arrives — is what catches a client that
    under-declares.
    """
    client, _ = await serve(aiohttp_client, config, max_compressed_bytes=64)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await call(
            ws,
            "send-context",
            {"session_id": session_id, "archive": {"size": 4096, "sha256": "a" * 64}},
            frame_id="a",
        )
    error = frame["error"]
    assert error["code"] == "policy.ingress-limit-exceeded"
    assert error["retryable"] is False
    assert error["details"]["cap"] == "compressed size"


async def test_a_decompression_bomb_is_refused_while_it_expands(aiohttp_client, config) -> None:
    """The case the streaming requirement exists for.

    Fifty megabytes of one repeated byte compress to under two
    kilobytes. A server that decompressed in one call would have
    allocated all fifty before any check ran; this one is handed the
    output in chunks and stops as soon as the cumulative budget is
    spent, so the cost of the bomb is one chunk over the cap.
    """
    bomb = io.BytesIO()
    with tarfile.open(fileobj=bomb, mode="w") as tar:
        info = tarfile.TarInfo("model/big.json")
        info.size = 50 * 1024 * 1024
        tar.addfile(info, io.BytesIO(b"A" * info.size))
    archive = zstandard.ZstdCompressor(level=3).compress(bomb.getvalue())
    assert len(archive) < 64 * 1024, "the point of the test is that the archive is tiny"

    client, state = await serve(aiohttp_client, config, max_decompressed_bytes=1024 * 1024)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
        session = state.sessions.require(session_id)

    error = frame["error"]
    assert error["code"] == "policy.ingress-limit-exceeded"
    assert error["details"]["cap"] == "cumulative decompressed size"
    assert error["details"]["measured"] <= 1024 * 1024 + 131072, "one chunk over, not fifty MiB"
    assert session.context_state == sessions.CONTEXT_NONE


async def test_the_entry_count_cap_fires(aiohttp_client, config) -> None:
    """Many small files are a bomb too, in inode terms.

    Nothing about the byte caps notices ten thousand empty files, which
    is why the entry count is a cap of its own in the ADR's list.
    """
    client, _ = await serve(aiohttp_client, config, max_entries=3)
    archive = base_context(**{f"model/{index}.json": b"{}" for index in range(6)})
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
    assert frame["error"]["details"]["cap"] == "entry count"


async def test_the_per_file_cap_fires_on_the_header_and_only_there(aiohttp_client, config) -> None:
    """One entry may not spend the whole cumulative budget.

    There is exactly **one** enforcement point, and the assertion on
    ``measured`` is what says which: the entry's declared header size,
    refused before a byte of it is copied. The streaming check that used
    to sit beside it could not fire — ``tarfile.extractfile`` bounds its
    reader at the header size, so the bytes that appear never exceed the
    number already refused — and while both existed, either could be
    deleted with this test still green.
    """
    client, _ = await serve(aiohttp_client, config, max_file_bytes=1024)
    archive = base_context(**{"model/device-model.json": b"x" * 4096})
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
    error = frame["error"]
    assert error["details"]["cap"] == "per-file size"
    assert error["details"]["entry"] == "model/device-model.json"
    assert error["details"]["limit"] == 1024
    assert error["details"]["measured"] == 4096, "the header, not a count of copied bytes"


async def test_the_path_depth_cap_fires(aiohttp_client, config) -> None:
    """Depth is a cap because a path is work for every component of it."""
    client, _ = await serve(aiohttp_client, config, max_path_depth=2)
    archive = base_context(**{"model/a/b/c.json": b"{}"})
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
    assert frame["error"]["details"]["cap"] == "path depth"


def _decompressed(archive: bytes) -> int:
    """The tar stream inside *archive*, which is what the spool counts."""
    return len(zstandard.ZstdDecompressor().decompress(archive, max_output_size=1 << 26))


@pytest.mark.parametrize(
    "budget",
    ["compressed size", "cumulative decompressed size", "entry count", "disk quota"],
)
async def test_every_budget_counts_across_the_base_context_and_its_extensions(
    aiohttp_client, config, budget
) -> None:
    """E44: cumulative, because ``extend-context`` is repeatable.

    A per-archive cap would bound nothing at all — a client would send
    the same bytes twice — so the budget belongs to the session and an
    extension spends what the base context left.

    All four are exercised, because all four had the same failure mode
    available and only one was pinned. Each case sets the budget to *one
    unit less than the two archives together*, so the extension fits
    comfortably on its own and only the base context's spending refuses
    it: turning any of these back into a per-archive or per-file limit
    passes the base, passes the extension, and fails here.
    """
    key = b"public key"
    base = base_context(**{"model/device-model.json": MODEL})
    extension = make_archive({"keys/signing.pub": key})
    on_disk = len(CONTEXT_YAML.encode()) + len(MODEL)
    override, measured = {
        "compressed size": (
            {"max_compressed_bytes": len(base) + len(extension) - 1},
            len(base) + len(extension),
        ),
        "cumulative decompressed size": (
            {"max_decompressed_bytes": _decompressed(base) + _decompressed(extension) - 1},
            _decompressed(base) + _decompressed(extension),
        ),
        "entry count": ({"max_entries": 2}, 3),
        "disk quota": ({"session_quota_bytes": on_disk + len(key) - 1}, on_disk + len(key)),
    }[budget]

    client, _ = await serve(aiohttp_client, config, **override)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        accepted = await send_archive(ws, "send-context", session_id, base)
        assert accepted["type"] == "result", accepted
        frame = await send_archive(ws, "extend-context", session_id, extension)

    error = frame["error"]
    if budget == "disk quota":
        assert error["code"] == "policy.quota-exceeded"
        assert error["details"]["quota"] == on_disk + len(key) - 1
    else:
        assert error["code"] == "policy.ingress-limit-exceeded"
        assert error["details"]["cap"] == budget
    assert error["details"]["measured"] == measured, "the base context's spending is included"


async def test_the_session_disk_quota_is_answered_typed(aiohttp_client, config) -> None:
    """ "Typed quota-exceeded instead of host exhaustion" (decision 8).

    Retryable, unlike the ingress caps: a budget frees up when a session
    closes, while an archive that is too large stays too large.
    """
    client, _ = await serve(aiohttp_client, config, session_quota_bytes=512)
    archive = base_context(**{"model/device-model.json": b"x" * 4096})
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
    assert frame["error"]["code"] == "policy.quota-exceeded"
    assert frame["error"]["retryable"] is True


# --------------------------------------------------------------------------
# Safe extraction
# --------------------------------------------------------------------------


def _member(name: str, kind: int, **fields) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    for key, value in fields.items():
        setattr(info, key, value)
    return info


@pytest.mark.parametrize(
    ("what", "archive_entries", "extras"),
    [
        ("absolute path", {"/etc/passwd": b"root"}, None),
        ("parent traversal", {"model/../../escape.json": b"{}"}, None),
        ("symlink", {}, [_member("model/link", tarfile.SYMTYPE, linkname="/etc/passwd")]),
        ("hardlink", {}, [_member("model/link", tarfile.LNKTYPE, linkname="context.yaml")]),
        ("device node", {}, [_member("model/null", tarfile.CHRTYPE, devmajor=1, devminor=3)]),
        ("outside the whitelist", {"evil.sh": b"#!/bin/sh"}, None),
        ("nested under a patch layer", {"patches/zephyr/deep/0001.patch": PATCH}, None),
        ("a file directly under patches", {"patches/0001.patch": PATCH}, None),
        ("manifest.yaml", {"manifest.yaml": b"context: 1"}, None),
        # The directory half of the same whitelist. Both cases were
        # untested, and `_check_directory_target` could be made to return
        # immediately with the suite green: the one directory entry in
        # this table was `patches/zephyr`, which `check_patch_layer`
        # answers rather than the whitelist.
        ("a directory outside the whitelist", {}, [_member("evil", tarfile.DIRTYPE)]),
        (
            "a directory nested under a patch layer",
            {},
            [_member("patches/zephyr/deep", tarfile.DIRTYPE)],
        ),
        # A name no filesystem can hold. Not a whitelist case: it reached
        # `open()` and came back as ENAMETOOLONG, so client-controlled
        # input produced an untyped internal_error.
        ("a path component the filesystem cannot hold", {f"model/{'n' * 300}": b"{}"}, None),
    ],
)
async def test_unsafe_entries_are_refused_by_shape(client, what, archive_entries, extras) -> None:
    """The zip-slip guard, one case per way out of the directory.

    Regular files and directories only, confined to the subtrees the
    context format defines. ``manifest.yaml`` is in the list for a
    different reason than the rest: it is not dangerous, it is *written
    by this side at the lock*, so an archive that carries one is trying
    to hand the server the result of a computation it has not made.
    """
    entries = {"context.yaml": CONTEXT_YAML.encode(), **archive_entries}
    archive = make_archive(entries, extras=extras)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
    assert frame["error"]["code"] == "context.unsafe-entry", what


async def test_a_refused_upload_leaves_the_session_exactly_as_it_was(client, state) -> None:
    """Bytes discarded, directory gone, session standing.

    A context is one artifact and half of one has no meaning, so a
    refusal takes the whole upload with it — and the session survives so
    the client can send a corrected context over it rather than
    re-negotiating a new one.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        archive = make_archive({"context.yaml": CONTEXT_YAML.encode(), "evil.sh": b"#!/bin/sh"})
        refused = await send_archive(ws, "send-context", session_id, archive)
        assert refused["error"]["code"] == "context.unsafe-entry"
        session = state.sessions.require(session_id)
        assert session.context_state == sessions.CONTEXT_NONE
        assert session.paths is None
        assert (
            not any(state.config.context_root.glob("*"))
            or not (state.config.context_root / session_id).exists()
        )

        accepted = await send_archive(ws, "send-context", session_id, base_context())
    assert accepted["type"] == "result"


async def test_the_archives_own_mode_bits_are_discarded(client, state) -> None:
    """A mode is not context content.

    Nothing in the format or the contract reads one, so honouring it
    would only let an archive ask for bits — setuid above all — on a
    file this server owns and later mounts into a build environment.
    """
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, data, mode in (
            ("context.yaml", CONTEXT_YAML.encode(), 0o644),
            ("model/device-model.json", MODEL, 0o4777),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            tar.addfile(info, io.BytesIO(data))
    archive = zstandard.ZstdCompressor().compress(raw.getvalue())

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, archive)
        paths = state.sessions.require(session_id).paths

    assert paths is not None
    assert (paths.context / "model/device-model.json").stat().st_mode & 0o7777 == 0o600


# --------------------------------------------------------------------------
# Patch policy: the config IS the policy
# --------------------------------------------------------------------------


async def test_a_denied_patch_layer_fails_the_whole_send(client, state) -> None:
    """Deny by default, and wholesale.

    "The server's builder config is the policy; unlisted patch layers
    are denied by default" — and with nothing configured, that is every
    layer. The context is refused as a unit rather than stripped of its
    patches, because a context minus its patches is a different build.
    """
    archive = base_context(**{"patches/zephyr/0001-fix.patch": PATCH})
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
        session = state.sessions.require(session_id)

    error = frame["error"]
    assert error["code"] == "policy.patch-layer-denied"
    assert error["details"]["layer"] == "zephyr"
    assert error["details"]["allowed"] == []
    assert session.context_state == sessions.CONTEXT_NONE


async def test_an_allowed_layer_passes_and_the_patch_lands(aiohttp_client, config) -> None:
    """The other half of the same rule, so "denied" is not just "broken"."""
    client, state = await serve(aiohttp_client, config, allowed_patch_layers=("zephyr",))
    archive = base_context(**{"patches/zephyr/0001-fix.patch": PATCH})
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
        paths = state.sessions.require(session_id).paths

    assert frame["type"] == "result", frame
    assert paths is not None
    assert (paths.context / "patches/zephyr/0001-fix.patch").read_bytes() == PATCH


async def test_mcuboot_is_a_layer_an_operator_can_allow(aiohttp_client, config) -> None:
    """Contract §1.1 names four layers and this server knew three.

    ``mcuboot`` is a layer because every device build is ``west build
    --sysbuild`` with MCUboot as the second image, so a context that
    patches the bootloader had no way to be allowed at all.
    """
    client, _ = await serve(aiohttp_client, config, allowed_patch_layers=("mcuboot",))
    archive = base_context(**{"patches/mcuboot/0001-swap.patch": PATCH})
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
    assert frame["type"] == "result", frame


async def test_a_third_party_layer_needs_its_x_prefix_and_the_config(
    aiohttp_client, config
) -> None:
    """ "Third-party layer names MUST carry an ``x-`` prefix" (§1.1).

    The prefix keeps two vendors from colliding on one name and having a
    context silently patch the wrong tree. It buys no permission: an
    ``x-`` layer is allowed exactly where an operator listed it, like
    every other layer.
    """
    client, _ = await serve(aiohttp_client, config, allowed_patch_layers=("x-acme",))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        allowed = await send_archive(
            ws, "send-context", session_id, base_context(**{"patches/x-acme/0001.patch": PATCH})
        )
        assert allowed["type"] == "result", allowed

    async with client.ws_connect("/ws", headers=auth()) as ws:
        other = await open_session(ws)
        frame = await send_archive(
            ws, "send-context", other, base_context(**{"patches/x-other/0001.patch": PATCH})
        )
    assert frame["error"]["code"] == "policy.patch-layer-denied"


async def test_an_empty_folder_for_a_denied_layer_is_refused_too(client) -> None:
    """A folder is a claim about the shape of the context.

    An empty ``patches/zephyr/`` carries no patch and could not change a
    build, but accepting one leaves a context whose own layout says a
    denied layer is welcome here.
    """
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        info = tarfile.TarInfo("context.yaml")
        info.size = len(CONTEXT_YAML.encode())
        tar.addfile(info, io.BytesIO(CONTEXT_YAML.encode()))
        tar.addfile(_member("patches/zephyr", tarfile.DIRTYPE))
    archive = zstandard.ZstdCompressor().compress(raw.getvalue())

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
    assert frame["error"]["code"] == "policy.patch-layer-denied"


def test_the_configuration_accepts_the_four_names_and_the_x_prefix() -> None:
    """Nameable is not the same as allowed, and the option knows both."""
    from mcuhome_buildserver.config import load_config

    config = load_config(
        ["--allow-patch-layer", "mcuboot", "--allow-patch-layer", "x-acme"], env={}
    )
    assert config.allowed_patch_layers == ("mcuboot", "x-acme")
    with pytest.raises(SystemExit):
        load_config(["--allow-patch-layer", "kernel"], env={})
    with pytest.raises(SystemExit):
        load_config(["--allow-patch-layer", "X-Acme"], env={})


def test_the_caps_and_the_context_root_are_configuration() -> None:
    """ "The config is the policy" applies to the numbers too (E44).

    ADR 0019 decision 8 requires the caps and names no number for any of
    them, so every one of them is an operator's to move — including from
    the environment, which is what an App's ``run`` script and a
    ``docker run`` have.
    """
    from mcuhome_buildserver.config import load_config

    config = load_config(["--max-entries", "7", "--context-root", "/srv/ctx"], env={})
    assert config.max_entries == 7
    assert config.context_root == Path("/srv/ctx")
    assert config.max_context_yaml_bytes == 64 * 1024, "the sixth cap has a default like the rest"
    config = load_config([], env={"MCUHOME_BUILDSERVER_SESSION_QUOTA_BYTES": "4096"})
    assert config.session_quota_bytes == 4096
    config = load_config(["--max-context-yaml-bytes", "128"], env={})
    assert config.max_context_yaml_bytes == 128
    config = load_config([], env={"MCUHOME_BUILDSERVER_MAX_CONTEXT_YAML_BYTES": "256"})
    assert config.max_context_yaml_bytes == 256
    with pytest.raises(SystemExit):
        load_config(["--max-file-bytes", "0"], env={})
    with pytest.raises(SystemExit):
        load_config(["--max-context-yaml-bytes", "0"], env={})


def test_the_context_root_falls_back_to_state_and_then_to_the_temporary_dir() -> None:
    """A server started by systemd has no ``HOME``, and must not invent one.

    :mod:`mcuhome.model.userpaths` records the same failure on the other
    side of the family: ``Path.home()`` answers a missing ``HOME`` from
    the account database, which picks a directory nobody asked for. Here
    the fallback is somewhere obviously ephemeral instead.
    """
    from mcuhome_buildserver.config import default_context_root

    assert default_context_root({"XDG_STATE_HOME": "/x"}) == Path(
        "/x/mcuhome-build-server/sessions"
    )
    assert default_context_root({"HOME": "/home/s"}) == Path(
        "/home/s/.local/state/mcuhome-build-server/sessions"
    )
    assert default_context_root({}).parts[-2:] == ("mcuhome-build-server", "sessions")


# --------------------------------------------------------------------------
# context.yaml: the pin document
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("what", "document"),
    [
        ("duplicate keys", CONTEXT_YAML + "target:\n  board: other\n"),
        ("an anchor", CONTEXT_YAML.replace("context: 3", "context: &c 3\nalias: *c")),
        ("no pins at all", "context: 3\n"),
        ("a second document", CONTEXT_YAML + "---\ncontext: 3\n"),
        ("a python tag", CONTEXT_YAML + "extra: !!python/object/apply:os.system ['id']\n"),
        ("a wrong format version", CONTEXT_YAML.replace("context: 3", "context: 9")),
        (
            "a build_environment that is not one",
            CONTEXT_YAML.replace(
                f"build_environment: {IMAGE_REFERENCE_FORMAT3}",
                "build_environment: not-a-reference",
            ),
        ),
        (
            "a prefixed package hash",
            CONTEXT_YAML.replace("sha256: " + "a" * 64, "sha256: sha256:" + "a" * 64),
        ),
    ],
)
async def test_a_context_yaml_the_format_does_not_describe_is_refused(
    client, what, document
) -> None:
    """The pin document is parsed strictly, and hardened three ways.

    Bounded before it is parsed, safe-loaded so no tag can construct a
    Python object, and refused for duplicate keys and anchors — a
    duplicate key makes the document mean two things at once, and an
    anchor graph is how a small file becomes a large one inside a parser
    that runs before any cap of this server sees the result.

    The two hash cases are build-container contract §3.3.1: "invalid
    input, not something to normalize", refused "naming the offending
    value" and without computing an ID from it.
    """
    archive = make_archive({"context.yaml": document.encode()})
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
    assert frame["error"]["code"] == "bad_request", what


async def test_an_oversize_context_yaml_is_an_ingress_refusal(client) -> None:
    """A pin document is a few hundred bytes; a cap of its own says so.

    It gets one rather than sharing the per-file ingress cap with a
    multi-megabyte patch, because the YAML parser is the single place in
    this server where a small input can buy unbounded work.
    """
    padded = CONTEXT_YAML + "# " + "x" * (70 * 1024) + "\n"
    archive = make_archive({"context.yaml": padded.encode()})
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
    assert frame["error"]["code"] == "policy.ingress-limit-exceeded"
    assert frame["error"]["details"]["cap"] == "context.yaml size"
    assert frame["error"]["details"]["limit"] == 64 * 1024, "the default, which the README states"


async def test_the_context_yaml_bound_is_the_operators_number(aiohttp_client, config) -> None:
    """The sixth cap is configuration like the other six.

    It was a constant in the module that enforces it, attributed to a
    product-owner decision with no record anywhere but the comment — and
    the README advertised the number to operators who had no way to move
    it. config.py's own docstring says why that is the wrong shape: a
    limit an operator cannot move is a limit they will work around by
    other means.
    """
    padded = CONTEXT_YAML + "# " + "x" * (70 * 1024) + "\n"
    raised, _ = await serve(aiohttp_client, config, max_context_yaml_bytes=128 * 1024)
    async with raised.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(
            ws, "send-context", session_id, make_archive({"context.yaml": padded.encode()})
        )
    assert frame["type"] == "result", "the document the default refuses, accepted"

    lowered, _ = await serve(aiohttp_client, config, max_context_yaml_bytes=64)
    async with lowered.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, base_context())
    assert frame["error"]["details"]["cap"] == "context.yaml size"
    assert frame["error"]["details"]["limit"] == 64, "the operator's number, not a constant"


async def test_the_context_format_is_the_one_the_session_was_admitted_on(
    aiohttp_client, config, monkeypatch
) -> None:
    """ "The format is negotiated at open-session and not re-negotiated here."

    The refusal says exactly that, and it was not true: the negotiated
    version was validated at admission and then thrown away, so
    ``send-context`` measured ``context.yaml`` against
    ``CONTEXT_FORMAT_MAX`` while telling the client it had been measured
    against what the session negotiated. The two are the same number only
    while the accepted range holds one, and the range exists precisely so
    it can widen — which is what this test does to it.
    """
    current = sessions.CONTEXT_FORMAT_MAX
    ahead = current + 1
    monkeypatch.setattr(sessions, "CONTEXT_FORMAT_MAX", ahead)
    client, _ = await serve(aiohttp_client, config)
    # The body is this format's; only the declared number moves. What is
    # under test is which number the document is measured against, and a
    # hypothetical next format's body would only add a second variable.
    document = CONTEXT_YAML.replace(f"context: {current}", f"context: {ahead}").encode()
    version = sessions.SESSION_PROTOCOL_VERSION

    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(
            ws,
            "open-session",
            {"protocol_version": version, "context_format": current},
            frame_id="o1",
        )
        older = frame["payload"]["session"]["id"]
        refused = await send_archive(
            ws, "send-context", older, make_archive({"context.yaml": document})
        )
        assert refused["error"]["code"] == "bad_request"
        assert f"admitted on {current}" in refused["error"]["message"], refused["error"]["message"]

        frame = await call(
            ws,
            "open-session",
            {"protocol_version": version, "context_format": ahead},
            frame_id="o2",
        )
        newer = frame["payload"]["session"]["id"]
        accepted = await send_archive(
            ws, "send-context", newer, make_archive({"context.yaml": document})
        )
        assert accepted["type"] == "result", accepted
        assert accepted["payload"]["context"]["format"] == ahead
        extended = await send_archive(
            ws, "extend-context", newer, make_archive({"keys/signing.pub": b"key"})
        )
        assert extended["payload"]["context"]["format"] == ahead, "reported, not assumed"


# --------------------------------------------------------------------------
# extend-context
# --------------------------------------------------------------------------


async def test_extend_context_adds_and_overwrites_by_path(client, state) -> None:
    """ "Per-layer replace semantics (add / overwrite / remove)."

    Replace means by path: an extension names files, and a file it names
    replaces the one that was there. Nothing is versioned and nothing is
    merged.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws, "send-context", session_id, base_context(**{"model/device-model.json": MODEL})
        )
        frame = await send_archive(
            ws,
            "extend-context",
            session_id,
            make_archive({"model/device-model.json": b"{}", "keys/signing.pub": b"key"}),
        )
        paths = state.sessions.require(session_id).paths

    assert frame["type"] == "result", frame
    assert frame["payload"]["files"] == 2
    assert paths is not None
    assert (paths.context / "model/device-model.json").read_bytes() == b"{}"
    assert (paths.context / "keys/signing.pub").read_bytes() == b"key"


async def test_extend_context_removes_and_says_how_many_existed(client, state) -> None:
    """Removing something that is not there is not an error.

    The client asked for a state and that state holds — the rule
    ``close-session`` already follows for a closed session. The count in
    the answer is what keeps a typo visible without turning it into a
    refusal.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws,
            "send-context",
            session_id,
            base_context(**{"model/device-model.json": MODEL, "keys/signing.pub": b"key"}),
        )
        frame = await call(
            ws,
            "extend-context",
            {"session_id": session_id, "remove": ["keys/signing.pub", "model/never-there.json"]},
            frame_id="r",
        )
        paths = state.sessions.require(session_id).paths

    assert frame["payload"]["removed"] == 1
    assert frame["payload"]["files"] == 1
    assert paths is not None
    assert not (paths.context / "keys").exists(), "an emptied directory goes with its last file"


async def test_an_extension_that_removes_and_adds_the_same_path_keeps_the_new_one(client, state):
    """Order within one call: removals first, then the archive.

    Settled nowhere, determined here. The archive is the positive
    statement of what the context should contain, so a client that says
    "remove X" and "here is X" means the new X.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws, "send-context", session_id, base_context(**{"model/device-model.json": MODEL})
        )
        frame = await send_archive(
            ws,
            "extend-context",
            session_id,
            make_archive({"model/device-model.json": b"new"}),
            remove=["model/device-model.json"],
        )
        paths = state.sessions.require(session_id).paths

    assert frame["type"] == "result", frame
    assert paths is not None
    assert (paths.context / "model/device-model.json").read_bytes() == b"new"


@pytest.mark.parametrize("how", ["archive", "remove"])
async def test_an_extension_may_not_touch_context_yaml(client, how) -> None:
    """``context.pins-immutable``, in both directions.

    ADR 0018 requires "an attempt is a typed error" and names this code;
    it is registered deliberately apart from
    ``context.unsafe-entry``. A ``context.yaml`` in an extension is a
    perfectly well-formed entry aimed at a forbidden target, and telling
    a client its path was unsafe would send it looking for the wrong
    mistake.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, base_context())
        if how == "archive":
            frame = await send_archive(
                ws, "extend-context", session_id, make_archive({"context.yaml": b"context: 1\n"})
            )
        else:
            frame = await call(
                ws,
                "extend-context",
                {"session_id": session_id, "remove": ["context.yaml"]},
                frame_id="r",
            )
    assert frame["error"]["code"] == "context.pins-immutable"


async def test_an_extension_that_changes_nothing_is_refused(client) -> None:
    """A client that sent it meant something.

    Both halves are optional and at least one is required, so "nothing
    changed" is never the answer to a command — it is the sign that the
    client built the payload it did not mean to send.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, base_context())
        frame = await call(ws, "extend-context", {"session_id": session_id}, frame_id="e")
    assert frame["error"]["code"] == "bad_request"


async def test_a_refused_extension_leaves_the_context_byte_for_byte(client, state) -> None:
    """Nothing is applied until everything is accepted.

    The archive is unpacked into a staging directory beside the context
    and moved in only once every cap, every path and the patch policy
    have passed. Atomicity is settled nowhere; a half-applied extension
    on a context whose ID is about to be computed is not a state worth
    being able to reach.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws, "send-context", session_id, base_context(**{"model/device-model.json": MODEL})
        )
        frame = await send_archive(
            ws,
            "extend-context",
            session_id,
            make_archive({"keys/signing.pub": b"key", "evil.sh": b"#!/bin/sh"}),
            remove=["model/device-model.json"],
        )
        paths = state.sessions.require(session_id).paths

    assert frame["error"]["code"] == "context.unsafe-entry"
    assert paths is not None
    assert (paths.context / "model/device-model.json").read_bytes() == MODEL
    assert not (paths.context / "keys/signing.pub").exists()
    assert not paths.staging.exists()
    assert not paths.spool.exists()


async def test_the_upload_spool_is_deleted_before_the_verb_answers(client, state) -> None:
    """The spooled tar is transient, and the ledger relies on it.

    The per-session disk quota deliberately does not meter the spool —
    :class:`IngressLedger` argues that it is bounded by the decompressed
    cap in its own right "and it is deleted before the verb answers".
    That last clause is the load-bearing one: a spool that survived the
    verb would be an unmetered copy of the whole archive sitting inside
    the per-session directory, and both verbs that write one were free to
    leave it there with the suite green.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws, "send-context", session_id, base_context(**{"model/device-model.json": MODEL})
        )
        paths = state.sessions.require(session_id).paths
        assert paths is not None
        assert not paths.spool.exists(), "after send-context"

        accepted = await send_archive(
            ws, "extend-context", session_id, make_archive({"keys/signing.pub": b"key"})
        )
        assert accepted["type"] == "result", accepted
        assert not paths.spool.exists(), "after extend-context"


async def test_a_refused_extension_gives_the_disk_meter_back(client, state) -> None:
    """The staged bytes were charged and are being thrown away.

    The meter moves in three places — an unpack charges, a removal
    credits, an overwrite does both — so after a refusal there is no
    single amount to undo and the meter is re-read off the context. A
    meter that only ever counted up would let a client spend a session's
    whole disk budget on extensions that were all refused.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws, "send-context", session_id, base_context(**{"model/device-model.json": MODEL})
        )
        session = state.sessions.require(session_id)
        before = session.ledger.disk_bytes
        await send_archive(
            ws,
            "extend-context",
            session_id,
            make_archive({"keys/signing.pub": b"x" * 900, "evil.sh": b"#!/bin/sh"}),
        )

    # context.yaml is on the disk like any other file, so it is on the
    # meter — the quota is about the host, not about the integrity list.
    assert before == len(MODEL) + len(CONTEXT_YAML.encode())
    assert session.ledger.disk_bytes == before


async def test_a_completed_transfer_is_charged_even_if_its_content_is_refused(client, state):
    """The host decompressed those bytes either way.

    The byte and entry counters move when the *transfer* completes, not
    when the verb succeeds: refunding an archive that arrived whole and
    then turned out to carry a symlink would make a bad archive free to
    send again and again. A transfer cut off mid-stream is charged
    nothing, because the rest never arrived.
    """
    archive = make_archive({"context.yaml": CONTEXT_YAML.encode(), "evil.sh": b"#!/bin/sh"})
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
        ledger = state.sessions.require(session_id).ledger

    assert frame["error"]["code"] == "context.unsafe-entry"
    assert ledger.compressed_bytes == len(archive)
    assert ledger.decompressed_bytes > 0
    # All three counters, not two. The entry counter used to move only
    # when the unpack *returned*, so every refusal inside the loop
    # charged zero entries while the byte counters had already been
    # charged — the divergence the docstring above forbids, and the one
    # this assertion was missing.
    assert ledger.entries == 2, "context.yaml arrived, and so did the entry that was refused"
    # The disk meter is the one that is given back: nothing of that
    # archive is on the host any more.
    assert ledger.disk_bytes == 0


async def test_extend_context_before_a_base_context_is_refused(client) -> None:
    """There is nothing to extend, and the code says which verb is missing."""
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await call(
            ws, "extend-context", {"session_id": session_id, "remove": ["model/x.json"]}, "e"
        )
    assert frame["error"]["code"] == "context.missing"


async def test_an_extension_re_runs_policy_over_the_files_present(aiohttp_client, config) -> None:
    """ "After every extension the server re-derives the patch-layer set
    from the files *actually present* and re-runs policy."

    There is no declared patch list that could disagree — a patch's
    layer is its subfolder — so the paths are the declaration, and an
    extension carrying a denied layer is refused on the way in.
    """
    client, state = await serve(aiohttp_client, config, allowed_patch_layers=("zephyr",))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws, "send-context", session_id, base_context(**{"patches/zephyr/0001.patch": PATCH})
        )
        frame = await send_archive(
            ws, "extend-context", session_id, make_archive({"patches/chip/0001.patch": PATCH})
        )
        paths = state.sessions.require(session_id).paths

    assert frame["error"]["code"] == "policy.patch-layer-denied"
    assert frame["error"]["details"]["layer"] == "chip"
    assert paths is not None
    assert not (paths.context / "patches/chip").exists()


async def test_two_uploads_cannot_run_on_one_connection_at_once(client) -> None:
    """Binary frames carry no id, so they belong to the upload that runs.

    One at a time per connection is the wire's own shape rather than a
    restriction placed on it, and a second announcement — here for a
    *different* session, so the per-session guard is not what answers —
    is refused rather than interleaved into the first, which would
    corrupt both archives.
    """
    archive = base_context()
    async with client.ws_connect("/ws", headers=auth()) as ws:
        first = await open_session(ws)
        second = await open_session(ws)
        for frame_id, session_id in (("a", first), ("b", second)):
            await ws.send_json(
                {
                    "id": frame_id,
                    "type": "send-context",
                    "payload": {
                        "session_id": session_id,
                        "archive": {
                            "size": len(archive),
                            "sha256": hashlib.sha256(archive).hexdigest(),
                        },
                    },
                }
            )
        while (refused := await ws.receive_json(timeout=15)).get("id") != "b":
            pass
        # The first upload is still waiting for its bytes; giving them to
        # it proves the refusal of the second did not disturb it.
        await ws.send_bytes(archive)
        while (accepted := await ws.receive_json(timeout=15)).get("id") != "a":
            pass

    assert refused["type"] == "error"
    assert "already in progress on this connection" in refused["error"]["message"]
    assert accepted["type"] == "result", accepted


async def test_two_context_commands_on_one_session_do_not_race(client) -> None:
    """One context command at a time, per session.

    They share one directory, one ledger and one spool file. Two at once
    take each other's: the second ``send-context`` of a race creates the
    directory the first is unpacking into, and its own refusal deletes
    the first's bytes on the way out. Queueing the second instead would
    deadlock — the bytes the first is waiting for arrive through the
    same reader that would be holding the queue.
    """
    archive = base_context()
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        for frame_id in ("a", "b"):
            await ws.send_json(
                {
                    "id": frame_id,
                    "type": "send-context",
                    "payload": {
                        "session_id": session_id,
                        "archive": {
                            "size": len(archive),
                            "sha256": hashlib.sha256(archive).hexdigest(),
                        },
                    },
                }
            )
        while (refused := await ws.receive_json(timeout=15)).get("id") != "b":
            pass
        await ws.send_bytes(archive)
        while (accepted := await ws.receive_json(timeout=15)).get("id") != "a":
            pass

    assert "already running in session" in refused["error"]["message"]
    assert accepted["type"] == "result", accepted


# --------------------------------------------------------------------------
# The remove list: a path is a path, whichever direction it points
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("what", "path"),
    [
        ("parent traversal", "../../victim.txt"),
        ("an absolute path", "/etc/passwd"),
        ("outside the whitelisted subtrees", "evil.sh"),
    ],
)
async def test_a_removal_path_is_validated_like_an_archive_entry(client, state, what, path) -> None:
    """``_apply_removals`` unlinks whatever it is handed, so the guard is
    everything: ``target = context / path`` followed by ``target.unlink()``
    turns an unchecked string into arbitrary file deletion.

    The assertion that matters is the last one — that the file is still
    there. Asserting the error code alone is what let the guard be
    deleted with the suite green: ``context.yaml`` was the only removal
    case covered, and that one is answered by ``context.pins-immutable``
    on a completely different branch, so nothing ever exercised
    ``check_path_shape`` on a removal at all.
    """
    victim = state.config.context_root / "victim.txt"
    victim.parent.mkdir(parents=True, exist_ok=True)
    victim.write_bytes(b"not yours")
    named = str(victim) if path == "/etc/passwd" else path

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, base_context())
        frame = await call(
            ws, "extend-context", {"session_id": session_id, "remove": [named]}, frame_id="r"
        )
        paths = state.sessions.require(session_id).paths

    assert frame["error"]["code"] == "context.unsafe-entry", what
    assert victim.read_bytes() == b"not yours", "the removal must not have happened"
    assert paths is not None
    assert (paths.context / "context.yaml").exists(), "and the context is untouched"


# --------------------------------------------------------------------------
# One path, one kind: files and directories cannot be the same name
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("what", "entries"),
    [
        ("the file first", [("model/a", b"x"), ("model/a/b.json", b"{}")]),
        ("the directory first", [("model/a/b.json", b"{}"), ("model/a", b"x")]),
    ],
)
async def test_one_archive_may_not_claim_a_path_as_both_kinds(client, state, what, entries) -> None:
    """A collision inside one archive is a typed refusal, not a traceback.

    Both orders, because an archive names its entries in whatever order
    it likes and the two used to fail in different places: ``mkdir`` over
    a regular file (``FileExistsError``) and ``open(…, "wb")`` on a
    directory (``IsADirectoryError``). Neither was caught, so the answer
    was ``internal_error`` — every other malformed archive in this module
    gets a registry code, and this one got a stack trace in the log.
    """
    archive = make_archive_from([("context.yaml", CONTEXT_YAML.encode()), *entries])
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
        session = state.sessions.require(session_id)

    error = frame["error"]
    assert error["code"] == "context.unsafe-entry", what
    assert {error["details"]["entry"], error["details"]["conflict"]} == {
        "model/a",
        "model/a/b.json",
    }, "both paths are named; the offending entry alone explains nothing"
    assert session.context_state == sessions.CONTEXT_NONE


async def test_an_extension_may_not_put_a_file_where_the_context_has_a_directory(
    client, state
) -> None:
    """The same collision across the two halves of one context.

    ``shutil.move`` documents that an existing-directory destination
    means "move the source *inside* it", so this used to answer
    ``result`` and land the client's bytes at ``model/a/a`` — a path it
    never named, which the frozen ``manifest.yaml`` would then list. The
    only comparison the protocol has is the client's own, against the
    context ID the lock returns, so the client would have seen a bare
    mismatch with nothing to explain it.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws, "send-context", session_id, base_context(**{"model/a/b.json": MODEL})
        )
        frame = await send_archive(
            ws, "extend-context", session_id, make_archive({"model/a": b"NEW"})
        )
        paths = state.sessions.require(session_id).paths

    assert frame["error"]["code"] == "context.unsafe-entry"
    assert paths is not None
    assert not (paths.context / "model/a/a").exists(), "no path the client never named"
    assert (paths.context / "model/a/b.json").read_bytes() == MODEL
    assert not paths.staging.exists()


def test_the_merge_never_re_parents_a_staged_file(tmp_path: Path) -> None:
    """The second guard, pinned where the first cannot reach it.

    :func:`_check_merge` refuses this collision before the merge runs, so
    over the wire the move itself is unreachable — and that is exactly
    why it needs a test of its own. ``shutil.move`` documents that an
    existing-directory destination means "move the source *inside* it",
    which is a silent wrong answer rather than an error;
    :func:`os.replace` raises. A guard whose backstop would misplace the
    bytes rather than refuse them is one bug away from doing it.
    """
    from mcuhome_buildserver.sessions import Session, _merge_staging

    context, staging = tmp_path / "context", tmp_path / "staging"
    (context / "model/a").mkdir(parents=True)
    (context / "model/a/b.json").write_bytes(MODEL)
    (staging / "model").mkdir(parents=True)
    (staging / "model/a").write_bytes(b"NEW")
    session = Session(id="s-x", profile="oneshot", created_at=0.0, expires_at=0.0, idle_timeout=0.0)

    with pytest.raises(OSError):
        _merge_staging(session, staging, context)
    assert not (context / "model/a/a").exists(), "never a path the client did not name"
    assert (context / "model/a/b.json").read_bytes() == MODEL


async def test_an_extension_may_put_a_file_where_a_removal_makes_room(client, state) -> None:
    """The other half of the rule, so "refused" is not just "broken".

    Removals run before the archive, so a client that removes ``model/a``
    and sends ``model/a/b.json`` in one call has described a context that
    exists, and it gets it. The check has to know about the removals for
    this to work — validating against the context as it stands would
    refuse a perfectly good extension.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, base_context(**{"model/a": b"old"}))
        frame = await send_archive(
            ws,
            "extend-context",
            session_id,
            make_archive({"model/a/b.json": MODEL}),
            remove=["model/a"],
        )
        paths = state.sessions.require(session_id).paths

    assert frame["type"] == "result", frame
    assert paths is not None
    assert (paths.context / "model/a/b.json").read_bytes() == MODEL


async def test_a_merge_that_cannot_be_applied_is_refused_before_anything_moves(
    client, state
) -> None:
    """ "Nothing is applied until everything is accepted" — including the
    merge itself.

    Staging alone did not reach this far. The removals ran first and the
    staged files were moved in one at a time, so a staged path whose
    parent was an existing regular file raised out of the middle of the
    merge: the removal had happened, one file was in, the other never
    landed, and the client was told ``internal_error``. A half-applied
    extension on a context whose ID is about to be computed is exactly
    the state the verb's own docstring promises is unreachable.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws,
            "send-context",
            session_id,
            base_context(**{"model/a": b"OLD", "model/z.json": b"{}"}),
        )
        frame = await send_archive(
            ws,
            "extend-context",
            session_id,
            make_archive({"keys/signing.pub": b"key", "model/a/b": b"y"}),
            remove=["model/z.json"],
        )
        paths = state.sessions.require(session_id).paths

    assert frame["type"] == "error"
    assert frame["error"]["code"] == "context.unsafe-entry", "typed, not internal_error"
    assert paths is not None
    assert (paths.context / "model/a").read_bytes() == b"OLD"
    assert (paths.context / "model/z.json").exists(), "the removal did not run either"
    assert not (paths.context / "keys/signing.pub").exists()
    assert not paths.staging.exists()


# --------------------------------------------------------------------------
# The disk meter's two credit paths
# --------------------------------------------------------------------------


def _measured(context: Path) -> int:
    return sum(path.stat().st_size for path in context.rglob("*") if path.is_file())


async def test_overwriting_a_file_gives_its_bytes_back_to_the_disk_meter(client, state) -> None:
    """ "Overwriting one file twenty times cost twenty files' worth of
    quota while the context never grew."

    The failure path was covered — a refused extension re-reads the meter
    off the directory — and both *success* paths were not, so either
    credit could be deleted with the suite green and the meter would
    simply drift away from what the directory holds.
    """
    payload = b"x" * 1000
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws, "send-context", session_id, base_context(**{"model/device-model.json": payload})
        )
        session = state.sessions.require(session_id)
        for round_number in range(5):
            accepted = await send_archive(
                ws,
                "extend-context",
                session_id,
                make_archive({"model/device-model.json": bytes([round_number]) * 1000}),
            )
            assert accepted["type"] == "result", accepted
        paths = session.paths

    assert paths is not None
    assert session.ledger.disk_bytes == _measured(paths.context), "the meter follows the directory"


async def test_removing_a_file_gives_its_bytes_back_to_the_disk_meter(client, state) -> None:
    """A quota that only ever counted up would turn the remove half of
    ``extend-context`` into a way of spending a session's whole budget
    without keeping anything.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws,
            "send-context",
            session_id,
            base_context(**{"model/device-model.json": MODEL, "keys/signing.pub": b"x" * 900}),
        )
        session = state.sessions.require(session_id)
        before = session.ledger.disk_bytes
        accepted = await call(
            ws,
            "extend-context",
            {"session_id": session_id, "remove": ["keys/signing.pub"]},
            frame_id="r",
        )
        assert accepted["type"] == "result", accepted
        paths = session.paths

    assert paths is not None
    assert session.ledger.disk_bytes == before - 900
    assert session.ledger.disk_bytes == _measured(paths.context)


# --------------------------------------------------------------------------
# Guards that had no test of their own
# --------------------------------------------------------------------------


async def test_an_archive_that_names_one_path_twice_is_ambiguous(client, state) -> None:
    """Last-write-wins content is what would get hashed at the lock.

    The context ID is computed over the bytes on disk, so an archive that
    says two different things about one path has already made the answer
    depend on the order the server happened to extract in. There is no
    registry code for "these bytes are not a readable archive", so it is
    the envelope's own pre-registry one.
    """
    archive = make_archive_from(
        [
            ("context.yaml", CONTEXT_YAML.encode()),
            ("model/device-model.json", b"first"),
            ("model/device-model.json", b"second"),
        ]
    )
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, archive)
        session = state.sessions.require(session_id)

    assert frame["error"]["code"] == "bad_request"
    assert "twice" in frame["error"]["message"]
    assert session.context_state == sessions.CONTEXT_NONE
    assert session.paths is None


def test_the_patch_policy_recheck_refuses_on_its_own(tmp_path: Path) -> None:
    """The second guard, pinned independently of the first.

    ADR 0019 §2 requires the layer set to be re-derived "from the files
    *actually present*" after every extension, and both call sites of
    this function could be deleted with the suite green — the test named
    after the rule is in fact answered by the ingress-time check, which
    refuses a denied patch before it is ever written. Testing this one as
    a unit is what keeps the safety net a net rather than a comment.
    """
    from mcuhome_buildserver.contextstore import recheck_patch_policy
    from mcuhome_buildserver.errors import SessionError

    (tmp_path / "patches/zephyr").mkdir(parents=True)
    (tmp_path / "patches/zephyr/0001.patch").write_bytes(PATCH)

    with pytest.raises(SessionError) as refusal:
        recheck_patch_policy(tmp_path, frozenset())
    assert refusal.value.code == "policy.patch-layer-denied"
    assert refusal.value.details["layer"] == "zephyr"
    assert recheck_patch_policy(tmp_path, frozenset({"zephyr"})) == ("zephyr",)


def test_the_file_count_walks_the_context_without_hashing_it(tmp_path: Path, monkeypatch) -> None:
    """``extend-context`` answers a file count, and a count needs no hashes.

    It used to call the collector that hashes every content file, so a
    repeatable verb did a full SHA-256 pass over a context of up to the
    per-session disk quota — 2 GiB by default — on every call, for a
    number a walk produces. The two must still agree about *which* files
    are the context, which is why both go through one exclusion rule.
    """
    from mcuhome_buildserver import contextstore

    (tmp_path / "model").mkdir()
    (tmp_path / "context.yaml").write_bytes(CONTEXT_YAML.encode())
    (tmp_path / "manifest.yaml").write_bytes(b"id: sha256:whatever")
    (tmp_path / "model/device-model.json").write_bytes(MODEL)

    assert contextstore.count_context_files(tmp_path) == 1
    assert contextstore.count_context_files(tmp_path) == len(
        contextstore.collect_context_files(tmp_path)
    )

    def never(path):
        raise AssertionError(f"the count hashed {path}")

    monkeypatch.setattr(contextstore, "sha256_file", never)
    assert contextstore.count_context_files(tmp_path) == 1


# --------------------------------------------------------------------------
# Where the per-session directories are allowed to live
# --------------------------------------------------------------------------


def test_the_context_root_is_created_private_and_level_by_level(tmp_path: Path) -> None:
    """Every level this server creates, it creates ``0o700``.

    The per-session directories under it hold ``keys/`` — a device's
    Matter commissioning credentials — and ``mkdir(parents=True)`` gives
    the levels it invents whatever the process umask happens to allow.
    The umask is cleared for the duration precisely so that the mode has
    to come from the call: under the usual ``0o022`` a plain ``mkdir``
    lands on ``0o755`` and looks close enough to pass.
    """
    import os as os_module

    from mcuhome_buildserver.contextstore import prepare_context_root

    root = tmp_path / "state" / "mcuhome-build-server" / "sessions"
    previous = os_module.umask(0o000)
    try:
        assert prepare_context_root(root) == root
    finally:
        os_module.umask(previous)
    for level in (root, root.parent, root.parent.parent):
        assert level.stat().st_mode & 0o077 == 0, level


def test_a_relative_context_root_is_refused_at_startup(tmp_path: Path, monkeypatch) -> None:
    """Contract §5.2 rule 4: "a path value that is not absolute ⇒
    ``unsupported.request``".

    Every path in an invocation's request document descends from the
    context root — ``out``, ``work``, ``tmp``, ``context``, ``result``,
    ``events``, ``cancel`` — so a relative root produces a document
    every conforming program has to refuse, and the same string is a
    ``--volume`` source, where docker reads a name without a slash as a
    *named volume* and hands the program an empty directory instead of
    the context. Refused rather than quietly resolved: ``resolve()``
    would pick whatever the server's working directory happened to be,
    which is not a location an operator chose.

    A startup refusal because it is an operator's mistake about a path,
    and every session would make it again.
    """
    from mcuhome_buildserver.config import load_config
    from mcuhome_buildserver.contextstore import UnsafeContextRoot, prepare_context_root

    # Chdir first: without the refusal the relative name resolves against
    # the working directory, and the point of the refusal is that nobody
    # chose that directory.
    monkeypatch.chdir(tmp_path)
    configured = load_config(["--context-root", "relative/sessions"], env={})
    assert not configured.context_root.is_absolute()
    with pytest.raises(UnsafeContextRoot) as refusal:
        prepare_context_root(configured.context_root)
    assert "absolute" in str(refusal.value)
    assert not (tmp_path / "relative").exists(), "nothing was created for it either"


def test_a_context_root_under_a_world_writable_directory_refuses_to_serve(tmp_path: Path) -> None:
    """The systemd fallback lands in ``/tmp``, and that is the case.

    With neither ``XDG_STATE_HOME`` nor ``HOME`` set the default is
    ``/tmp/mcuhome-build-server/sessions``, a fixed name in a directory
    every local user can write to: whoever creates it first owns the
    parent of every per-session directory and can rename one away and
    substitute their own. Session ids are unguessable, so the attack is
    on the parent rather than on the name.

    ``/tmp`` itself is not the problem — it is root-owned and sticky, and
    sticky is exactly what stops a stranger from renaming somebody else's
    entry. A world-writable directory *without* the sticky bit is.
    """
    from mcuhome_buildserver.contextstore import UnsafeContextRoot, prepare_context_root

    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)  # chmod rather than mkdir(mode=…), which the umask trims
    with pytest.raises(UnsafeContextRoot) as refusal:
        prepare_context_root(shared / "sessions")
    assert "--context-root" in str(refusal.value)
    assert not (shared / "sessions").exists(), "nothing was created under it"

    shared.chmod(0o1777)
    assert prepare_context_root(shared / "sessions").exists(), "sticky is what /tmp has"


def test_an_unsafe_context_root_stops_the_server_before_it_binds(tmp_path: Path) -> None:
    """A refusal an operator can act on, rather than a traceback.

    It is their mistake about a path and the message says which directory
    and what is wrong with it, so the process exits non-zero with that
    one sentence and never binds the socket.
    """
    from mcuhome_buildserver.server import run

    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    config = Config(
        host="127.0.0.1",
        port=0,
        token="t" * 32,
        pair_file=None,
        context_root=shared / "sessions",
    )
    assert run(config) == 2


def test_a_context_root_owned_by_somebody_else_refuses_to_serve(
    tmp_path: Path, monkeypatch
) -> None:
    """Ownership, checked all the way up rather than one level.

    A root this server owns is still a root a stranger can rename away if
    they own its parent, so every existing level is asked. The check is
    exercised by moving *us* rather than the directory: creating one
    owned by another user needs privileges a test suite must not have.
    """
    import os as os_module

    from mcuhome_buildserver.contextstore import UnsafeContextRoot, prepare_context_root

    root = tmp_path / "sessions"
    root.mkdir()
    monkeypatch.setattr(os_module, "geteuid", lambda: 4242)
    with pytest.raises(UnsafeContextRoot) as refusal:
        prepare_context_root(root)
    assert "credentials" in str(refusal.value)


def test_the_two_informational_pin_fields_may_be_empty(tmp_path) -> None:
    """Contract §3.2: constraint is "original intent — never hashed" and
    package.url is "hint only — never hashed". The reference client
    writes both empty for a local source (an unstated constraint is PEP
    440's empty "any", and a file:// hint would leak its filesystem
    layout here), so an empty statement is accepted; a missing key or a
    non-string stays malformed.
    """
    document = tmp_path / "context.yaml"
    document.write_text(
        "context: 3\n"
        "mcuhome:\n"
        "  constraint: ''\n"
        "  version: 2.4.0\n"
        "  package: {url: '', sha256: '" + "a" * 64 + "'}\n"
        f"build_environment: ghcr.io/mcu-home/build-container:zephyr-4.4.0-r10@sha256:{'b' * 64}\n"
        "target: {board: nrf7002dk/nrf5340/cpuapp}\n",
        encoding="utf-8",
    )
    pins = contextstore.parse_context_yaml(document, expected_version=3, max_bytes=65536)
    assert pins.sdk.constraint == ""
    assert pins.sdk.url == ""
    assert pins.sdk.version == "2.4.0"


def test_a_version_that_is_not_a_version_is_refused_at_the_pins(tmp_path) -> None:
    """The version becomes a filename component in the SDK store's search,
    so a path-shaped value is refused where it arrives, not trusted to
    stay inside the operator's source directory.
    """
    for hostile in ("../../../etc/x", "a/b", ".hidden", "", "x" * 80):
        document = tmp_path / "context.yaml"
        document.write_text(
            "context: 3\n"
            "mcuhome:\n"
            "  constraint: ''\n"
            f"  version: '{hostile}'\n"
            "  package: {url: '', sha256: '" + "a" * 64 + "'}\n"
            f"build_environment: {IMAGE_REFERENCE_FORMAT3}\n"
            "target: {board: nrf7002dk/nrf5340/cpuapp}\n",
            encoding="utf-8",
        )
        with pytest.raises(protocol.ProtocolError):
            contextstore.parse_context_yaml(document, expected_version=3, max_bytes=65536)
