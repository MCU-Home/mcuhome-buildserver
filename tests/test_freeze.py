# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""``lock-context``: the freeze, the manifest, and the identity behind them.

The context ID exists so that two independently written parties compute
the same value (ADR 0018 §6, build-container contract §3.3). This file
therefore checks two different things and never confuses them: that the
server computes the ID *through* ``mcuhome-model`` rather than beside it,
and that ``mcuhome-model``'s rule as installed here still produces the
frozen answers the conformance vectors state.
"""

from __future__ import annotations

import asyncio
import hashlib
import time

import pytest
from mcuhome.model.context import (
    CONTEXT_ID_VECTORS,
    ContextFile,
    context_id,
    vector_id,
)
from ruamel.yaml import YAML

from mcuhome_buildserver import sessions
from mcuhome_buildserver.errors import SessionError
from tests.conftest import CONTEXT_YAML, auth, base_context, call, make_archive, send_archive
from tests.test_context import MODEL, PATCH, open_session, serve

CONTAINER_DIGEST = "sha256:" + "b" * 64
SDK_SHA256 = "a" * 64
BOARD = "nrf7002dk/nrf5340/cpuapp"


async def send_and_lock(ws, session_id: str, archive: bytes) -> dict:
    """The two verbs every test here needs, in the flow's own order."""
    sent = await send_archive(ws, "send-context", session_id, archive)
    assert sent["type"] == "result", sent
    return await call(ws, "lock-context", {"session_id": session_id}, frame_id="lock")


def read_manifest(path) -> dict:
    return YAML(typ="safe", pure=True).load(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# The identity
# --------------------------------------------------------------------------


async def test_the_lock_answers_the_context_id_and_nothing_else(client) -> None:
    """E37, frozen by the product owner against the richer alternative.

    The request carries ``session_id`` and nothing else, the response
    carries the context ID and nothing else. The comparison ADR 0019
    requires — both sides comparing values they computed independently —
    therefore happens on the *client*, and this server never sees the
    client's value, so it can never raise that mismatch. The consequence
    is asserted here so nobody rediscovers it as a gap.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_and_lock(
            ws, session_id, base_context(**{"model/device-model.json": MODEL})
        )

    assert frame["type"] == "result", frame
    assert set(frame["payload"]) == {"context_id"}
    assert frame["payload"]["context_id"].startswith("sha256:")
    assert len(frame["payload"]["context_id"]) == len("sha256:") + 64


async def test_the_id_is_the_models_rule_over_the_bytes_received(client) -> None:
    """The value, computed a second time from the other side of the wire.

    The test hashes the bytes it sent and runs ``mcuhome-model``'s
    ``context_id`` over them itself. That is exactly the comparison the
    workbench is required to make, and it is what "both sides compute
    the same value" has to mean: the server may not re-implement the
    rule (ADR 0020 decision 4), so the only thing worth asserting is
    that the number it answers is the rule's.
    """
    files = {"model/device-model.json": MODEL, "keys/signing.pub": b"public key"}
    expected = context_id(
        container_digest=CONTAINER_DIGEST,
        sdk_sha256=SDK_SHA256,
        board=BOARD,
        files=[
            ContextFile(path=path, sha256=hashlib.sha256(data).hexdigest())
            for path, data in files.items()
        ],
    )
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_and_lock(ws, session_id, base_context(**files))

    assert frame["payload"]["context_id"] == expected


async def test_an_extension_changes_the_identity(client) -> None:
    """The ID is hashed once, at the lock — over the *effective* context.

    ADR 0018's amendment moved the hash from "re-hashed at build time"
    to "hashed once, at ``lock-context``", and the point of that moment
    is that everything sent up to it is in the answer. A context that
    grew and kept its ID would attribute two different builds to one
    identity.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        plain = await open_session(ws)
        first = await send_and_lock(ws, plain, base_context(**{"model/device-model.json": MODEL}))

    async with client.ws_connect("/ws", headers=auth()) as ws:
        extended = await open_session(ws)
        await send_archive(
            ws, "send-context", extended, base_context(**{"model/device-model.json": MODEL})
        )
        await send_archive(
            ws, "extend-context", extended, make_archive({"keys/signing.pub": b"public key"})
        )
        second = await call(ws, "lock-context", {"session_id": extended}, frame_id="lock")

    assert first["payload"]["context_id"] != second["payload"]["context_id"]


async def test_an_empty_context_has_an_identity_and_may_be_locked(client) -> None:
    """ "A context that was sent but is empty may be locked" (ADR 0019).

    It has a well-defined ID — the ``files`` list is simply empty and
    the document still has the key — and the things a ``build`` needs
    beyond existence, ``keys/signing.pub`` above all, are checked by
    ``build``, which is where the contract scopes them.
    """
    expected = context_id(
        container_digest=CONTAINER_DIGEST, sdk_sha256=SDK_SHA256, board=BOARD, files=()
    )
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_and_lock(ws, session_id, base_context())

    assert frame["payload"]["context_id"] == expected


# --------------------------------------------------------------------------
# manifest.yaml
# --------------------------------------------------------------------------


async def test_the_manifest_repeats_the_pins_and_adds_the_list_and_the_id(client, state) -> None:
    """ "It repeats rather than refers, so the lock result is readable on
    its own: the document that carries an identity carries the inputs
    that identity was computed from" (ADR 0018's amendment).

    Six keys, exactly as build-container contract §3.2 draws them.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_and_lock(
            ws, session_id, base_context(**{"model/device-model.json": MODEL})
        )
        paths = state.sessions.require(session_id).paths

    assert paths is not None
    manifest = read_manifest(paths.context / "manifest.yaml")
    assert set(manifest) == {"context", "mcuhome", "container", "target", "files", "id"}
    assert manifest["context"] == 1
    assert manifest["container"]["digest"] == CONTAINER_DIGEST
    assert manifest["container"]["tag"] == "zephyr-4.4.0-r4"
    assert manifest["mcuhome"]["constraint"] == "^2.3.6"
    assert manifest["target"] == {"board": BOARD}
    assert manifest["id"] == frame["payload"]["context_id"]


async def test_the_manifest_carries_no_created_timestamp(client, state) -> None:
    """ "The one field that does not travel is ``created``."

    It dates the *request* and lives in ``context.yaml`` alone; the
    manifest's own moment is the lock. Asserted separately from the key
    set above because it is a rule about a field rather than about a
    shape — and because the field is right there in the context.yaml
    this test sent, so a manifest writer that copied the document
    wholesale would pass every other check here.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_and_lock(ws, session_id, base_context())
        paths = state.sessions.require(session_id).paths

    assert paths is not None
    assert "created" in CONTEXT_YAML, "the document under test declares one"
    assert "created" not in read_manifest(paths.context / "manifest.yaml")


async def test_no_hash_in_the_manifest_is_wrapped_across_two_lines(client, state) -> None:
    """A ``sha256:`` digest is 71 characters and the emitter would fold it.

    Legal YAML, and still the wrong thing to write: ``manifest.yaml`` is
    read by build containers this project does not write, in languages
    it does not choose, and build-container contract §3.3.1 has them
    **refuse** a digest rendered any other way rather than repair it. A
    one-line value cannot be read as two.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_and_lock(ws, session_id, base_context(**{"keys/signing.pub": b"key"}))
        paths = state.sessions.require(session_id).paths

    assert paths is not None
    text = (paths.context / "manifest.yaml").read_text(encoding="utf-8")
    assert f"digest: {CONTAINER_DIGEST}" in text
    assert f"id: {frame['payload']['context_id']}" in text
    assert f"sha256: {SDK_SHA256}" in text
    assert all(len(line) < 200 for line in text.splitlines()), "no runaway line either"


async def test_neither_context_document_is_in_the_integrity_list(client, state) -> None:
    """Both exclusions, and they have different reasons.

    ``manifest.yaml`` is structural — it is the document that carries
    the list. ``context.yaml`` is ADR 0018 §6: hashing it would readmit
    ``created`` and ``mcuhome.constraint`` through the back door, so two
    byte-identical configurations created a second apart would get two
    identities, and one resolved pin reached under two constraints would
    get two more.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_and_lock(
            ws,
            session_id,
            base_context(**{"model/device-model.json": MODEL, "keys/signing.pub": b"key"}),
        )
        paths = state.sessions.require(session_id).paths

    assert paths is not None
    listed = [entry["path"] for entry in read_manifest(paths.context / "manifest.yaml")["files"]]
    assert listed == ["keys/signing.pub", "model/device-model.json"], "sorted by path"
    assert "context.yaml" not in listed
    assert "manifest.yaml" not in listed


async def test_a_patch_is_an_ordinary_entry_of_the_list(aiohttp_client, config) -> None:
    """ "There is no patch list in the manifest" (contract §3.1).

    A patch's layer is its subfolder and its order is its filename, so
    it needs no section of its own — it hashes into the identity like
    every other file, which is what makes two contexts differing only in
    a patch two different contexts.
    """
    client, state = await serve(aiohttp_client, config, allowed_patch_layers=("zephyr",))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        patched = base_context(**{"patches/zephyr/0001-fix.patch": PATCH})
        await send_and_lock(ws, session_id, patched)
        paths = state.sessions.require(session_id).paths

    assert paths is not None
    manifest = read_manifest(paths.context / "manifest.yaml")
    assert manifest["files"] == [
        {"path": "patches/zephyr/0001-fix.patch", "sha256": hashlib.sha256(PATCH).hexdigest()}
    ]


# --------------------------------------------------------------------------
# What the freeze refuses
# --------------------------------------------------------------------------


async def test_a_context_yaml_that_changed_after_acceptance_is_refused(client, state) -> None:
    """Defence in depth on top of the extension refusal.

    The pins are three of the four hashed inputs and the document that
    declares them is outside the integrity list by construction, so
    nothing else in the freeze would notice if it had changed. The
    refusal is ``context.integrity-mismatch`` — a recomputed value
    disagreeing with the bytes received, which is what that code means —
    and it names the path, as every integrity refusal does.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, base_context())
        paths = state.sessions.require(session_id).paths
        assert paths is not None
        (paths.context / "context.yaml").write_text(
            CONTEXT_YAML.replace(BOARD, "nrf52840dk/nrf52840"), encoding="utf-8"
        )
        frame = await call(ws, "lock-context", {"session_id": session_id}, frame_id="lock")

    assert frame["error"]["code"] == "context.integrity-mismatch"
    assert frame["error"]["details"]["paths"] == ["context.yaml"]


async def test_the_lock_is_one_way_and_unlocks_the_working_commands(client) -> None:
    """Both halves of the boundary, over a context that really exists.

    After the lock every writing command is refused — a second
    ``lock-context`` as much as another patch — and ``verify`` and
    ``build`` stop answering ``context.not-locked``. What they answer
    instead is now the *next* thing that is missing rather than a
    missing backend: this session's SDK pin names a package no source
    directory holds, so both reach ``sdk.unavailable``. Reaching a
    refusal from inside the working path is what proves the gate opened
    rather than merely stopped complaining.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_and_lock(ws, session_id, base_context())

        for index, verb in enumerate(("send-context", "extend-context", "lock-context")):
            frame = await call(ws, verb, {"session_id": session_id}, frame_id=f"w{index}")
            assert frame["error"]["code"] == "context.locked", verb
        for index, verb in enumerate(("verify", "build")):
            frame = await call(ws, verb, {"session_id": session_id}, frame_id=f"r{index}")
            assert frame["error"]["code"] == "sdk.unavailable", verb


# --------------------------------------------------------------------------
# The directory's end
# --------------------------------------------------------------------------


async def test_close_session_destroys_the_context(client, state) -> None:
    """ "The per-session directory — the context and every artifact in it
    — is deleted at ``close-session``" (ADR 0019's amendment).

    Which is also why ``get-artifact`` has to run before it. The
    amendment removed decision 2's "and for a bounded grace period after
    close" together with an undefined bound: nothing said how long,
    while the directory it kept alive holds a device's Matter
    commissioning credentials.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_and_lock(ws, session_id, base_context(**{"keys/signing.pub": b"secretish"}))
        root = state.sessions.require(session_id).paths.root
        assert root.exists()
        await call(ws, "close-session", {"session_id": session_id}, frame_id="x")

    assert not root.exists()


def test_an_expired_lease_takes_the_context_with_it(tmp_path) -> None:
    """Reaped means reaped, not "swept up later".

    The lease is the only thing that bounds a session whose client went
    away, so the credentials in its context must not outlive it by
    however long a future sweep happens to take.
    """
    manager = sessions.SessionManager(ttl=0.0)
    session = manager.open(
        profile="oneshot", protocol_version=sessions.SESSION_PROTOCOL_VERSION, context_format=1
    )
    from mcuhome_buildserver.contextstore import SessionPaths

    session.paths = SessionPaths.create(tmp_path, session.id)
    session.context_state = sessions.CONTEXT_UNLOCKED
    root = session.paths.root
    assert root.exists()

    try:
        manager.require(session.id)
    except sessions.SessionError as error:
        assert error.code == "session.expired"
    assert not root.exists()
    assert session.context_state == sessions.CONTEXT_NONE


# --------------------------------------------------------------------------
# Conformance
# --------------------------------------------------------------------------


def test_this_server_consumes_the_model_and_no_other_half_of_the_family() -> None:
    """ADR 0020 decision 4, checked rather than remembered.

    "The build server recomputes a context ID from bytes it received off
    a socket and must carry no build logic to do it." The temptation is
    concrete and it is right next door: ``mcuhome.workbench.contextdir``
    already has a context-directory walker, a manifest emitter and a
    verifier, and importing it would delete most of
    :mod:`mcuhome_buildserver.contextstore`. It would also make this
    server carry the build half of the product it exists to keep at
    arm's length, so the rule is a syntax check and not a habit.
    """
    import ast
    from pathlib import Path

    package = Path(__file__).resolve().parent.parent / "mcuhome_buildserver"
    offenders = []
    for source in sorted(package.rglob("*.py")):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            offenders += [
                f"{source.name}: {name}"
                for name in names
                if name.startswith(("mcuhome.workbench", "mcuhome.compiler"))
            ]
    assert offenders == []


def test_the_context_id_vectors_hold_on_this_side() -> None:
    """ADR 0020 §4's conformance obligation, discharged where it applies.

    The vectors are "the frozen rule stated as inputs and outputs rather
    than as code", and they exist for whoever writes the *second*
    implementation. This server is one of the two parties that must
    agree, so it runs them against the ``mcuhome-model`` it actually
    imports: a model that drifted — a different canonical encoding, a
    different sort, a field entering the hash — would break attribution
    here long before anyone noticed a document had changed.
    """
    assert len(CONTEXT_ID_VECTORS) >= 5
    for vector in CONTEXT_ID_VECTORS:
        assert vector_id(vector) == vector["id"], vector["name"]


def test_the_model_keeps_both_context_documents_out_of_the_hash() -> None:
    """The exclusion is enforced by the vocabulary, not only observed here.

    The server excludes both documents when it collects the file set,
    and the model refuses them if it ever stopped: two independent
    guards for one rule, which is the right number for a rule whose
    breach would silently change every context ID this server issues.
    """
    from mcuhome.model.errors import BuildError

    for path in ("context.yaml", "manifest.yaml"):
        try:
            context_id(
                container_digest=CONTAINER_DIGEST,
                sdk_sha256=SDK_SHA256,
                board=BOARD,
                files=[ContextFile(path=path, sha256="c" * 64)],
            )
        except BuildError:
            continue
        raise AssertionError(f"{path} must never be an integrity entry")


# --------------------------------------------------------------------------
# The lock against everything else in flight
# --------------------------------------------------------------------------


async def test_a_lock_cannot_slip_between_an_extension_and_its_bytes(client, state) -> None:
    """The freeze takes the same in-flight guard the uploads take.

    Every command runs as its own task and the reader keeps taking TEXT
    frames while an announced upload is still arriving, so a
    ``lock-context`` sent after an ``extend-context``'s announcement and
    before its bytes used to freeze *around* it: the manifest listed the
    files present at that instant, the extension then applied to the
    locked context, and the session ended up holding a file that is in
    neither ``manifest.yaml`` nor the context ID already answered. Both
    documents this contradicts say the same thing — "nothing may extend
    the context afterwards, so within a session ``manifest.yaml`` is
    immutable" (contract §3.2) and "the lock is one-way" (ADR 0018's
    amendment) — and it defeated the one comparison the protocol has,
    since the workbench's ID and the server's would agree while the file
    that arrived afterwards was invisible to both.

    ``require_writable_context`` cannot see this: it reads the context's
    *state*, and the state of a context that is being written to is
    still ``unlocked``. What is in flight is a different question.
    """
    extension = make_archive({"keys/signing.pub": b"public key"})
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws, "send-context", session_id, base_context(**{"model/device-model.json": MODEL})
        )
        await ws.send_json(
            {
                "id": "e",
                "type": "extend-context",
                "payload": {
                    "session_id": session_id,
                    "archive": {
                        "size": len(extension),
                        "sha256": hashlib.sha256(extension).hexdigest(),
                    },
                },
            }
        )
        refused = await call(ws, "lock-context", {"session_id": session_id}, frame_id="l")
        await ws.send_bytes(extension)
        while (extended := await ws.receive_json(timeout=15)).get("id") != "e":
            pass
        locked = await call(ws, "lock-context", {"session_id": session_id}, frame_id="l2")
        paths = state.sessions.require(session_id).paths

    assert refused["type"] == "error"
    assert "already running in session" in refused["error"]["message"]
    assert extended["type"] == "result", extended
    assert locked["type"] == "result", locked

    # The manifest and the directory agree, which is the whole point of
    # freezing at a defined moment.
    assert paths is not None
    listed = [entry["path"] for entry in read_manifest(paths.context / "manifest.yaml")["files"]]
    assert listed == ["keys/signing.pub", "model/device-model.json"]


async def test_a_close_during_an_upload_is_answered_typed_and_leaves_nothing(client, state) -> None:
    """``close-session`` is deliberately not serialized against the
    context verbs — a client must be able to close a session whatever it
    is doing — so it can land while a ``send-context`` waits for its
    bytes, and it deletes the per-session directory on the way out.

    The upload then woke up holding paths to a directory that no longer
    existed and **re-created** it on its way into the unpack, so the tree
    ``close-session`` had just destroyed came back with nothing left in
    the process that could ever name it again; the missing spool file
    escaped as an untyped ``internal_error``. Now the session is re-read
    after the await rather than assumed across it.
    """
    archive = base_context(**{"keys/signing.pub": b"public key"})
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await ws.send_json(
            {
                "id": "s",
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
        closed = await call(ws, "close-session", {"session_id": session_id}, frame_id="c")
        assert closed["payload"]["session"]["state"] == "closed"
        await ws.send_bytes(archive)
        while (answer := await ws.receive_json(timeout=15)).get("id") != "s":
            pass

    assert answer["type"] == "error"
    assert answer["error"]["code"] == "session.closed", "typed, not internal_error"
    assert not (state.config.context_root / session_id).exists(), "and not re-created behind it"


# --------------------------------------------------------------------------
# The reaper: a lease that nobody has to ask about
# --------------------------------------------------------------------------


def _abandoned(manager: sessions.SessionManager, tmp_path) -> sessions.Session:
    """One session with a real directory, and a client that never returns."""
    from mcuhome_buildserver.contextstore import SessionPaths

    session = manager.open(
        profile="oneshot", protocol_version=sessions.SESSION_PROTOCOL_VERSION, context_format=1
    )
    session.paths = SessionPaths.create(tmp_path, session.id)
    session.context_state = sessions.CONTEXT_UNLOCKED
    (session.paths.context / "keys").mkdir(parents=True)
    (session.paths.context / "keys/signing.pub").write_bytes(b"SECRET-KEY")
    return session


def test_the_sweep_takes_a_session_whose_lease_ran_out(tmp_path) -> None:
    """ "Deleted at lease expiry" was true only if a client came back.

    Expiry lived in ``SessionManager.require``, and ``require`` needs the
    caller to present the session id — so a client that crashed, or
    simply closed its socket, left ``context.yaml`` and ``keys/`` on disk
    for the life of the server. That directory holds a device's Matter
    commissioning credentials.
    """
    manager = sessions.SessionManager(ttl=0.0)
    session = _abandoned(manager, tmp_path)
    root = session.paths.root
    assert (root / "context/keys/signing.pub").read_bytes() == b"SECRET-KEY"

    assert manager.reap() == (session.id,)
    assert not root.exists()
    assert manager.open_count == 0
    assert manager.reap() == (), "sweeping twice reaps nothing twice"

    # A client that does come back hears what happened, not "closed".
    with pytest.raises(SessionError) as refusal:
        manager.require(session.id)
    assert refusal.value.code == "session.expired"


def test_the_sweep_takes_an_idle_session_too(tmp_path) -> None:
    """Both halves of the lease are real.

    The hard TTL bounds a session that is working; the idle timeout
    bounds one that is not, and it was recorded in the lease document
    while nothing enforced it at all.
    """
    manager = sessions.SessionManager(ttl=3600.0, idle_timeout=1.0)
    session = _abandoned(manager, tmp_path)
    session.last_command_at = time.time() - 60.0
    root = session.paths.root

    assert manager.reap() == (session.id,)
    assert not root.exists()
    with pytest.raises(SessionError) as refusal:
        manager.require(session.id)
    assert refusal.value.code == "session.expired"
    assert "idle timeout" in refusal.value.message


async def test_the_server_sweeps_without_anybody_asking(
    aiohttp_client, config, monkeypatch
) -> None:
    """The task, not just the method: a sweep nobody runs is not a sweep.

    Started at ``on_startup`` and cancelled at ``on_cleanup``, which is
    what turns ``SessionManager.reap`` into the thing the README has
    always claimed happens at lease expiry.
    """
    monkeypatch.setattr(sessions, "DEFAULT_REAP_INTERVAL", 0.01)
    client, state = await serve(aiohttp_client, config)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws, "send-context", session_id, base_context(**{"keys/signing.pub": b"SECRET-KEY"})
        )
        session = state.sessions.require(session_id)
        root = session.paths.root
        assert (root / "context/keys/signing.pub").exists()
        session.expires_at = time.time() - 1.0
        for _ in range(300):
            if not root.exists():
                break
            await asyncio.sleep(0.01)

    assert not root.exists(), "the lease ran out and nobody had to ask"
    assert state.sessions.open_count == 0


async def test_a_stopping_server_takes_the_directories_with_it(aiohttp_client, config) -> None:
    """A stopping server's sessions are over by definition.

    They are in-memory records bound to this process, so nothing that
    survives it could use one — and what *can* survive it is the
    directory, which is the half worth deleting on the way out.
    """
    client, state = await serve(aiohttp_client, config)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(
            ws, "send-context", session_id, base_context(**{"keys/signing.pub": b"SECRET-KEY"})
        )
        root = state.sessions.require(session_id).paths.root
    assert root.exists()

    await client.close()
    assert not root.exists()
