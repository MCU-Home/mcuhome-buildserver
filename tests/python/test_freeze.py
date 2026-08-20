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
    canonical_json,
    context_id,
    vector_id,
)
from ruamel.yaml import YAML

from mcuhome.buildserver import app as app_module
from mcuhome.buildserver import config as config_module
from mcuhome.buildserver import sessions
from mcuhome.buildserver.errors import SessionError
from tests.python.conftest import (
    BUILD_CONTEXT_BYTES,
    CONTEXT_YAML,
    IMAGE,
    IMAGE_DIGEST,
    IMAGE_LABELS,
    IMAGE_REFERENCE_FORMAT3,
    ZEPHYR_LINE,
    auth,
    base_context,
    call,
    context_yaml,
    device_model,
    make_archive,
    send_archive,
)
from tests.python.test_context import MODEL, PATCH, open_session, serve

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
    files = {
        "build-context.json": BUILD_CONTEXT_BYTES,
        "model/device-model.json": MODEL,
        "keys/signing.pub": b"public key",
    }
    expected = context_id(
        sdk_sha256=SDK_SHA256,
        environment_digest=IMAGE_DIGEST,
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

    The archive is assembled here rather than through ``base_context``
    because that fixture carries the generator declaration, which is
    content and would make this context exactly not empty. Nothing a real
    client sends looks like this — and the rule under test is the
    server's, which is why it is worth being able to state it at all.
    """
    expected = context_id(
        sdk_sha256=SDK_SHA256, environment_digest=IMAGE_DIGEST, board=BOARD, files=()
    )
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_and_lock(
            ws, session_id, make_archive({"context.yaml": CONTEXT_YAML.encode()})
        )

    assert frame["payload"]["context_id"] == expected


async def test_two_contexts_differing_only_in_their_environment_get_two_identities(
    client, docker
) -> None:
    """What replaced the model-versus-context cross-check, and why it is better.

    Under the format this replaced, the environment was outside the hash
    and the required Zephyr line was a field of ``context.yaml`` — which
    is outside the integrity list by construction. Two contexts with
    byte-identical files and two different required lines therefore had
    **one** ID, built in containers of two different lines, and both
    passed ``verify``; a server-side cross-check against the model was
    what kept that honest.

    Now the environment is the hash's own input, so the two contexts are
    two contexts and nothing has to be cross-checked to make it so. This
    is that property, measured on this server: the same bytes, one pin
    changed, two identities.
    """
    other_digest = "sha256:" + "d" * 64
    other = IMAGE_REFERENCE_FORMAT3.replace(IMAGE_DIGEST, other_digest)
    # A second conforming environment on this host, so that both pins can
    # actually be served and the only difference left is the digest.
    second = f"{IMAGE}:zephyr-4.4.0-r11"
    docker.images[second] = {
        "Id": "sha256:" + "7" * 64,
        "RepoTags": [second],
        "RepoDigests": [f"{IMAGE}@{other_digest}"],
        "Config": {"Labels": dict(IMAGE_LABELS)},
    }
    docker.listed = [*docker.listed, second]

    identities = []
    for pin in (IMAGE_REFERENCE_FORMAT3, other):
        async with client.ws_connect("/ws", headers=auth()) as ws:
            session_id = await open_session(ws)
            frame = await send_and_lock(
                ws,
                session_id,
                base_context(**{"context.yaml": context_yaml(build_environment=pin)}),
            )
            identities.append(frame)

    assert all("payload" in frame for frame in identities), identities
    first, second = (frame["payload"]["context_id"] for frame in identities)
    assert first != second


async def test_a_model_stating_the_required_line_locks_normally(client) -> None:
    """The other side of the check, so it cannot be a blanket refusal.

    A readable model agreeing with ``context.yaml`` is the ordinary case
    and locks like any other context. Worth its own test because the
    comparison is the only place this server reads the device model at
    all: a mistake in it would refuse every honest context, and the
    suite's other models are stubs that state no line and are passed
    over.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_and_lock(
            ws,
            session_id,
            base_context(**{"model/device-model.json": device_model(ZEPHYR_LINE)}),
        )

    assert frame["type"] == "result", frame
    assert frame["payload"]["context_id"].startswith("sha256:")


# --------------------------------------------------------------------------
# manifest.yaml
# --------------------------------------------------------------------------


async def test_the_manifest_repeats_the_pins_and_adds_the_list_and_the_id(client, state) -> None:
    """ "It repeats rather than refers, so the lock result is readable on
    its own: the document that carries an identity carries the inputs
    that identity was computed from" (ADR 0018's amendment).

    Six keys, exactly as build-container contract §3.2 draws them. The
    sixth is ``build_environment``, and it is a **repeat**: the client
    pinned it, this server records what it was handed. That is the whole
    difference the format made here — the manifest gained nothing this
    server decided, so two servers handed one context write one manifest.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_and_lock(
            ws, session_id, base_context(**{"model/device-model.json": MODEL})
        )
        paths = state.sessions.require(session_id).paths

    assert paths is not None
    manifest = read_manifest(paths.context / "manifest.yaml")
    assert set(manifest) == {
        "context",
        "mcuhome",
        "build_environment",
        "target",
        "files",
        "id",
    }
    assert manifest["context"] == sessions.CONTEXT_FORMAT_MAX
    # Verbatim from context.yaml, digest included: this server chose none
    # of it and may not, because the digest is a hashed identity input.
    assert manifest["build_environment"] == IMAGE_REFERENCE_FORMAT3
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
    assert f"build_environment: {IMAGE_REFERENCE_FORMAT3}" in text
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

    ``build-context.json`` is neither, and the list proves it: it names
    the tool that generated the context, a build environment is admitted
    against that name, and a file that decides who may build belongs
    inside the identity the build is claimed under.
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
    assert listed == [
        "build-context.json",
        "keys/signing.pub",
        "model/device-model.json",
    ], "sorted by path"
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
        {
            "path": "build-context.json",
            "sha256": hashlib.sha256(BUILD_CONTEXT_BYTES).hexdigest(),
        },
        {"path": "patches/zephyr/0001-fix.patch", "sha256": hashlib.sha256(PATCH).hexdigest()},
    ]


# --------------------------------------------------------------------------
# What the freeze refuses
# --------------------------------------------------------------------------


async def test_a_context_yaml_that_changed_after_acceptance_is_refused(client, state) -> None:
    """Defence in depth on top of the extension refusal.

    The pins are two of the three hashed inputs and the document that
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
        profile="oneshot",
        protocol_version=sessions.SESSION_PROTOCOL_VERSION,
        context_format=sessions.CONTEXT_FORMAT_MAX,
    )
    from mcuhome.buildserver.contextstore import SessionPaths

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


def test_this_server_calls_the_workbench_and_never_the_compiler() -> None:
    """The edge that reversed, and the one that did not.

    This server used to carry the *whole* driving half of the build
    contract, so the rule was that it consumed the vocabulary
    (``mcuhome.model``) and neither of the halves built on it. It is an
    orchestrator no longer: a session's build environment is the
    workbench's, which is the entire point — a fix to how a container is
    driven is one fix rather than two.

    What has not moved, and is what this test is now for, is the other
    edge. ``mcuhome.compiler`` is the program that runs **inside** the
    build container. A build server that imported it would be carrying a
    toolchain it exists to keep at arm's length, and the container it
    drives would no longer be the only thing that compiles.
    """
    import ast
    from pathlib import Path

    package = Path(__file__).resolve().parents[2] / "mcuhome" / "buildserver"
    offenders = []
    for source in sorted(package.rglob("*.py")):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            offenders += [
                f"{source.name}: {name}" for name in names if name.startswith("mcuhome.compiler")
            ]
    assert offenders == []


def test_importing_this_server_does_not_load_the_compiler() -> None:
    """And it holds at run time, not only in the syntax tree.

    The syntax check above cannot see a dynamic import, and the
    workbench has one on purpose: it resolves ``mcuhome.compiler``
    through ``importlib`` for the build methods that need a toolchain.
    Reaching it from here would mean this server had asked for one.
    """
    import subprocess
    import sys

    probe = (
        "import sys, mcuhome.buildserver.app, mcuhome.buildserver.backend;"
        "print('mcuhome.compiler' in sys.modules)"
    )
    answer = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert answer.stdout.strip() == "False", answer.stdout


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
    assert len(CONTEXT_ID_VECTORS) >= 6
    for vector in CONTEXT_ID_VECTORS:
        assert vector_id(vector) == vector["id"], vector["name"]


def test_a_utf16_ordering_of_the_files_array_is_caught_by_the_vectors() -> None:
    """The suite's own coverage, checked where the second party runs it.

    The document under the hash *is* RFC 8785, and RFC 8785 orders object
    keys by UTF-16 code units — so a second implementation reaching for
    its JCS library's comparator for the ``files`` array is the plausible
    mistake rather than an exotic one. The two orders agree across the
    whole BMP and disagree the moment an astral path meets a BMP one, so
    a suite in which no vector holds both would pass such an
    implementation and let it compute a different context ID forever.

    This server is one of the two parties that must agree, so it checks
    the property here rather than trusting that the table has it: replay
    every vector with the wrong sort, and some vector must come out
    wrong.
    """

    def utf16_id(vector: dict) -> str:
        inputs = vector["inputs"]
        document = {
            "files": [
                {"path": path, "sha256": sha256}
                for path, sha256 in sorted(
                    inputs["files"], key=lambda entry: entry[0].encode("utf-16-be")
                )
            ],
            "sdk": {"sha256": inputs["sdk_sha256"]},
            "target": {"board": inputs["board"]},
        }
        return "sha256:" + hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()

    wrong = [vector["name"] for vector in CONTEXT_ID_VECTORS if utf16_id(vector) != vector["id"]]
    assert wrong, "no vector distinguishes code-point order from UTF-16 code-unit order"


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
                environment_digest=IMAGE_DIGEST,
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
    assert listed == ["build-context.json", "keys/signing.pub", "model/device-model.json"]


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
    from mcuhome.buildserver.contextstore import SessionPaths

    session = manager.open(
        profile="oneshot",
        protocol_version=sessions.SESSION_PROTOCOL_VERSION,
        context_format=sessions.CONTEXT_FORMAT_MAX,
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


def test_a_session_running_an_invocation_is_not_idle(tmp_path) -> None:
    """A build is one command that then runs for minutes.

    Counting commands alone, a session compiling away looked idle after
    ten minutes and was reaped under its own build — the container
    removed mid-compile, the client left waiting on a verdict that could
    never arrive. Observed on a real remote build before this held.
    """
    manager = sessions.SessionManager(ttl=3600.0, idle_timeout=1.0)
    session = _abandoned(manager, tmp_path)
    session.last_command_at = time.time() - 60.0
    session.invocations["inv-1"] = sessions.INVOCATION_RUNNING

    assert manager.reap() == (), "a session doing work is not an idle one"
    assert session.paths.root.exists()

    # And the moment the work ends, the idle half applies again — the
    # exemption is "is working", not "has ever worked".
    session.invocations["inv-1"] = sessions.INVOCATION_FINISHED
    assert manager.reap() == (session.id,)


def test_a_session_fetching_its_build_environment_is_not_idle(tmp_path) -> None:
    """The other long command, and the one that was missed.

    ``send-context`` receives an archive and then fetches the build
    environment the context pinned — over a gigabyte, minutes of it,
    with the client blocked on the command frame the whole time.
    Observed on a real remote build: "fetching build environment" at one
    second, "reaped 1 expired session" twenty-seven seconds later, on a
    server whose idle timeout was fifteen. The work was thrown away
    under the client that was waiting for it.

    ``_context_work`` holds the flag for exactly as long as one of the
    three context verbs is in flight, which is why the exemption is that
    flag and not a timer of its own.
    """
    manager = sessions.SessionManager(ttl=3600.0, idle_timeout=1.0)
    session = _abandoned(manager, tmp_path)
    session.last_command_at = time.time() - 60.0
    session.context_busy = True

    assert manager.reap() == (), "a session fetching an image is not an idle one"
    assert session.paths.root.exists()

    # And when the command is acknowledged, the idle half applies again.
    session.context_busy = False
    assert manager.reap() == (session.id,)


def test_a_long_context_command_leaves_its_session_usable(tmp_path) -> None:
    """Finishing work is activity — the other half of the same rule.

    The idle clock counts absent *commands*, and the command that
    started this one was sent before it ran. A ``send-context`` that
    spent a hundred seconds fetching a build environment was
    acknowledged into a session already past its idle timeout, and the
    very next verb — ``lock-context``, the one that freezes what just
    arrived — was refused ``session.expired``. Observed on a real remote
    build, with the fetched image sitting there unused.

    The invocation path had this rule already (``_drive`` touches when a
    build ends); the context path did not.
    """
    manager = sessions.SessionManager(ttl=3600.0, idle_timeout=15.0)
    session = _abandoned(manager, tmp_path)
    session.last_command_at = time.time() - 100.0

    with sessions._context_work(session):
        pass

    # The session is usable, which is what the client's next verb needs.
    assert manager.require(session.id) is session
    assert manager.reap() == ()


def test_the_hard_ttl_takes_a_working_session_anyway(tmp_path) -> None:
    """The two halves keep their own meanings.

    "The hard TTL bounds a session that is working" — so the exemption
    above belongs to the idle half alone, and a running invocation
    cannot make a session immortal.
    """
    manager = sessions.SessionManager(ttl=1.0, idle_timeout=3600.0)
    session = _abandoned(manager, tmp_path)
    session.expires_at = time.time() - 1.0
    session.invocations["inv-1"] = sessions.INVOCATION_RUNNING

    assert manager.reap() == (session.id,)
    assert manager.reaped_reason(session.id) == "lease"


def test_finishing_an_invocation_restarts_the_idle_clock(tmp_path) -> None:
    """The end of a build is activity, and no command marks it.

    The command that starts a build is sent before it runs, so a
    fifteen-minute build ends into a session already past its idle
    timeout — and the next verb is ``get-artifact``, the one that
    collects what the build produced. Observed exactly so: 892 seconds of
    compiling, delivered nowhere, refused with ``session.expired``.
    """
    manager = sessions.SessionManager(ttl=3600.0, idle_timeout=1.0)
    session = _abandoned(manager, tmp_path)
    session.last_command_at = time.time() - 60.0
    session.invocations["inv-1"] = sessions.INVOCATION_RUNNING

    # The build ends: state first, then the touch the backend performs.
    session.invocations["inv-1"] = sessions.INVOCATION_FINISHED
    session.touch()

    assert manager.reap() == (), "a session that just finished work is not idle"


def test_the_lease_can_hold_a_build_that_uses_its_whole_deadline(tmp_path) -> None:
    """Two numbers that used to contradict each other.

    The build deadline is the operator's and the hard TTL was a constant
    below it, so a build allowed 90 minutes lived in a session reaped
    after 60 — the deadline could never fire, and the work was thrown
    away by the lease instead.
    """
    deadline = config_module.DEFAULT_BUILD_DEADLINE_SECONDS
    assert sessions.ttl_for(deadline) > deadline

    # An operator who raises the deadline gets a lease that still holds
    # it; one who lowers it keeps the ordinary lease.
    assert sessions.ttl_for(deadline * 2) > deadline * 2
    assert sessions.ttl_for(60) == sessions.DEFAULT_SESSION_TTL


def test_the_idle_half_is_the_operators_and_reaches_the_manager(tmp_path) -> None:
    """Configured, not constant — and wired, not merely accepted.

    The hard half is derived from the build deadline, so it has no knob;
    the idle half measures something the server cannot derive, and a
    server that could not be told would make every lease-versus-time
    defect reproducible only by a build long enough to outlast ten
    minutes of silence.
    """
    parsed = config_module.load_config(
        ["--session-idle-timeout-seconds", "15", "--context-root", str(tmp_path)], env={}
    )
    assert parsed.session_idle_timeout_seconds == 15

    variable = config_module.ENV_PREFIX + "SESSION_IDLE_TIMEOUT_SECONDS"
    from_env = config_module.load_config(["--context-root", str(tmp_path)], env={variable: "20"})
    assert from_env.session_idle_timeout_seconds == 20

    state = app_module.ServerState(config=parsed)
    assert state.sessions.idle_timeout == 15
    assert state.sessions.ttl == sessions.ttl_for(parsed.build_deadline_seconds)


def test_admission_is_the_operators_and_reaches_the_manager(tmp_path) -> None:
    """The cap and the waiting room, wired rather than merely accepted.

    The cap was a constant with no option in front of it, which made four
    concurrent sessions a number an operator could not lower on a machine
    that cannot feed four builds. The two seat times are the same kind of setting
    as the idle timeout: a private server sets the base high, a public
    one low.
    """
    parsed = config_module.load_config(
        [
            "--max-sessions",
            "1",
            "--seat-retry-seconds",
            "30",
            "--seat-retry-max-seconds",
            "300",
            "--max-seats",
            "8",
            "--context-root",
            str(tmp_path),
        ],
        env={},
    )
    assert (parsed.max_sessions, parsed.max_seats) == (1, 8)

    variable = config_module.ENV_PREFIX + "MAX_SESSIONS"
    from_env = config_module.load_config(["--context-root", str(tmp_path)], env={variable: "2"})
    assert from_env.max_sessions == 2

    state = app_module.ServerState(config=parsed)
    assert state.sessions.max_open == 1
    assert state.sessions.seats.retry_seconds == 30
    assert state.sessions.seats.retry_max_seconds == 300
    assert state.sessions.seats.max_seats == 8


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
