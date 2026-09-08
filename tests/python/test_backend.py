# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The backend, over the wire: argv, documents, events, artifacts.

Every test here drives the real verbs over a real socket against a
container runtime that is stubbed at the seam
(:class:`~tests.python.conftest.FakeDocker`). **No container is ever
started and no build is ever run**, which is a rule of this suite rather
than a convenience: the machine that runs it has one build's worth of
RAM, and a suite that could start a real container would eventually
start one on somebody's laptop.

What is asserted is therefore exactly what this backend is: the ``run``
it composes for one step, the request document it writes, what it makes
of the result document that comes back, and what reaches the client
while it happens. The step itself — the tree, the judgement, the
liveness ladder — is the workbench's container profile, the same code a
local container build runs, and is tested there.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest
from mcuhome.workbench import buildenvsession, buildprocess, containerbuild
from ruamel.yaml import YAML

from mcuhome.buildserver import sessions
from tests.python.conftest import (
    BUILD_CONTEXT_BYTES,
    ENVIRONMENT,
    ENVIRONMENT_VERSION,
    IMAGE,
    IMAGE_DIGEST,
    IMAGE_LABELS,
    IMAGE_RUNNABLE,
    IMAGE_TAG,
    TOOLS_PACKAGE,
    FakeProcess,
    auth,
    buildable_context,
    call,
    collect,
    conforming_environment,
    context_yaml,
    environment_labels,
    failing_environment,
    hanging_environment,
    make_archive,
    send_archive,
    silent_environment,
    write_result,
    write_sdk_package,
)

MODEL = b'{"device": {"board": "nrf7002dk/nrf5340/cpuapp"}}'
PATCH = b"--- a/x\n+++ b/x\n"


@pytest.fixture
def config(config):
    """The suite's config, with the patch layers this protocol knows allowed.

    Overridden for this module alone. The config **is** the patch policy
    and unlisted layers are denied by default, which is right everywhere
    else; here it would mean no test could ever send a patched context.
    """
    return replace(config, allowed_patch_layers=sessions.PATCH_LAYERS)


async def open_session(ws) -> str:
    frame = await call(
        ws, "open-session", {"protocol_version": sessions.SESSION_PROTOCOL_VERSION}, frame_id="o"
    )
    return frame["payload"]["session"]["id"]


async def locked(ws, config, **files: bytes) -> tuple[str, str]:
    """A session with a frozen, buildable context. Returns ids."""
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    session_id = await open_session(ws)
    sent = await send_archive(ws, "send-context", session_id, buildable_context(sha256, **files))
    assert sent["type"] == "result", sent
    frozen = await call(ws, "lock-context", {"session_id": session_id}, frame_id="l")
    assert frozen["type"] == "result", frozen
    return session_id, frozen["payload"]["context_id"]


async def built(ws, config, **files: bytes) -> tuple[str, list[dict]]:
    """One session that locked a context and ran one build to its verdict."""
    session_id, _ = await locked(ws, config, **files)
    await call(ws, "build", {"session_id": session_id}, frame_id="b")
    return session_id, await collect(ws, until="invocation.verdict")


def _volumes(argv: list[str]) -> list[str]:
    return [item for index, item in enumerate(argv) if argv[index - 1] == "--volume"]


# --------------------------------------------------------------------------
# The step: what this backend actually says to a container runtime
# --------------------------------------------------------------------------


async def test_the_step_runs_the_entry_point_the_specification_fixes(
    client, config, docker
) -> None:
    """§6: the entry point at its fixed path, with **no arguments**.

    Composed from the base directory and the path the specification
    fixes, never taken from the image's own ``CMD``: an image is not
    required to name one, and an environment that did would be telling
    the orchestrator how to start it — which is the one thing §6 puts on
    this side.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await built(ws, config, **{"model/device-model.json": MODEL})

    started = docker.step
    assert started[-1] == "/mcuhome/bin/build-environment-entry"
    assert started[-2] == IMAGE_RUNNABLE
    environment = [started[index + 1] for index, item in enumerate(started) if item == "--env"]
    assert environment == ["MCUHOME_BUILDER_BASE_DIR=/"]


async def test_the_step_gets_one_fresh_container_and_no_network(client, config, docker) -> None:
    """The flags that make a step a step, and the reason for each.

    ``--rm`` and one container per step is how the specification's
    pristine-tree guarantee (§3) is met for free: nothing a step wrote
    survives the container it ran in. ``--network none`` is §11's "no
    network" made checkable rather than asserted — "everything a build
    needs is in your packages, in the SDK, or in the build context" is
    not a property one can read off a build log. ``--init`` is
    arithmetic: a build spawns hundreds of short-lived children and PID 1
    has to reap them. ``--name`` is what lets a step that was stopped be
    reaped by name rather than by hope.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)

    started = docker.step
    assert started[:2] == ["docker", "run"]
    assert "--rm" in started
    assert "--init" in started
    assert started[started.index("--network") + 1] == "none"
    assert "--user" in started
    assert started[started.index("--name") + 1] == f"mcuhome-{session_id}-1"


async def test_the_tree_is_mounted_piece_by_piece_and_never_wholesale(
    client, config, docker, state
) -> None:
    """§4's tree, and what is **absent** from the mount set is the point.

    The specification makes ``build-context`` a directory the
    environment may never write and ``sdk`` one it should treat as
    read-only, and in this profile the strongest means of saying so is a
    read-only bind mount — kernel-enforced rather than a promise the
    environment is asked to keep. One bind mount of the session root
    would satisfy neither, and it would hand the step ``downloads``,
    where ``get-artifact`` builds the archive it is about to stream to a
    client.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)
        paths = state.sessions.require(session_id).paths

    mounted = _volumes(docker.step)
    targets = {volume.removesuffix(":ro").rsplit(":", 1)[1] for volume in mounted}
    assert targets == {
        "/mcuhome/invocation-request.json",
        "/mcuhome/sdk",
        "/mcuhome/build-context",
        "/mcuhome/out",
        "/mcuhome/cache/local",
    }
    assert f"{paths.context}:/mcuhome/build-context:ro" in mounted
    assert f"{paths.sdk}:/mcuhome/sdk:ro" in mounted
    assert not any(volume.startswith(f"{paths.root}:") for volume in mounted)
    assert not any(str(paths.downloads) in volume for volume in mounted)
    assert not any(str(paths.staging) in volume for volume in mounted)


async def test_work_is_not_mounted_and_out_is(client, config, docker) -> None:
    """§4: ``work`` is empty at the start of every step, ``out`` survives it.

    A fresh container gives the first for nothing — mounting anything at
    ``work`` would hand the step a directory that outlives it — while
    ``out`` "holds the artifacts of the whole session" and is therefore
    the one writable thing this side provides.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await built(ws, config)

    mounted = _volumes(docker.step)
    assert not any(volume.endswith(":/mcuhome/work") for volume in mounted)
    out = next(volume for volume in mounted if volume.endswith(":/mcuhome/out"))
    assert not out.endswith(":ro")


async def test_the_image_is_named_by_digest_and_never_by_tag(client, config, docker) -> None:
    """A tag can be made to point at other bytes; a digest cannot.

    The image was chosen by the labels of one manifest, and it is that
    manifest's digest which runs — so a build cannot be served by bytes
    other than the ones whose declaration was checked.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await built(ws, config, **{"model/device-model.json": MODEL})

    named = [argument for argument in docker.step if argument.startswith(IMAGE)]
    assert named
    assert all(IMAGE_DIGEST in argument for argument in named)


async def test_the_step_is_started_with_this_servers_hard_limits(client, config, docker) -> None:
    """The numbers the configuration carries, on the container itself.

    The orchestrating side cannot trust an environment to stay inside a
    recommendation — it may have a bug and run amok — so the guard is
    outside it, and §11 tells the environment plainly that whatever
    budget was set may be enforced hard. The memory ceiling is this
    server's own default; the CPU figure is this host, unless an
    operator said otherwise.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await built(ws, config)

    started = docker.step
    assert started[started.index("--memory") + 1] == "8589934592"
    assert started[started.index("--pids-limit") + 1] == str(config.container_pids) == "4096"
    assert float(started[started.index("--cpus") + 1]) > 0


async def test_an_operator_moves_both_halves_of_the_budget_at_once(
    aiohttp_client, config, docker
) -> None:
    """``--container-cpus`` and ``--container-memory``, in both places.

    The same two numbers are the recommendation in the request document
    and the hard limits on the container, and they have to be the same
    two numbers: an environment told it may use four cores while the
    runtime holds it to one would size its parallelism from a budget it
    does not have.
    """
    from mcuhome.buildserver.app import ServerState, create_app

    state = ServerState(replace(config, container_cpus="2.5", container_memory="6g"))
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await built(ws, state.config)

    started = docker.step
    assert started[started.index("--cpus") + 1] == "2.5"
    assert started[started.index("--memory") + 1] == str(6 * 1024**3)
    limits = docker.invocations[-1].request["limits"]
    assert limits == {"cpus": 2.5, "memory_bytes": 6 * 1024**3}


async def test_a_server_that_bounds_no_memory_states_none(aiohttp_client, config, docker) -> None:
    """The empty string is an operator saying "not by memory, here".

    A figure that bounds nothing is left unstated rather than written as
    a zero: ``--memory 0`` is the runtime's own spelling for *no limit*,
    and ``"memory_bytes": 0`` in the request document would tell an
    environment to fit in nothing.
    """
    from mcuhome.buildserver.app import ServerState, create_app

    state = ServerState(replace(config, container_memory=""))
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await built(ws, state.config)

    assert "--memory" not in docker.step
    assert "memory_bytes" not in docker.invocations[-1].request["limits"]


# --------------------------------------------------------------------------
# The request document (§6.1)
# --------------------------------------------------------------------------


async def test_the_request_document_carries_every_field_the_specification_defines(
    client, config, docker
) -> None:
    """§6.1's object, and nothing invented beside it.

    The generation this side speaks, the two identifiers, the action and
    its parameters. ``session_id`` is opaque — "never build a path from
    it" — and ``invocation_id`` is the one the result document is named
    after.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)

    document = docker.invocations[-1].request
    assert document["spec_generation"] == buildenvsession.SPEC_GENERATION
    assert document["session_id"] == session_id
    assert document["invocation_id"] == f"{session_id}-1"
    assert document["action"] == "build"
    assert document["parameters"] == {}
    assert set(document) <= {
        "spec_generation",
        "session_id",
        "invocation_id",
        "action",
        "parameters",
        "limits",
    }


async def test_a_request_document_never_names_this_machine(client, config, docker, state) -> None:
    """A build cannot tell this server from a workbench building locally.

    Nothing in the document is a path at all — the tree is where §4 says
    it is, identical on every machine and for every session. It is worth
    pinning rather than assuming: the compiler cache is keyed on the
    compile command line, into which Zephyr puts absolute paths, so one
    session directory leaking through would give this server a cache per
    session, which is no cache at all.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)
        paths = state.sessions.require(session_id).paths

    document = json.dumps(docker.invocations[-1].request)
    assert str(paths.root) not in document
    assert "/tmp" not in document


async def test_the_mode_a_client_asks_for_does_not_travel(client, config, docker) -> None:
    """Every step of this profile is clean, so ``incremental`` is answered clean.

    The build action takes no parameters at all, and the reason is the
    profile rather than the vocabulary: one fresh container per step is
    what makes the pristine-tree guarantee free, and a container that
    starts empty has nothing to build incrementally on. Answering a
    clean build is never wrong — it is slower than what was asked for and
    is what was asked for plus safety — while a parameter this side
    invented would be a promise nothing keeps.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id, "mode": "incremental"}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")

    assert frames[-1]["payload"]["status"] == "success"
    assert docker.invocations[-1].request["parameters"] == {}


# --------------------------------------------------------------------------
# The cache tiers (§8)
# --------------------------------------------------------------------------


@pytest.fixture
def cached(config, tmp_path):
    return replace(config, ccache_dir=tmp_path / "ccache")


async def test_the_shared_cache_is_offered_read_only(aiohttp_client, cached, docker) -> None:
    """§8: ``shared`` belongs to the orchestrator, and here it is read-only.

    A build server serves contexts it does not trust and has no cache
    warming verb, so there is deliberately no writable mode: an option
    that made an untrusted build's shared cache writable would be the one
    setting that turns a shared cache into a shared attack surface.
    """
    from mcuhome.buildserver.app import ServerState, create_app

    # The directory is the operator's to create: the tier is offered
    # read-only, so an empty one behaves exactly like no mount, and a
    # server that made it would be claiming a cache nobody warmed.
    cached.ccache_dir.mkdir(parents=True, exist_ok=True)
    state = ServerState(cached)
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await built(ws, cached)

    mounted = _volumes(docker.step)
    assert f"{cached.ccache_dir}:/mcuhome/cache/shared:ro" in mounted


async def test_without_a_configured_cache_only_the_local_tier_exists(
    client, config, docker
) -> None:
    """§8: a tier the orchestrator provides nothing for is simply absent.

    "May be missing entirely" is the specification's own wording, and an
    empty directory would be a warm cache that is not one.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await built(ws, config)

    tiers = [
        volume.removesuffix(":ro").rsplit(":", 1)[1]
        for volume in _volumes(docker.step)
        if "/mcuhome/cache/" in volume
    ]
    assert tiers == ["/mcuhome/cache/local"]


# --------------------------------------------------------------------------
# The answer, the events and the log
# --------------------------------------------------------------------------


async def test_a_working_verb_answers_the_invocation_id_immediately(client, config) -> None:
    """``build`` answers ``{invocation_id}`` at once.

    A build is minutes to hours; a command frame that waited for it
    would make every client's socket a build timer, and a client that
    lost the socket would lose the result of work that is still running.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, context_id = await locked(ws, config)
        answer = await call(ws, "build", {"session_id": session_id}, frame_id="b")
        assert answer["type"] == "result"
        assert answer["payload"] == {
            "session_id": session_id,
            "invocation_id": "inv-1",
            "action": "build",
            "context_id": context_id,
            # What this server will actually do, whatever was asked for.
            "mode": "clean",
        }
        frames = await collect(ws, until="invocation.verdict")

    finished = frames[-1]["payload"]
    assert finished["status"] == "success"
    assert finished["error"] is None
    assert sorted(entry["path"] for entry in finished["artifacts"]) == [
        "build-report.json",
        "firmware.bin",
        "firmware.hex",
    ]


async def test_the_verdict_attributes_to_the_servers_own_context_id(client, config) -> None:
    """Attribution always uses the identity this server computed itself.

    It is the value the freeze wrote and the one every invocation is
    re-measured against, so it is the only one that says what was
    actually built.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, context_id = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")

    assert frames[-1]["payload"]["context"] == context_id


async def test_the_raw_log_is_its_own_frame_type_with_its_own_counter(
    client, config, docker
) -> None:
    """The log is a separate kind of frame, and it counts its own lines.

    Standard output and standard error together are one raw, opaque
    stream that a consumer must not parse for machine decisions, while
    an event is something a consumer matches on. The counter is what
    makes the transport's drop-the-oldest policy safe for the first: a
    client that sees the numbers jump knows it lost lines rather than
    believing it read a complete log with a silent hole in it.
    """

    def talkative(request, out, on_line):
        on_line("-- west build")
        on_line("-- ninja: no work to do")
        return conforming_environment(request, out, on_line)

    docker.run_program = talkative
    async with client.ws_connect("/ws", headers=auth()) as ws:
        _, frames = await built(ws, config)

    logs = [frame for frame in frames if frame.get("type") == "log"]
    assert [entry["payload"]["seq"] for entry in logs][:2] == [1, 2]
    assert logs[0]["payload"]["line"] == "-- west build"
    assert logs[0]["payload"]["invocation_id"] == "inv-1"


async def test_the_events_are_this_servers_own_and_are_numbered(client, config) -> None:
    """A build environment has no event channel, so the stream is this side's.

    The specification gives an environment a request document, a result
    document and a log — and nothing else. What a client follows is
    therefore what this server did: the invocation started, and the
    verdict it reached. Numbering them is what makes the file
    ``attach-session`` replays resumable.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await ws.send_json({"id": "b", "type": "build", "payload": {"session_id": session_id}})
        frames = await collect(ws, until="invocation.verdict")

    events = [frame for frame in frames if frame.get("type") == "event"]
    assert [frame["event"] for frame in events] == ["invocation.started", "invocation.verdict"]
    assert [frame["payload"]["seq"] for frame in events] == [1, 2]
    assert all(frame["payload"]["invocation_id"] == "inv-1" for frame in events)


# --------------------------------------------------------------------------
# What the result document is worth
# --------------------------------------------------------------------------


async def test_no_result_document_is_builder_crashed_and_retryable(client, config, docker) -> None:
    """§6.3: "a step that produced no readable result document failed".

    Whatever it exited with — and it is the retryable one, because it is
    an infrastructure failure rather than a verdict on the context: a
    limit that killed the step produces exactly this, and the same
    invocation may well succeed on a retry.
    """
    docker.run_program = silent_environment
    async with client.ws_connect("/ws", headers=auth()) as ws:
        _, frames = await built(ws, config)

    verdict = frames[-1]["payload"]
    assert verdict["status"] == "failure"
    assert verdict["error"]["code"] == "builder.crashed"
    assert verdict["error"]["retryable"] is True
    assert verdict["artifacts"] == []


async def test_a_failure_carries_the_environments_own_message(client, config, docker) -> None:
    """§6.2's ``message`` is free text for a human, and it travels as such.

    Under a name that says whose sentence it is, bounded and stripped of
    control characters: it is the one untrusted string in the document
    and it ends up in a frame this server signs its name under.
    """
    docker.run_program = failing_environment
    async with client.ws_connect("/ws", headers=auth()) as ws:
        _, frames = await built(ws, config)

    error = frames[-1]["payload"]["error"]
    assert error["code"] == "builder.failed"
    assert error["retryable"] is False
    assert error["details"]["environment_message"] == "the build failed"
    assert error["details"]["status"] == "failure"


async def test_unsupported_says_the_environment_and_not_the_build_is_wrong(
    client, config, docker
) -> None:
    """§6.2: ``unsupported`` means *no environment of my kind can do this*.

    "It tells the orchestrator to look for a different environment
    rather than report a broken build", so it is the one failure of a
    step that comes back as a statement about the environment — a client
    reading it goes to another server, or another image, rather than to
    its own sources.
    """

    def refusing(request, out, on_line):
        write_result(
            request,
            out,
            {
                "spec_generation": buildenvsession.SPEC_GENERATION,
                "invocation_id": request["invocation_id"],
                "status": "unsupported",
                "message": "this environment builds no Matter devices",
                "artifacts": [],
            },
        )
        return FakeProcess(1)

    docker.run_program = refusing
    async with client.ws_connect("/ws", headers=auth()) as ws:
        _, frames = await built(ws, config)

    verdict = frames[-1]["payload"]
    assert verdict["status"] == "unsupported"
    assert verdict["error"]["code"] == "version.builder-unsatisfiable"
    assert "Matter" in verdict["error"]["details"]["environment_message"]


async def test_exit_zero_with_a_failing_document_is_a_violation(client, config, docker) -> None:
    """§6.3, and the pessimistic reading of a contradiction.

    "Exit 0 when you wrote a result document with ``status: success``,
    and non-zero otherwise." Where the two disagree the step failed
    either way; carrying the violation separately is what lets a client
    say that the *environment* misbehaved rather than the build.
    """

    def contradictory(request, out, on_line):
        write_result(
            request,
            out,
            {
                "spec_generation": buildenvsession.SPEC_GENERATION,
                "invocation_id": request["invocation_id"],
                "status": "failure",
                "message": "no",
                "artifacts": [],
            },
        )
        return FakeProcess(0)

    docker.run_program = contradictory
    async with client.ws_connect("/ws", headers=auth()) as ws:
        _, frames = await built(ws, config)

    verdict = frames[-1]["payload"]
    assert verdict["status"] == "failure"
    assert verdict["environment_violation"]


async def test_a_declared_artifact_that_does_not_re_hash_is_not_served(
    client, config, docker
) -> None:
    """What a client is offered is what was measured, not what was declared.

    The artifacts are hashed where they actually are, by the side that
    will hand them over — so a name in the result document that no file
    answers to is a failed step rather than a delivery with a hole in it.
    """

    def lying(request, out, on_line):
        write_result(
            request,
            out,
            {
                "spec_generation": buildenvsession.SPEC_GENERATION,
                "invocation_id": request["invocation_id"],
                "status": "success",
                "message": "",
                "artifacts": ["firmware.bin"],
            },
        )
        return FakeProcess(0)

    docker.run_program = lying
    async with client.ws_connect("/ws", headers=auth()) as ws:
        _, frames = await built(ws, config)

    verdict = frames[-1]["payload"]
    assert verdict["status"] == "failure"
    assert verdict["artifacts"] == []


async def test_an_artifact_outside_out_is_never_resolved(client, config, docker, state) -> None:
    """A declared name that leaves ``out`` is refused rather than followed.

    ``out`` is the whole of what a step may deliver, and a symlink out of
    it is the shape an escape takes: a client that asked for
    ``firmware.bin`` would be handed the bytes of a host file the step
    never produced.
    """

    def escaping(request, out, on_line):
        outside = out.parent / "outside"
        outside.write_bytes(b"a host file\n")
        (out / "firmware.bin").symlink_to(outside)
        write_result(
            request,
            out,
            {
                "spec_generation": buildenvsession.SPEC_GENERATION,
                "invocation_id": request["invocation_id"],
                "status": "success",
                "message": "",
                "artifacts": ["firmware.bin"],
            },
        )
        return FakeProcess(0)

    docker.run_program = escaping
    async with client.ws_connect("/ws", headers=auth()) as ws:
        _, frames = await built(ws, config)

    verdict = frames[-1]["payload"]
    assert verdict["status"] == "failure"
    assert verdict["artifacts"] == []


# --------------------------------------------------------------------------
# get-artifact
# --------------------------------------------------------------------------


async def test_get_artifact_announces_an_archive_and_streams_it(client, config) -> None:
    """The mirror of the upload, and the bytes are a ``tar.zst``.

    The result frame **is** the announcement — size, SHA-256 and what is
    in the archive — and the BINARY frames follow it. There is no
    acknowledgement behind them for the reason the upload needs one and
    this does not: the receiving side is the client, and it knows the
    transfer is complete when it has taken the announced number of bytes.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)
        await ws.send_json(
            {
                "id": "g",
                "type": "get-artifact",
                "payload": {"session_id": session_id, "invocation_id": "inv-1"},
            }
        )
        announcement = None
        while announcement is None:
            frame = await ws.receive_json(timeout=15)
            if frame.get("id") == "g":
                announcement = frame
        archive = b""
        while len(archive) < announcement["payload"]["archive"]["size"]:
            message = await ws.receive(timeout=15)
            archive += message.data

    announced = announcement["payload"]["archive"]
    assert hashlib.sha256(archive).hexdigest() == announced["sha256"]
    assert len(archive) == announced["size"]

    import io
    import tarfile

    import zstandard

    raw = zstandard.ZstdDecompressor().decompress(archive, max_output_size=1 << 20)
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        assert sorted(tar.getnames()) == ["build-report.json", "firmware.bin", "firmware.hex"]


async def test_get_artifact_with_a_path_holds_exactly_that_one(client, config) -> None:
    """With ``path``, the archive holds exactly that declared artifact."""
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)
        await ws.send_json(
            {
                "id": "g",
                "type": "get-artifact",
                "payload": {
                    "session_id": session_id,
                    "invocation_id": "inv-1",
                    "path": "firmware.bin",
                },
            }
        )
        while True:
            frame = await ws.receive_json(timeout=15)
            if frame.get("id") == "g":
                break

    members = frame["payload"]["artifacts"]
    assert [entry["path"] for entry in members] == ["firmware.bin"]
    assert members[0]["role"] == "firmware"


async def test_a_path_that_is_not_a_declared_artifact_is_typed(client, config) -> None:
    """``artifact.unknown``, with the paths the invocation did declare.

    The invocation exists and answered, so the statement is about the
    artifact rather than about the invocation.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)
        frame = await call(
            ws,
            "get-artifact",
            {"session_id": session_id, "invocation_id": "inv-1", "path": "zephyr.elf"},
            frame_id="g",
        )

    error = frame["error"]
    assert error["code"] == "artifact.unknown"
    assert error["retryable"] is False
    assert "firmware.hex" in error["details"]["declared"]


async def test_get_artifact_of_an_unknown_invocation_reuses_the_invocation_code(
    client, config
) -> None:
    """``invocation.unknown`` — the id, not the path, is what is wrong."""
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        frame = await call(
            ws,
            "get-artifact",
            {"session_id": session_id, "invocation_id": "inv-9"},
            frame_id="g",
        )
    assert frame["error"]["code"] == "invocation.unknown"


async def test_a_download_that_no_longer_matches_what_was_verified_is_refused(
    client, config, state
) -> None:
    """The artifacts are re-measured at delivery, not trusted from the step.

    A session's tree stays writable between the end of a step and the
    download, so a check made once and trusted afterwards is a check that
    can be walked around — and what would be delivered is a file's bytes
    under a name somebody else verified.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)

        record = state.backend.record(session_id, "inv-1")
        outside = state.config.context_root / "outside"
        outside.write_bytes(b"a host file outside out/\n")
        (record.out / "firmware.hex").unlink()
        (record.out / "firmware.hex").symlink_to(outside)

        frame = await call(
            ws,
            "get-artifact",
            {"session_id": session_id, "invocation_id": "inv-1", "path": "firmware.hex"},
            frame_id="g",
        )

    assert frame["type"] == "error"
    assert frame["error"]["code"] == "artifact.integrity-mismatch"
    assert frame["error"]["retryable"] is False
    assert frame["error"]["details"]["path"] == "firmware.hex"


async def test_one_download_at_a_time_per_connection_and_never_one_spool(
    client, config, monkeypatch
) -> None:
    """Two ``get-artifact`` commands on one connection, and neither corrupts
    the other.

    Every command runs as its own task, so two downloads would interleave
    their BINARY frames — which carry no id, so a client cannot sort them
    — and a spool named by invocation id alone would have two deliveries
    of one invocation write the same file, the first to finish unlinking
    it while the second was still streaming it.
    """
    from mcuhome.buildserver import artifacts
    from mcuhome.buildserver import sessions as session_module

    spools: list[str] = []
    live = 0
    concurrent = 0
    real = artifacts.build_archive

    def slow(*, out, artifacts: tuple, spool: Path):
        nonlocal live, concurrent
        live += 1
        concurrent = max(concurrent, live)
        spools.append(spool.name)
        try:
            time.sleep(0.05)
            return real(out=out, artifacts=artifacts, spool=spool)
        finally:
            live -= 1

    monkeypatch.setattr(session_module.artifacts, "build_archive", slow)

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)
        for frame_id in ("g1", "g2"):
            await ws.send_json(
                {
                    "id": frame_id,
                    "type": "get-artifact",
                    "payload": {"session_id": session_id, "invocation_id": "inv-1"},
                }
            )
        answered: dict[str, dict] = {}
        received: dict[str, bytes] = {}
        current: str | None = None
        while len(answered) < 2 or any(
            len(received[key]) < answered[key]["payload"]["archive"]["size"] for key in answered
        ):
            message = await ws.receive(timeout=15)
            if message.type.name == "BINARY":
                assert current is not None
                received[current] += message.data
                continue
            frame = json.loads(message.data)
            if frame.get("id") in ("g1", "g2"):
                answered[frame["id"]] = frame
                received[frame["id"]] = b""
                current = frame["id"]

    assert concurrent == 1, "two archives were built at the same time on one connection"
    assert len(set(spools)) == 2, "two deliveries shared one spool file"
    for key, frame in answered.items():
        assert len(received[key]) == frame["payload"]["archive"]["size"]
        assert hashlib.sha256(received[key]).hexdigest() == frame["payload"]["archive"]["sha256"]


# --------------------------------------------------------------------------
# Off the event loop
# --------------------------------------------------------------------------


async def test_nothing_filesystem_heavy_runs_on_the_event_loop(
    client, config, docker, monkeypatch
) -> None:
    """The SDK and the artifact archive, both off the loop.

    ``acquire_sdk`` hashes a package, streams a full zstd decompression
    to disk and untars it; ``build_archive`` tars and compresses a
    build's artifacts and then re-reads the spool. Either on the event
    loop stalls every other session, every other connection and the
    WebSocket heartbeat — which drops unrelated clients after thirty
    seconds.
    """
    from mcuhome.buildserver import artifacts, backend

    threads: dict[str, threading.Thread] = {}

    def record(name, function):
        def wrapper(*arguments, **keywords):
            threads[name] = threading.current_thread()
            return function(*arguments, **keywords)

        return wrapper

    monkeypatch.setattr(
        backend.packagefetch, "acquire_sdk", record("sdk", backend.packagefetch.acquire_sdk)
    )
    monkeypatch.setattr(artifacts, "build_archive", record("archive", artifacts.build_archive))

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)
        await ws.send_json(
            {
                "id": "g",
                "type": "get-artifact",
                "payload": {"session_id": session_id, "invocation_id": "inv-1"},
            }
        )
        while True:
            frame = await ws.receive_json(timeout=15)
            if frame.get("id") == "g":
                break

    assert set(threads) == {"sdk", "archive"}
    for name, thread in threads.items():
        assert thread is not threading.main_thread(), f"{name} ran on the event loop"


async def test_the_verdict_frame_is_sent_and_never_offered(client, config, monkeypatch):
    """The one frame with no second way to be learned.

    The log is offered — dropping the oldest line rather than applying
    backpressure through the log reader and from there into the compiler
    — and it carries a counter that makes a gap visible. The verdict is
    this server's own judgement, a client is waiting for exactly it, and
    a drop would lose it for good.
    """
    from mcuhome.buildserver.ws import Connection

    offered: list[dict] = []
    sent: list[dict] = []
    real_offer, real_send = Connection.offer, Connection.send

    def offer(self, frame):
        offered.append(frame)
        return real_offer(self, frame)

    async def send(self, frame):
        sent.append(frame)
        return await real_send(self, frame)

    monkeypatch.setattr(Connection, "offer", offer)
    monkeypatch.setattr(Connection, "send", send)

    async with client.ws_connect("/ws", headers=auth()) as ws:
        await built(ws, config)

    def verdict(frames):
        return [frame for frame in frames if frame.get("event") == "invocation.verdict"]

    assert len(verdict(sent)) == 1
    assert verdict(offered) == []
    assert any(frame.get("type") == "log" for frame in offered)
    assert any(frame.get("event") == "invocation.started" for frame in offered)


# --------------------------------------------------------------------------
# attach-session, cancel, close-session
# --------------------------------------------------------------------------


async def test_attach_session_replays_before_it_joins_the_live_stream(
    client, config, monkeypatch
) -> None:
    """The boundary is a boundary, and the ordering is what makes it one.

    Every event frame a client sees before the verb's answer is history
    and everything after it is live — which fails the moment the
    connection joins the audience *before* the replay: every ``await`` in
    the replay loop is a turn for the supervisor of an invocation that is
    still running, so live frames land among the replayed ones and an
    event the reader has not reached yet is delivered twice.

    Asserted on the order of the two operations rather than on a race,
    because a race that reproduces sometimes is a test that passes
    sometimes.
    """
    from mcuhome.buildserver.backend import SessionBackend
    from mcuhome.buildserver.ws import Connection

    timeline: list[tuple[str, object]] = []
    real_attach = SessionBackend.attach
    real_send = Connection.send

    def attach(self, session_id, connection, *, boundary=None):
        timeline.append(("attach", boundary))
        return real_attach(self, session_id, connection, boundary=boundary)

    async def send(self, frame):
        if frame.get("type") == "event":
            timeline.append(("event", frame["payload"].get("seq")))
        return await real_send(self, frame)

    monkeypatch.setattr(SessionBackend, "attach", attach)
    monkeypatch.setattr(Connection, "send", send)

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)
        timeline.clear()
        answer = await call(
            ws,
            "attach-session",
            {"session_id": session_id, "invocation_id": "inv-1", "from_seq": 1},
            frame_id="a",
        )

    assert answer["payload"]["replayed"] == 2
    assert timeline == [("event", 1), ("event", 2), ("attach", ("inv-1", 2))]


def test_an_event_already_replayed_is_not_relayed_to_that_connection_again(
    config, tmp_path
) -> None:
    """The other half of the boundary: history is not repeated as news.

    Joining after the replay closes the interleaving; the boundary closes
    the duplicate. An event this connection already has from the file is
    not delivered to it a second time, while it still reaches every other
    connection, which never saw it.
    """
    from mcuhome.buildserver import protocol
    from mcuhome.buildserver.backend import InvocationRecord, SessionBackend

    class Fake:
        def __init__(self) -> None:
            self.frames: list[dict] = []

        def offer(self, frame):
            self.frames.append(frame)

    backend = SessionBackend(config, docker=object())
    record = InvocationRecord(
        id="inv-1",
        session_id="s-1",
        action="build",
        directory=tmp_path,
        context_id="x",
        out=tmp_path / "out",
    )
    replayed, fresh = Fake(), Fake()
    backend.attach("s-1", replayed, boundary=("inv-1", 6))
    backend.attach("s-1", fresh)

    for seq in (5, 6, 7):
        backend._publish(
            record, protocol.event_frame("invocation.started", {"seq": seq}), drop_when_full=True
        )

    assert [frame["payload"]["seq"] for frame in replayed.frames] == [7]
    assert [frame["payload"]["seq"] for frame in fresh.frames] == [5, 6, 7]


async def test_attach_session_replays_the_verdict_a_lost_socket_missed(client, config) -> None:
    """The NDJSON file on disk **is** the replay buffer.

    It stays there for the life of the session, so a client whose socket
    died during a build reconnects, asks for the invocation it started,
    and is handed the verdict it missed. No in-memory ring behind it,
    which means there is nothing a long reconnect can find already
    evicted.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)

        await ws.send_json(
            {
                "id": "a",
                "type": "attach-session",
                "payload": {
                    "session_id": session_id,
                    "invocation_id": "inv-1",
                    "from_seq": 2,
                },
            }
        )
        replayed: list[dict] = []
        while True:
            frame = await ws.receive_json(timeout=15)
            if frame.get("id") == "a":
                answer = frame
                break
            replayed.append(frame)

    assert answer["payload"]["replayed"] == 1
    assert [entry["event"] for entry in replayed] == ["invocation.verdict"]
    assert replayed[0]["payload"]["status"] == "success"


async def test_cancel_raises_the_stop_sentinel_of_the_running_step(
    aiohttp_client, config, docker
) -> None:
    """Generation 3 defines no cooperative cancellation, so a stop is a signal.

    The sentinel is the orchestrating side's own file and is never named
    in a request document: it is only how the decision to send a signal
    reaches the supervising loop. What actually ends a build is that
    signal and, behind it, the container going away — a signal to the
    client that started the container never reached anything.
    """
    state, client = await _building(aiohttp_client, config, docker)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await _started(docker)
        record = state.backend.record(session_id, "inv-1")
        answer = await call(
            ws, "cancel", {"session_id": session_id, "invocation_id": "inv-1"}, frame_id="c"
        )
        assert answer["payload"]["cancelled"] is True
        assert record.step.cancel.exists()
        frames = await collect(ws, until="invocation.verdict")
        await call(ws, "close-session", {"session_id": session_id}, frame_id="x")

    assert record.cancelled is True
    verdict = frames[-1]["payload"]
    # A stopped step writes no result document, and saying so as a plain
    # failure would hide that the failure was asked for.
    assert verdict["status"] == "cancelled"
    assert verdict["error"] is None


async def test_the_liveness_ladder_signals_a_step_that_will_not_stop(
    aiohttp_client, config, docker
) -> None:
    """The rungs, with a grace of zero so the ladder runs in a test.

    The sentinel first, SIGTERM after the grace period, SIGKILL after
    that. What is asserted is the ladder's shape and never its clock:
    sixty seconds is the right number for a deployment and the wrong one
    for a test.
    """
    from mcuhome.buildserver.app import ServerState, create_app

    processes: list[FakeProcess] = []

    def hanging(request, out, on_line):
        processes.append(FakeProcess(0, hang=True))
        return processes[-1]

    docker.run_program = hanging
    state = ServerState(
        replace(config, cancel_grace_seconds=0, allowed_patch_layers=sessions.PATCH_LAYERS)
    )
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await _started(docker)
        await call(ws, "cancel", {"session_id": session_id, "invocation_id": "inv-1"}, frame_id="c")
        frames = await collect(ws, until="invocation.verdict")

    assert processes[0].terminated is True
    assert frames[-1]["payload"]["status"] == "cancelled"


async def test_the_deadline_is_enforced_from_outside(aiohttp_client, config, docker) -> None:
    """§11: "whatever budget the orchestrator has set, it may enforce hard".

    A step that runs past the operator's deadline is stopped by the same
    ladder a cancel walks — the environment is told nothing and needs to
    be told nothing, because the enforcement is what §11 already
    promises.
    """
    from mcuhome.buildserver.app import ServerState, create_app

    processes: list[FakeProcess] = []

    def hanging(request, out, on_line):
        processes.append(FakeProcess(0, hang=True))
        return processes[-1]

    docker.run_program = hanging
    state = ServerState(replace(config, build_deadline_seconds=0, cancel_grace_seconds=0))
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")

    assert processes[0].terminated is True
    assert frames[-1]["payload"]["status"] == "failure"


async def test_a_step_that_ignores_sigterm_is_killed(
    aiohttp_client, config, docker, monkeypatch
) -> None:
    """The last rung, and the shortest.

    By the time it is reached the step has ignored a signal it was
    expected to handle. What reaps one that ignores this too is the
    container going away when the session is released — there is always
    that hammer behind this one.
    """
    from mcuhome.buildserver.app import ServerState, create_app

    monkeypatch.setattr(buildprocess, "_KILL_AFTER_SECONDS", 0.0)
    processes: list[FakeProcess] = []

    def stubborn(request, out, on_line):
        processes.append(FakeProcess(0, hang=True, ignores_terminate=True))
        return processes[-1]

    docker.run_program = stubborn
    state = ServerState(replace(config, build_deadline_seconds=0, cancel_grace_seconds=0))
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    assert processes[0].terminated is True
    assert processes[0].killed is True


async def test_a_reaped_session_tells_whoever_is_waiting(client, config, state) -> None:
    """A build stopped by the sweep owes its client a verdict.

    A client waits for exactly one frame — the verdict of the invocation
    it started — and the socket stays open when a session is reaped, so
    no connection loss ends that wait either. Measured once at 56 minutes
    of a client waiting for a build whose container had long since been
    removed.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)
        # An invocation this server has not judged is what the sweep
        # finds when it takes a session away mid-build.
        state.backend.record(session_id, "inv-1").outcome = None

        await state.backend.release(session_id, reaped="idle timeout")
        frames = await collect(ws, until="invocation.verdict")

    verdict = frames[-1]["payload"]
    assert verdict["invocation_id"] == "inv-1"
    assert verdict["status"] == "failure"
    assert verdict["error"]["code"] == "session.expired"
    assert "idle timeout" in verdict["error"]["message"]
    assert verdict["artifacts"] == []


async def test_a_closed_session_announces_nothing(client, config, state) -> None:
    """``close-session`` is the client's own act, and needs no answer.

    The announcement belongs to the sweep alone: a client that closed a
    session knows it did, and a frame telling it so would be a second
    spelling of its own verb's answer.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)
        state.backend.record(session_id, "inv-1").outcome = None

        await state.backend.release(session_id)
        answer = await call(ws, "capabilities", {}, frame_id="c")

    assert answer["id"] == "c"


async def test_close_session_reaps_the_containers_of_the_session(client, config, docker) -> None:
    """One session's steps are one session's containers, and they go with it.

    ``--rm`` already removed the ones that finished; the sweep is for a
    step that was stopped, and it is best effort because a failed
    teardown must not replace the build's own verdict.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)
        await call(ws, "close-session", {"session_id": session_id}, frame_id="x")

    assert docker.removed == docker.containers
    assert docker.removed


async def test_close_session_stops_the_step_before_it_deletes_the_tree(
    aiohttp_client, config, docker, monkeypatch
) -> None:
    """The order is the guarantee.

    Close is an implicit cancel: the stop signal is raised for a step
    that is still running, the container is removed — which is the actual
    kill, since the build runs inside it — and only then is the tree
    deleted. Deleting first pulls the mount source out from under a step
    that is still running in it.

    The second half is the one that made a whole suite hang: the
    container being gone is not the invocation being over. The supervisor
    runs on a worker thread, and closing used to return while that thread
    was still walking its ladder.
    """
    from mcuhome.buildserver.app import ServerState, create_app

    docker.run_program = hanging_environment
    state = ServerState(replace(config, cancel_grace_seconds=0))
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        session = state.sessions.require(session_id)
        paths = session.paths
        record = state.backend.record(session_id, "inv-1")
        await _started(docker)
        seen = _watch_rm(monkeypatch, docker, paths, record)

        await call(ws, "close-session", {"session_id": session_id}, frame_id="x")
        assert record.drive.done(), "close-session answered while the supervisor was still up"

    assert seen and all(entry == ("rm", True, True) for entry in seen), (
        "the tree was still there and the signal was set at every removal"
    )
    assert not paths.root.exists(), "and the tree is gone once the container is"


async def _started(docker, *, timeout: float = 10.0) -> None:
    """Wait until the fake has a running step, and fail if it never does."""
    deadline = time.monotonic() + timeout
    while not docker.running:
        assert time.monotonic() < deadline, "the invocation never started a step"
        await asyncio.sleep(0.01)


def _watch_rm(monkeypatch, docker, paths, record) -> list[tuple[str, bool, bool]]:
    """Record what was still on disk when the container was removed.

    Each entry is ``(command, the session tree is there, the stop signal
    was raised)`` — the two facts every ordering test here is about.
    """
    seen: list[tuple[str, bool, bool]] = []
    real_answer = docker.answer

    def recording(argv, on_line=None):
        if argv[1] == "rm":
            step = record.step
            seen.append(("rm", paths.root.exists(), step is not None and step.cancel.exists()))
        return real_answer(argv, on_line)

    monkeypatch.setattr(containerbuild, "run_command", recording)
    return seen


async def _building(aiohttp_client, config, docker, **overrides):
    """A server with one session whose step hangs. Returns the lot.

    The grace is zero because the ladder is walked in full here and sixty
    seconds is a deployment's number, not a test's; the step hangs
    because an invocation that has already finished cannot demonstrate
    anything about the order a release does things in.
    """
    from mcuhome.buildserver.app import ServerState, create_app

    docker.run_program = hanging_environment
    state = ServerState(replace(config, cancel_grace_seconds=0, **overrides))
    client = await aiohttp_client(create_app(state))
    return state, client


async def test_the_sweep_stops_the_step_before_it_deletes_the_tree(
    aiohttp_client, config, docker, monkeypatch
) -> None:
    """The reaper walks the same four steps a close does.

    A session whose hard TTL runs out under a running build must not lose
    its tree while the supervisor is still reading it, which is the one
    state neither half can recover from. The sweep marks the session and
    the release does the work.
    """
    state, client = await _building(aiohttp_client, config, docker)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        session = state.sessions.find(session_id)
        paths = session.paths
        record = state.backend.record(session_id, "inv-1")
        await _started(docker)
        seen = _watch_rm(monkeypatch, docker, paths, record)

        session.expires_at = time.time() - 1
        assert state.sessions.reap() == (session_id,)
        assert paths.root.exists(), "the sweep marks it and does not delete under the build"
        assert state.sessions.pending_releases() == (session_id,)

        assert await sessions.release_pending(state) == ()

    assert seen and all(entry == ("rm", True, True) for entry in seen), (
        "the tree was still there and the signal was set at every removal"
    )
    assert record.drive.done(), "and the supervisor was waited for"
    assert not paths.root.exists()


async def test_a_lease_that_runs_out_inside_a_verb_reaches_the_sweep(
    aiohttp_client, config, docker, monkeypatch
) -> None:
    """A refusal cannot stop to remove a container.

    A lease noticed inside a verb answers the client immediately and
    marks the session; the sweep then does the release in the order that
    holds. Doing it inside the refusal would delete a tree a supervisor
    is still reading.
    """
    state, client = await _building(aiohttp_client, config, docker)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        session = state.sessions.find(session_id)
        paths = session.paths
        record = state.backend.record(session_id, "inv-1")
        await _started(docker)
        seen = _watch_rm(monkeypatch, docker, paths, record)

        session.expires_at = time.time() - 1
        refused = await call(ws, "get-artifact", {"session_id": session_id}, frame_id="g")
        assert refused["error"]["code"] == "session.expired"
        assert paths.root.exists(), "a refusal cannot stop to remove a container"
        assert state.sessions.pending_releases() == (session_id,)

        assert await sessions.release_pending(state) == ()

    assert seen and all(entry == ("rm", True, True) for entry in seen)
    assert record.drive.done()
    assert not paths.root.exists()


async def test_shutdown_stops_the_steps_before_the_trees_go(
    aiohttp_client, config, docker, monkeypatch
) -> None:
    """Process exit, in the one order that protects anything.

    The release comes first, under one budget for the whole loop, and the
    trees go afterwards — including the tree of a session that did not
    release, because a stopping process is the last thing that could ever
    name it.
    """
    state, client = await _building(aiohttp_client, config, docker)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        session = state.sessions.find(session_id)
        paths = session.paths
        record = state.backend.record(session_id, "inv-1")
        await _started(docker)
        seen = _watch_rm(monkeypatch, docker, paths, record)

    # The real thing: closing the test client runs the application's own
    # cleanup, which is where the order lives.
    await client.close()

    assert seen and all(entry == ("rm", True, True) for entry in seen), (
        "the tree was still there and the signal was set at every removal"
    )
    assert record.drive.done(), "and the supervisor was waited for"
    assert not paths.root.exists()


async def test_shutdown_is_bounded_for_every_session_together(
    aiohttp_client, config, docker, monkeypatch
) -> None:
    """One budget for the loop, not one ladder per session.

    A stopping server is expected to be gone: waiting the full ladder
    once per session would make exit take longer than a service manager
    waits before it sends SIGKILL, which is a bound that buys nothing.
    """
    monkeypatch.setattr(sessions, "SHUTDOWN_RELEASE_SECONDS", 0.0)
    state, client = await _building(aiohttp_client, config, docker)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        paths = state.sessions.find(session_id).paths
        record = state.backend.record(session_id, "inv-1")
        await _started(docker)

        started = time.monotonic()
        await sessions.release_every_session(state)
        spent = time.monotonic() - started

        assert spent < 5.0, "a budget of nothing is a wait of nothing"
        assert state.sessions.pending_releases() == (session_id,)
        state.sessions.shutdown()
        assert not paths.root.exists(), "the trees go even for a session that did not release"

        await asyncio.wait_for(record.drive, timeout=10)


async def test_close_session_refuses_when_the_supervisor_outlives_the_ladder(
    aiohttp_client, config, docker, monkeypatch
) -> None:
    """The wait is bounded, and running out of it is an answer.

    The ladder ends in a rung that gives up, so a supervisor still there
    afterwards is not a slow build — it is a defect on this side. Two
    things then must not happen: the verb must not delete the session's
    files underneath the thread that is still reading them, and it must
    not answer ``result`` as though it had. And the refusal leaves the
    session in a state the **sweep** can finish, because the retry cannot
    depend on a client sending a second close.
    """
    from mcuhome.buildserver import backend
    from mcuhome.buildserver.app import ServerState, create_app

    waited = [0.0]
    monkeypatch.setattr(backend, "_ladder_seconds", lambda config: waited[0])
    docker.run_program = hanging_environment
    state = ServerState(config)
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        paths = state.sessions.require(session_id).paths
        record = state.backend.record(session_id, "inv-1")
        await _started(docker)

        refused = await call(ws, "close-session", {"session_id": session_id}, frame_id="x")
        assert refused["error"]["code"] == "internal_error"
        assert paths.root.exists(), "the tree stayed, which is the whole point of refusing"

        waited[0] = 30.0
        assert state.sessions.pending_releases() == (session_id,)
        assert await sessions.release_pending(state) == ()

    assert record.drive.done()
    assert state.sessions.pending_releases() == ()
    assert not paths.root.exists(), "and the sweep is what deleted it"


async def test_one_invocation_at_a_time_per_session(client, config, docker) -> None:
    """§3: steps of a session run strictly one after another.

    The environment cannot check it, so it is a backend duty.
    Pre-registry, like the context verbs' own guard: no registered code
    means "this session is already doing work", and inventing one is a
    protocol decision.
    """
    docker.run_program = hanging_environment
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        second = await call(ws, "build", {"session_id": session_id}, frame_id="b2")
        await call(ws, "close-session", {"session_id": session_id}, frame_id="x")

    assert second["type"] == "error", second
    assert second["error"]["code"] == "bad_request", second
    assert "one invocation at a time" in second["error"]["message"].lower()


# --------------------------------------------------------------------------
# verify, which this server answers itself
# --------------------------------------------------------------------------


async def test_verify_is_answered_without_starting_anything(client, config, docker) -> None:
    """Verifying a context is not an action, and cannot be one.

    The orchestrator creates the context, hashes it and delivers it; the
    environment is forbidden to modify it. There is nothing an
    environment could confirm that this side does not already know from
    its own bytes — so the verb is answered here, from the measurement
    made before every working invocation, and no container starts.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, context_id = await locked(ws, config)
        answer = await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        frames = await collect(ws, until="invocation.verdict")

    assert answer["payload"]["action"] == "verify"
    verdict = frames[-1]["payload"]
    assert verdict["status"] == "success"
    assert verdict["context"] == context_id
    assert verdict["artifacts"] == []
    assert not any(argv[1:2] == ["run"] for argv in docker.calls)


async def test_a_context_that_moved_fails_verify_without_poisoning_the_session(
    client, config, state
) -> None:
    """A mismatch is a failed invocation and not a dead session.

    Nothing was applied to any tree — a step of this profile builds in a
    container that is thrown away — so a client that fixes its context is
    fixing something this session never acted on.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"model/device-model.json": MODEL})
        paths = state.sessions.require(session_id).paths
        (paths.context / "model/device-model.json").write_bytes(b"{}")
        frame = await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        attached = await call(ws, "attach-session", {"session_id": session_id}, frame_id="a")

    assert frame["error"]["code"] == "context.integrity-mismatch"
    assert attached["type"] == "result", "and the session is still usable"


# --------------------------------------------------------------------------
# The SDK, and the image
# --------------------------------------------------------------------------


async def test_a_pin_no_source_holds_is_sdk_unavailable(client, config) -> None:
    """The pin is looked up in two tiers, and "not here" is a final answer.

    The operator's own directories first and MCUHome's package registry
    behind them — and the url in a context is a hint that is never
    fetched either way: a server that followed it would let a client
    point its fetcher wherever it liked.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        sha256 = write_sdk_package(config.sdk_sources[0], "9.9.9")
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, buildable_context(sha256))
        await call(ws, "lock-context", {"session_id": session_id}, frame_id="l")
        frame = await call(ws, "build", {"session_id": session_id}, frame_id="b")

    error = frame["error"]
    assert error["code"] == "sdk.unavailable"
    assert error["retryable"] is False
    # The client keeps what it can act on and no operator host path: the
    # searched directories are this machine's layout and stay off the
    # wire.
    assert "sources" not in error["details"]
    assert str(config.sdk_sources[0]) not in str(frame)


async def test_a_package_with_the_right_name_and_wrong_bytes_is_refused(client, config) -> None:
    """The name only makes a candidate findable; the hash makes it the package.

    A file named for the right version whose bytes hash to something else
    is either a corrupted mirror or a package somebody replaced, and both
    are answers an operator has to see rather than a fallback this server
    can make.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, buildable_context(sha256))
        await call(ws, "lock-context", {"session_id": session_id}, frame_id="l")
        (config.sdk_sources[0] / "mcuhome-sdk-2.4.0.tar.zst").write_bytes(b"not the package")
        frame = await call(ws, "build", {"session_id": session_id}, frame_id="b")

    assert frame["error"]["code"] == "sdk.unavailable"
    assert frame["error"]["details"]["sha256"] == sha256


async def test_the_sdk_is_unpacked_per_session_and_mounted_read_only(
    client, config, docker, state
) -> None:
    """§4: ``sdk`` is the orchestrator's to place, and the step may not write it.

    Per session rather than shared, because a session's directory is what
    goes away with the session — and read-only to the kernel, which is
    stronger than a promise the environment is asked to keep.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await built(ws, config)
        paths = state.sessions.require(session_id).paths

    assert (paths.sdk / "mcuhome/__init__.py").read_bytes() == b"# the SDK\n"
    assert f"{paths.sdk}:/mcuhome/sdk:ro" in _volumes(docker.step)


async def test_the_image_is_chosen_once_and_the_session_keeps_it(
    client, config, docker, state
) -> None:
    """One session, one build environment.

    ``send-context`` chooses the image and the session holds it; a
    registry that starts publishing a newer revision mid-session must not
    take over, because the artifacts would then come out of an image the
    session was never answered with.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"model/device-model.json": MODEL})
        asked = len(state.backend._images.asked) if state.backend._images else 0
        del asked
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")
        context = state.sessions.require(session_id).paths.context

    assert IMAGE_RUNNABLE in docker.step
    recorded = YAML(typ="safe", pure=True).load((context / "manifest.yaml").read_text())
    # The manifest records the packages, never the delivery: an image is
    # one delivery of a set, and two builds of one context on two hosts
    # may legitimately use different ones.
    assert recorded["build_environment"] == ENVIRONMENT.to_dict(url=False)


async def test_an_image_that_went_away_after_the_lock_is_a_typed_refusal(
    client, config, docker
) -> None:
    """The choice can be lost, and it is never silently swapped.

    An operator may remove an image while a session sits locked. Another
    image declaring the same packages would serve the same requirement —
    and substituting it is what must not happen without saying so, because
    the session was answered with these bytes.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        docker.present = set()
        frame = await call(ws, "build", {"session_id": session_id}, frame_id="b")

    error = frame["error"]
    assert error["code"] == "version.builder-unavailable"
    assert error["retryable"] is False
    assert error["details"]["digest"] == IMAGE_DIGEST
    assert not any(argv[1:2] == ["run"] for argv in docker.calls)


async def test_an_image_whose_generation_this_server_does_not_speak_is_refused(
    client, config, registry
) -> None:
    """§12: the side that notices refuses.

    "The orchestrator does not start an environment whose generation it
    does not implement" — the label is read before anything is started,
    which is exactly why it is a label.
    """
    registry.labels_ = environment_labels(generation="4")
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
        frame = await send_archive(ws, "send-context", session_id, buildable_context(sha256))

    assert frame["error"]["code"] == "version.builder-unavailable"
    assert "generation" in frame["error"]["message"]


async def test_an_environment_that_does_not_accept_this_context_is_refused(
    client, config, registry
) -> None:
    """§9.1: the constraint is checked before every step, on this side.

    "When the check fails you are not started at all and never see the
    context" — so an environment that accepts only contexts from another
    tool is refused at the moment the context arrives, not minutes into a
    build.
    """
    registry.labels_ = environment_labels(constraint="custom-tool:~=1.0")
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
        context = buildable_context(sha256, **{"build-context.json": BUILD_CONTEXT_BYTES})
        frame = await send_archive(ws, "send-context", session_id, context)

    assert frame["error"]["code"] == "version.builder-unavailable"
    assert "does not accept" in frame["error"]["message"]


async def test_capabilities_lists_the_environments_this_host_has(client) -> None:
    """Pre-session and cheap: what is here, with what it declares.

    Nothing starts a container — a client asking what this server has is
    not yet asking any image to prove it — and the allowlist beside it is
    the half a client can act on before it uploads anything.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "capabilities")

    containers = frame["payload"]["containers"]
    assert len(containers) == 1
    assert containers[0]["digest"] == IMAGE_DIGEST
    assert containers[0]["labels"]["org.mcuhome.build-environment.spec-generation"] == "3"
    assert frame["payload"]["environments"]["allowed"] == [IMAGE]


async def test_capabilities_answers_an_empty_inventory_when_docker_is_down(client, docker) -> None:
    """The question is which environments this host has, and "none" is a fact.

    The refusal for a missing runtime belongs to the verb that actually
    needs a container, where it can be acted on.
    """
    docker.version_status = None
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "capabilities")

    assert frame["type"] == "result"
    assert frame["payload"]["containers"] == []


async def test_a_runtime_that_dies_between_send_context_and_build_is_typed(
    client, config, docker
) -> None:
    """The pre-start refusal at the moment a step would start.

    A daemon that went away in between is ``builder.runtime-unavailable``,
    retryable, with the session untouched and usable afterwards.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        docker.version_status = 1
        frame = await call(ws, "build", {"session_id": session_id}, frame_id="b")
        docker.version_status = 0
        again = await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")

    assert frame["error"]["code"] == "builder.runtime-unavailable"
    assert frame["error"]["retryable"] is True
    assert again["type"] == "result", "the session survived the refusal"


# --------------------------------------------------------------------------
# The context, re-measured
# --------------------------------------------------------------------------


async def test_the_locked_context_is_re_measured_before_every_invocation(
    client, config, state
) -> None:
    """Contexts are small, so they are checked rather than trusted.

    What the re-check buys is the one thing the freeze cannot: the
    manifest and the files are compared *now*, so an invocation is never
    attributed to an identity that moved after it was answered.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"model/device-model.json": MODEL})
        paths = state.sessions.require(session_id).paths
        (paths.context / "model/device-model.json").write_bytes(b"{}")
        frame = await call(ws, "build", {"session_id": session_id}, frame_id="b")

    error = frame["error"]
    assert error["code"] == "context.integrity-mismatch"
    assert error["details"]["paths"] == ["model/device-model.json"]


async def test_a_rewritten_pin_is_caught_by_the_same_re_measurement(client, config, state) -> None:
    """A manifest that changed after it was written is what the check catches.

    A self-consistently forged manifest verifies clean, so the comparison
    that matters is against the pins the session was admitted on — which
    this server holds and the file cannot move.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        manifest = state.sessions.require(session_id).paths.context / "manifest.yaml"
        manifest.write_text(
            manifest.read_text().replace("nrf7002dk/nrf5340/cpuapp", "nrf5340dk/nrf5340/cpuapp")
        )
        frame = await call(ws, "build", {"session_id": session_id}, frame_id="b")

    assert frame["error"]["code"] == "context.integrity-mismatch"
    assert "target.board" in frame["error"]["details"]["paths"]


async def test_a_rewritten_context_format_version_is_caught_too(client, config, state) -> None:
    """The manifest's own format version is read back and compared.

    It is the last value in the document that nothing else measures: not
    an input of the identity, and not in the integrity list, because the
    manifest carries that list and cannot be in it.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        manifest = state.sessions.require(session_id).paths.context / "manifest.yaml"
        assert "context: 4" in manifest.read_text()
        manifest.write_text(manifest.read_text().replace("context: 4", "context: 2"))
        frame = await call(ws, "build", {"session_id": session_id}, frame_id="b")

    assert frame["error"]["code"] == "context.integrity-mismatch"
    assert "context" in frame["error"]["details"]["paths"]


async def test_a_container_image_this_server_cannot_read_is_refused_at_the_frame(
    client, config
) -> None:
    """A pin that is not a reference never becomes a search.

    It is answered at the layer that did not understand it: the typed
    codes describe what a *session* did, and a value that is not a
    reference at all has not got that far. A client that sent one gets
    the parser's own sentence back, which is what says which character
    is wrong.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
        frame = await send_archive(
            ws,
            "send-context",
            session_id,
            buildable_context(sha256),
            container_image=":not a tag",
        )

    assert frame["type"] == "error"
    assert frame["error"]["code"] == "bad_request"
    assert "container_image" in frame["error"]["message"]


async def test_a_fetch_that_fails_is_retryable_and_says_so(client, config, docker) -> None:
    """No network, a registry wanting a login, a digest nothing answers to.

    All of them come back, which is what ``retryable`` promises — and the
    reason itself was already on the client's screen, because the pull's
    own output was relayed while it happened.
    """
    docker.present = set()  # nothing on this host, and nothing pullable
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
        frame = await send_archive(ws, "send-context", session_id, buildable_context(sha256))

    error = frame["error"]
    assert error["code"] == "version.builder-unfetchable"
    assert error["retryable"] is True
    assert error["details"]["digest"] == IMAGE_DIGEST
    assert docker.pulls == [IMAGE_RUNNABLE]


async def test_the_result_document_is_not_reported_as_a_leftover(
    client, config, docker, caplog
) -> None:
    """A step's result document lives in ``out`` and is not an artifact.

    §6.2 puts it there and this side reads it; a server that counted it
    among the files a step "forgot to declare" would say something is
    wrong after every successful build. What the count is for is the
    difference between a build that produced nothing and one that
    produced something it did not declare.
    """

    def leaves_a_file(request, out, on_line):
        (out / "zephyr.elf").write_bytes(b"diagnostic material\n")
        return conforming_environment(request, out, on_line)

    docker.run_program = leaves_a_file
    with caplog.at_level("INFO"):
        async with client.ws_connect("/ws", headers=auth()) as ws:
            await built(ws, config)

    noted = [
        record.getMessage() for record in caplog.records if "undeclared" in record.getMessage()
    ]
    assert noted == ["invocation inv-1: 1 undeclared file(s) left in out"], noted


async def test_a_package_this_host_cannot_resolve_is_a_package_refusal(
    client, config, docker
) -> None:
    """Which packages, and which image, are two questions with two answers.

    A context pins the tools package by its family and an index says
    which concrete package this host needs. An index that does not carry
    that version answers nothing about any image — a client told "no
    image declares this set" would go looking through repositories for a
    set that was never resolved in the first place.
    """
    write_sdk_package(config.sdk_sources[0], "2.4.0")
    index = config.sdk_sources[0] / "index.json"
    index.write_text(json.dumps({"packages": {}}), encoding="utf-8")

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, buildable_context("a" * 64))

    assert frame["error"]["code"] == "sdk.unavailable", frame
    assert "package" in frame["error"]["message"]


async def test_a_package_index_naming_other_bytes_is_refused_as_a_package(
    client, config, docker
) -> None:
    """Same version, different hash — the one thing that must never be shopped for.

    A source that publishes the pinned version under other bytes is not
    "this source does not have it": it is an answer an operator has to
    see, and it is about a package rather than about an image.
    """
    write_sdk_package(config.sdk_sources[0], "2.4.0")
    index = config.sdk_sources[0] / "index.json"
    document = json.loads(index.read_text(encoding="utf-8"))
    document["packages"][TOOLS_PACKAGE][ENVIRONMENT_VERSION]["sha256"] = "1" * 64
    index.write_text(json.dumps(document), encoding="utf-8")

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, buildable_context("a" * 64))

    assert frame["error"]["code"] == "sdk.unavailable", frame


async def test_no_image_declares_the_set_names_every_candidate_and_its_reason(
    client, config, registry
) -> None:
    """The refusal comes after every candidate was tried, and says why for each.

    An image built from the same package *versions* under other bytes and
    an image that was never published read identically in a one-line
    message, and the difference is the whole point: one is a different
    environment that must never be substituted, the other is nothing at
    all. So the refusal carries what was wanted, which repositories this
    server may look in, and the workbench's own account of each
    candidate.
    """
    registry.tags_ = (IMAGE_TAG, "2.4.0-r2")
    registry.labels_ = environment_labels(workspace=f"{ENVIRONMENT_VERSION}@sha256:{'1' * 64}")

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
        frame = await send_archive(ws, "send-context", session_id, buildable_context(sha256))

    error = frame["error"]
    assert error["code"] == "version.builder-unsatisfiable"
    assert error["retryable"] is False
    assert error["details"]["required"] == ENVIRONMENT.described()
    assert error["details"]["allowed"] == [IMAGE]
    problem = error["details"]["problem"]
    for tag in registry.tags_:
        assert f"{IMAGE}:{tag}" in problem, problem
    assert "1" * 64 in problem, "the near miss is named by the bytes that differ"


async def test_the_allowlist_is_walked_in_order_and_the_first_match_wins(
    aiohttp_client, config, docker, registry
) -> None:
    """Two repositories, and the order is the operator's statement.

    The list is a search list as well as a boundary: an operator who puts
    their own mirror first means their own mirror, and a resolver that
    asked the second one anyway would be deciding where a build's bytes
    come from.
    """
    from mcuhome.buildserver.app import ServerState, create_app

    mirror = "registry.example.test/mcuhome/build-environment"
    registry.repositories = {mirror: IMAGE_LABELS, IMAGE: IMAGE_LABELS}
    state = ServerState(replace(config, allowed_environments=(mirror, IMAGE)))
    client = await aiohttp_client(create_app(state))
    # The bytes the first repository answers with are on this host, so
    # nothing is fetched and the choice is the only thing under test.
    docker.images[f"{mirror}@{IMAGE_DIGEST}"] = {
        "Id": "sha256:" + "c" * 64,
        "RepoTags": [],
        "RepoDigests": [f"{mirror}@{IMAGE_DIGEST}"],
        "Config": {"Labels": dict(IMAGE_LABELS)},
    }

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        sha256 = write_sdk_package(state.config.sdk_sources[0], "2.4.0")
        frame = await send_archive(ws, "send-context", session_id, buildable_context(sha256))

    assert frame["type"] == "result", frame
    assert frame["payload"]["container"]["build_environment"].startswith(mirror)
    assert all(not asked.startswith(IMAGE) for asked in registry.asked), (
        "the second repository was asked although the first one answered"
    )


async def test_a_context_without_a_generator_declaration_is_refused(client, config) -> None:
    """A context that says nothing about who wrote it is not a build context.

    The build environment specification makes ``build-context.json`` and
    a readable ``generator`` in it part of what a build context *is*, and
    has the orchestrator refuse one that carries neither before the
    environment is started. It has to be refused rather than passed on,
    because that chain is what the environment's own "which contexts do I
    accept" declaration is checked against: read as empty, the check
    would silently pass for a context no environment ever agreed to.
    """
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(
            ws,
            "send-context",
            session_id,
            make_archive({"context.yaml": context_yaml(sdk_sha256=sha256)}),
        )

    error = frame["error"]
    assert error["code"] == "context.missing"
    assert error["retryable"] is False
    assert "build-context.json" in error["message"]


async def test_an_unreadable_generator_declaration_is_refused_too(client, config) -> None:
    """Present and unreadable is the same answer as absent.

    Half a declaration is not a weaker statement than none: either way
    there is nothing to hold an environment's constraint against, and a
    reader that recovered from it would be inventing the one value the
    check is made of.
    """
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(
            ws,
            "send-context",
            session_id,
            make_archive(
                {
                    "build-context.json": b"{not json",
                    "context.yaml": context_yaml(sdk_sha256=sha256),
                }
            ),
        )

    assert frame["error"]["code"] == "context.missing"


async def test_a_build_asked_for_incrementally_is_answered_as_the_clean_one_it_is(
    client, config
) -> None:
    """The verb answers what will happen, not what was asked for.

    Every step runs in a fresh container, so there is nothing for an
    incremental build to be incremental against. Answering a clean build
    is never wrong — it is what was asked for plus time — but leaving a
    client to assume its word was honoured would be, so the mode this
    server will use is in the acknowledgement.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        answer = await call(
            ws, "build", {"session_id": session_id, "mode": "incremental"}, frame_id="b"
        )
        await collect(ws, until="invocation.verdict")

    assert answer["payload"]["mode"] == "clean"


async def test_a_verify_answers_its_verb_before_it_reports_the_verdict(client, config) -> None:
    """The frame that names an invocation comes before the frames about it.

    A verify is over before its handler returns — this server answers it
    from its own measurement — so the two events it produces would
    otherwise be queued in front of the result frame that first tells the
    client what the invocation is called. The frames of one connection go
    out in the order they were queued, so the fix is to queue them after,
    and the order is worth pinning because it is the one an ordinary
    client reads without thinking about it.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await ws.send_json({"id": "v", "type": "verify", "payload": {"session_id": session_id}})
        frames = await collect(ws, until="invocation.verdict")

    kinds = [
        frame.get("event") if frame.get("type") == "event" else frame.get("type")
        for frame in frames
    ]
    assert kinds == ["result", "invocation.started", "invocation.verdict"], frames
