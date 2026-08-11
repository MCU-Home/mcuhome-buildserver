# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The container backend, over the wire: argv, documents, events, artifacts.

Every test here drives the real verbs over a real socket against a
docker that is stubbed at the seam (:class:`~tests.conftest.FakeDocker`).
**No container is ever started and no build is ever run**, which is a
rule of this suite rather than a convenience: the machine that runs it
has one build's worth of RAM, and a suite that could start a real
container would eventually start one on somebody's laptop.

What is asserted is therefore exactly what a backend is: the argv it
composes, the request documents it writes, what it makes of the result
documents that come back, and what reaches the client while it happens.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from mcuhome_buildserver import sessions
from tests.conftest import (
    BUILD_REPORT,
    IMAGE,
    IMAGE_DIGEST,
    IMAGE_LABELS,
    IMAGE_REFERENCE,
    ZEPHYR_LINE,
    FakeProcess,
    auth,
    base_context,
    buildable_context,
    call,
    collect,
    device_model,
    emit,
    manifest_id,
    send_archive,
    write_result,
    write_sdk_package,
)

MODEL = b'{"device": {"board": "nrf7002dk/nrf5340/cpuapp"}}'
PATCH = b"--- a/x\n+++ b/x\n"


@pytest.fixture
def config(config):
    """The suite's config, with the four contract layers allowed.

    Overridden for this module alone. The config **is** the patch policy
    and unlisted layers are denied by default, which is right everywhere
    else; here it would mean no test could ever reach a patched tree,
    and the writable views of §6.2 are half of what this module is about.
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


# --------------------------------------------------------------------------
# The argv: what a backend actually says to a container runtime
# --------------------------------------------------------------------------


async def test_the_session_container_is_started_with_the_contracts_two_flags(
    client, config, docker
) -> None:
    """``--network=none`` and ``--init``, plus this backend's own policy.

    The first is contract §9.1 made checkable rather than asserted:
    "everything a build needs is mounted or in the image" is not a
    property one can read off a build log, and taking the network away
    turns the claim into something the build either satisfies or does
    not. The second is arithmetic: a build spawns hundreds of
    short-lived children and PID 1 has to reap them.

    The rest is backend policy, which §11 leaves free — and it is
    asserted anyway, because the composed command is the interface
    between the contract and the runtime.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"model/device-model.json": MODEL})
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")

    started = next(
        argv for argv in docker.calls if argv[:2] == ["docker", "run"] and "--detach" in argv
    )
    assert "--network=none" in started
    assert "--init" in started
    assert "--user" in started
    # The image is named by digest, never by tag: a tag carries no
    # compatibility meaning and no identity (ADR 0018 §7).
    assert IMAGE_REFERENCE in started
    # The container's main process is the backend's to choose, and the
    # image must not depend on its own ENTRYPOINT or CMD (§2.2).
    assert started[-3:] == ["/bin/sh", "-c", "while :; do sleep 86400; done"]


def _volumes(argv: list[str]) -> list[str]:
    return [item for index, item in enumerate(argv) if argv[index - 1] == "--volume"]


async def test_the_session_tree_is_mounted_piece_by_piece_and_never_wholesale(
    client, config, docker, state
) -> None:
    """The whole ``-v`` set, because what is *absent* from it is the point.

    §9.1 write-protects ``context`` and every non-``writable`` tree
    "with the strongest means its profile has", and §4.1 makes
    ``writable`` a thing the backend **asserts** and the program may
    never probe — so the assertion has to be true of the mount set as a
    whole rather than of one mount read in isolation. One bind mount of
    the session root satisfied neither: the SDK is unpacked into
    ``<root>/sdk`` and mounted read-only at the path ``describe`` names,
    so a root mount exposed the same host directory writable under its
    other name, and ``trees.sdk.writable: false`` was a claim this
    server was making falsely.

    So the container sees exactly the paths the request document names,
    each at its own host path, and nothing else of the session tree —
    not ``staging``, not the upload spool, and above all not
    ``downloads``, where ``get-artifact`` builds the archive it is about
    to stream to a client.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")
        paths = state.sessions.require(session_id).paths

    started = next(argv for argv in docker.calls if "--detach" in argv)
    assert sorted(_volumes(started)) == sorted(
        [
            f"{paths.context}:{paths.context}:ro",
            f"{paths.work}:{paths.work}",
            f"{paths.invocations}:{paths.invocations}",
            f"{paths.sdk}:{paths.sdk}:ro",
        ]
    )
    root = paths.root
    assert f"{root}:{root}" not in _volumes(started)
    assert not any(str(paths.downloads) in volume for volume in _volumes(started))
    assert not any(str(paths.staging) in volume for volume in _volumes(started))


async def test_a_read_only_tree_has_no_writable_second_name(client, config, docker, state) -> None:
    """The mutation the old layout was: ``trees.sdk.writable`` is false,
    and no mount makes that directory writable under any other path.

    This is the assertion that survives a refactor of the layout, because
    it is stated about the two things that have to agree — what the
    request document asserts about a tree, and what the mount set does
    with the host directory behind it.
    """
    docker.program["trees"]["sdk"] = {"path": "/opt/mcuhome-sdk"}
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")
        paths = state.sessions.require(session_id).paths

    document = docker.invocations[-1].request
    assert document["trees"]["sdk"] == {"path": "/opt/mcuhome-sdk", "writable": False}
    started = next(argv for argv in docker.calls if "--detach" in argv)
    assert f"{paths.sdk}:/opt/mcuhome-sdk:ro" in _volumes(started)
    writable = [volume for volume in _volumes(started) if not volume.endswith(":ro")]
    assert not any(
        Path(volume.split(":")[0]) in (paths.sdk, *paths.sdk.parents) for volume in writable
    ), writable


async def test_the_session_container_is_started_with_this_servers_resource_limits(
    client, config, docker
) -> None:
    """The composed ``run``, with the numbers the config carries.

    §1.2's ``container`` row promises "per-session resource limits" and
    §9.1 makes them the backend's to enforce, and
    ``abi.request_document`` leans on exactly that when it omits
    ``limits.memory_bytes``: "enforcement is the backend's … this server
    enforces memory through the container runtime rather than by
    asking". That sentence was true of nothing until these flags
    existed.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")

    started = next(argv for argv in docker.calls if "--detach" in argv)
    assert started[started.index("--memory") + 1] == config.container_memory == "8g"
    assert started[started.index("--pids-limit") + 1] == str(config.container_pids) == "4096"
    assert "--cpus" not in started
    # And the document still says nothing about memory: the runtime
    # enforces it, so the program is not asked to.
    assert "memory_bytes" not in docker.invocations[-1].request["limits"]


async def test_the_describe_probe_is_mounted_and_has_no_network(client, config, docker) -> None:
    """The other ``docker run`` this server composes, asserted as one.

    ``describe`` is an invocation, so §9.1's "no network during an
    invocation" is about it too — and the probe directory holds the
    request document the program reads and the result document it
    writes, neither of which exists inside the container without a
    mount. The fake refuses a request path no ``--volume`` reaches, so
    the mount is exercised here rather than assumed.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await locked(ws, config)

    described = next(argv for argv in docker.calls if argv[-2:-1] == ["describe"])
    assert described[:5] == ["docker", "run", "--rm", "--init", "--network=none"]
    assert "--user" in described
    request = Path(described[-1])
    volumes = _volumes(described)
    assert volumes == [f"{request.parent}:{request.parent}"]
    assert described[-4:-1] == [IMAGE_REFERENCE, "/mcuhome/run", "describe"]


async def test_two_describes_of_one_image_do_not_share_a_probe_directory(
    client, config, docker, state
) -> None:
    """§5.1 step 1's per-invocation directory, applied to ``describe``.

    The fixed path it replaced is named in the contract — "it removes
    the data race the fixed path ``/ctx/.mcuhome/command.json`` had,
    where two concurrent ``docker exec`` invocations overwrote each
    other's document" — and a probe directory keyed by the image id is
    that path again: nothing serializes two callers, and the second
    caller's ``result.unlink`` deletes the first caller's answer, which
    reads back as "no result document was written" and disqualifies a
    good image.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await locked(ws, config)
        # The memo is what normally makes the second describe never
        # happen; dropping it is how a *concurrent* pair is reproduced
        # without racing the test itself.
        state.backend._images.clear()
        sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
        second = await open_session(ws)
        await send_archive(ws, "send-context", second, buildable_context(sha256))

    described = [argv for argv in docker.calls if argv[-2:-1] == ["describe"]]
    assert len(described) == 2
    assert Path(described[0][-1]).parent != Path(described[1][-1]).parent


async def test_the_invocation_is_two_positional_operands_and_never_a_flag(
    client, config, docker
) -> None:
    """§5.1, frozen: ``/mcuhome/run <action> <absolute request path>``.

    "Exactly two positional operands, both mandatory, **never a flag**."
    The argv is frozen and never grows, because a new operand breaks
    every third-party container that does not know it while an unknown
    JSON field costs an older program nothing.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")

    executed = next(argv for argv in docker.calls if argv[1] == "exec")
    program = executed.index("/mcuhome/run")
    assert executed[program:] == ["/mcuhome/run", "verify", executed[-1]]
    assert Path(executed[-1]).is_absolute()
    assert Path(executed[-1]).name == "request.json"
    # And the frame in front of the program, which the assertion above
    # says nothing about: the exec is what writes into `out` and `work`,
    # so it is the one that must not run as root.
    assert executed[:3] == ["docker", "exec", "--user"]
    assert executed[3] == f"{os.getuid()}:{os.getgid()}"


# --------------------------------------------------------------------------
# The request document
# --------------------------------------------------------------------------


async def test_the_request_document_carries_every_mandatory_field(client, config, docker) -> None:
    """§5.2's list for a working action, and the preamble in front of it.

    "Mandatory in v1: ``request`` and ``result`` for every action.
    Additionally for every working action: ``session``, ``out``,
    ``work``, ``tmp``, ``context``, ``trees.sdk``, ``limits.jobs``."
    Every path value is absolute, and the document lives outside the
    context.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    document = docker.invocations[-1].request
    assert document["request"] == 1
    for field in ("result", "out", "work", "tmp", "context", "events", "cancel"):
        assert Path(document[field]).is_absolute(), field
    # `session` is an **opaque token** and the one field that is not a
    # path: "a program MUST NOT compose any path from it".
    assert document["session"] == session_id
    assert document["trees"]["sdk"]["path"]
    assert document["limits"]["jobs"] >= 1
    # Outside the context, so that the context can be a kernel-enforced
    # read-only mount (§5.1 step 1).
    assert not str(Path(document["result"])).startswith(document["context"] + "/")


async def test_the_request_document_names_no_invocation_id(client, config, docker) -> None:
    """§5.2: "There is **no invocation ID** in the request document."

    The backend addresses an invocation by the ``out``, ``result`` and
    ``events`` paths it chose for it, so a token the program could only
    echo back would be one more field for a third party to get right for
    nothing. This server assigns one anyway — ``get-artifact`` and
    ``cancel`` address it — and never tells the program.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        answer = await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    assert answer["payload"]["invocation_id"] == "inv-1"
    assert "invocation" not in docker.invocations[-1].request
    assert "inv-1" not in json.dumps(docker.invocations[-1].request["trees"])


async def test_limits_are_authoritative_and_memory_is_not_promised(client, config, docker) -> None:
    """``limits.jobs`` is resolved host-side; ``memory_bytes`` is absent.

    The job count "is not a hint … the container sees the host CPU count
    but not the RAM budget", so it is written and it is the operator's
    number. ``memory_bytes`` is advisory and enforcement is the
    backend's, so a number written into the document that nothing behind
    it enforces would be a promise to the program that no one keeps.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    limits = docker.invocations[-1].request["limits"]
    assert limits["jobs"] == config.build_jobs == 2
    assert limits["deadline_seconds"] == 5400
    assert limits["cancel_grace_seconds"] == 60
    assert "memory_bytes" not in limits


async def test_build_states_its_mode_and_demands_it_be_honoured(client, config, docker) -> None:
    """``/params/mode`` in ``required``, with the value it sends (§5.2).

    "The *value* counts, not only the name": a program that knows the
    pointer but not the value MUST refuse rather than accept the job and
    quietly deliver something else. So the mode is written explicitly
    even though its default is defined by absence — the value has to be
    there to be honoured.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id, "mode": "incremental"}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    document = docker.invocations[-1].request
    assert document["params"] == {"mode": "incremental"}
    assert "/params/mode" in document["required"]


async def test_verify_gets_the_trees_and_demands_nothing(client, config, docker) -> None:
    """§7.3: the writable views are still supplied, and never demanded.

    "The backend still supplies the writable views §4.1 requires for
    every patched layer — ``verify`` simply does not use them, and a
    view it never writes to is indistinguishable from one it was not
    given." Demanding one through ``required`` would ask a conforming
    program to refuse for not using something it is forbidden to use.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"patches/zephyr/0001-fix.patch": PATCH})
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")

    document = docker.invocations[-1].request
    assert document["trees"]["zephyr"] == {"path": "/opt/zephyr", "writable": True}
    assert "required" not in document
    assert "params" not in document


@pytest.mark.parametrize("layer", ["zephyr", "chip", "mcuboot"])
async def test_a_patched_in_image_tree_is_writable_where_describe_put_it(
    client, config, docker, layer
) -> None:
    """E47: the container's own copy-on-write layer **is** the view.

    "In the ``container`` profile the container's own copy-on-write
    layer is that view, and it costs nothing to provide": the image's
    trees are writable inside the container by construction, one session
    is one container, and the container is discarded at
    ``close-session``. So the backend asserts ``writable: true`` for an
    in-image tree at the path ``describe`` reported, and the assertion
    is truthful because the layer makes it so.

    The consequence asserted here is the negative one: **no mount is
    involved at all.** No overlay, no copy, no ``docker cp`` — the tree
    is already in the image.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{f"patches/{layer}/0001-fix.patch": PATCH})
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    document = docker.invocations[-1].request
    declared = document["trees"][layer]
    assert declared["writable"] is True
    assert declared["path"].startswith("/opt/")
    assert f"/trees/{layer}" in document["required"]
    started = next(argv for argv in docker.calls if "--detach" in argv)
    assert not any(declared["path"] in argument for argument in started)
    assert not any(argv[1] == "cp" for argv in docker.calls)


async def test_an_unpatched_tree_gets_no_entry_at_all(client, config, docker) -> None:
    """§4.1: "the program then uses its own".

    A ``trees`` entry is what a backend supplies, and supplying one for
    a tree the image already carries and nothing patches would be the
    backend naming a path it has no reason to have an opinion about.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    assert set(docker.invocations[-1].request["trees"]) == {"sdk"}


async def test_a_patched_sdk_is_handed_over_writable(client, config, docker) -> None:
    """The SDK is the one tree that is a mount, so its mode is a mount mode.

    Unpatched it is read-only; patched it is the writable view §6.2
    asks for, and it needs neither an overlay nor a copy to be one: it
    was unpacked into this session's own directory and dies with the
    session.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"patches/sdk/0001-fix.patch": PATCH})
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    assert docker.invocations[-1].request["trees"]["sdk"]["writable"] is True
    started = next(argv for argv in docker.calls if "--detach" in argv)
    assert not any(argument.endswith("/sdk:ro") for argument in started)


# --------------------------------------------------------------------------
# The answer, the events and the log
# --------------------------------------------------------------------------


async def test_a_working_verb_answers_the_invocation_id_immediately(client, config) -> None:
    """E46: ``build`` and ``verify`` answer ``{invocation_id}`` at once.

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
        }
        frames = await collect(ws, until="invocation.verdict")

    finished = frames[-1]["payload"]
    assert finished["status"] == "success"
    assert finished["error"] is None
    assert [entry["path"] for entry in finished["artifacts"]] == [
        "firmware.hex",
        "firmware.bin",
        "build-report.json",
    ]


async def test_the_finished_event_attributes_to_the_servers_own_context_id(client, config) -> None:
    """§9.3: "Attribution always uses the context ID the backend computed
    itself; ``result.context`` exists only to be compared against it."
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, context_id = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        frames = await collect(ws, until="invocation.verdict")

    assert frames[-1]["payload"]["context"] == context_id


async def test_program_events_are_relayed_verbatim_with_the_servers_addressing(
    client, config, docker
) -> None:
    """§8: fields intact, never rewritten, never dropped — unknown names too.

    "A backend passes an event whose name it does not know through to
    its client verbatim, with its fields intact, and never drops it,
    never rewrites it and never treats it as an error." That is what
    lets a third-party program report its own phases under ``x-`` names
    through a server that has never heard of them.
    """

    def program(action, request, on_line):
        emit(request, "invocation.started", 1, action=action)
        emit(request, "x-acme.flashing", 2, chip="nrf5340", progress=0.5)
        write_result(
            request,
            {
                "result": 1,
                "status": "success",
                "action": action,
                "session": request["session"],
                "reason": None,
                "error": None,
                "context": manifest_id(request),
            },
        )
        emit(request, "invocation.finished", 3, status="success")
        return FakeProcess(0)

    docker.run_program = program
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        frames = await collect(ws, until="invocation.verdict")

    unknown = next(frame for frame in frames if frame.get("event") == "x-acme.flashing")
    assert unknown["payload"]["chip"] == "nrf5340"
    assert unknown["payload"]["progress"] == 0.5
    assert unknown["payload"]["seq"] == 2
    assert unknown["payload"]["invocation_id"] == "inv-1"
    assert unknown["payload"]["session_id"] == session_id


async def test_the_raw_log_is_its_own_frame_type_with_its_own_counter(
    client, config, docker
) -> None:
    """E46: the log is a separate kind, and it counts its own lines.

    Contract §8 makes the two different things: events are a typed,
    registered vocabulary a consumer matches on, while stdout and stderr
    together are "one raw, opaque log stream" consumers "MUST NOT parse
    for machine decisions". The counter is what makes the transport's
    drop-the-oldest policy safe for it — a client that sees the numbers
    jump knows it lost lines.
    """

    def program(action, request, on_line):
        on_line("-- west build")
        on_line("-- ninja: no work to do")
        write_result(
            request,
            {
                "result": 1,
                "status": "success",
                "action": action,
                "session": request["session"],
                "reason": None,
                "error": None,
                "context": manifest_id(request),
            },
        )
        emit(request, "invocation.finished", 1, status="success")
        return FakeProcess(0)

    docker.run_program = program
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        frames = await collect(ws, until="invocation.verdict")

    logs = [frame for frame in frames if frame.get("type") == "log"]
    assert [entry["payload"]["seq"] for entry in logs] == [1, 2]
    assert logs[0]["payload"]["line"] == "-- west build"
    assert logs[0]["payload"]["invocation_id"] == "inv-1"


async def test_an_over_long_event_line_is_discarded_and_not_an_abort(
    client, config, docker
) -> None:
    """§8: over 8192 bytes is "discarded and counted, never an abort".

    A program that writes rubbish into its own event stream has not
    failed its build, and a backend that stopped on one would turn a
    cosmetic defect into a lost invocation.
    """

    def program(action, request, on_line):
        Path(request["events"]).write_text(
            json.dumps({"event": "x-huge", "seq": 1, "pad": "z" * 9000}) + "\n"
        )
        emit(request, "invocation.finished", 2, status="success")
        write_result(
            request,
            {
                "result": 1,
                "status": "success",
                "action": action,
                "session": request["session"],
                "reason": None,
                "error": None,
                "context": manifest_id(request),
            },
        )
        return FakeProcess(0)

    docker.run_program = program
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        frames = await collect(ws, until="invocation.verdict")

    assert not any(frame.get("event") == "x-huge" for frame in frames)
    assert frames[-1]["payload"]["status"] == "success"


# --------------------------------------------------------------------------
# What the result document is worth
# --------------------------------------------------------------------------


async def test_no_result_document_is_builder_crashed_and_retryable(client, config, docker) -> None:
    """§9.1: "an ``out`` directory without a result document at ``result``
    is a failed invocation by definition" — and it is the retryable one.

    "An infrastructure failure, not a verdict on the context": a limit
    that aborted the program produces exactly this, and the same
    invocation may well succeed on a retry.
    """
    docker.run_program = lambda action, request, on_line: FakeProcess(137)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")

    payload = frames[-1]["payload"]
    assert payload["status"] == "failure"
    assert payload["error"]["code"] == "builder.crashed"
    assert payload["error"]["retryable"] is True
    assert payload["artifacts"] == []


async def test_a_declared_artifact_that_does_not_re_hash_is_not_served(
    client, config, docker
) -> None:
    """§9.3: "re-hash every artifact from the bytes on disk".

    Declared values are advisory. An artifact whose bytes disagree with
    its declaration fails §5.3's sixth condition, so the whole
    invocation is a failure — a build that declared four artifacts and
    produced three is not a build that delivers three.
    """

    def program(action, request, on_line):
        (Path(request["out"]) / "firmware.hex").write_bytes(b"actual")
        write_result(
            request,
            {
                "result": 1,
                "status": "success",
                "action": "build",
                "session": request["session"],
                "reason": None,
                "error": None,
                "context": manifest_id(request),
                "layers": {},
                "artifacts": [
                    {
                        "root": "out",
                        "path": "firmware.hex",
                        "role": "firmware",
                        "hashes": {"sha256": hashlib.sha256(b"declared").hexdigest()},
                    }
                ],
            },
        )
        emit(request, "invocation.finished", 1, status="success")
        return FakeProcess(0)

    docker.run_program = program
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")

    payload = frames[-1]["payload"]
    assert payload["status"] == "failure"
    assert payload["artifacts"] == []


async def test_an_artifact_outside_out_is_skipped_rather_than_resolved(
    client, config, docker
) -> None:
    """§9.3: normalize, contain strictly, and skip an unknown ``root``.

    Both halves in one program: a path that climbs out of ``out`` and an
    entry whose ``root`` this version does not know. "A consumer that
    sees a ``root`` it does not know MUST skip that artifact and MUST
    NOT resolve it against ``out``."
    """

    def program(action, request, on_line):
        write_result(
            request,
            {
                "result": 1,
                "status": "success",
                "action": "build",
                "session": request["session"],
                "reason": None,
                "error": None,
                "context": manifest_id(request),
                "layers": {},
                "artifacts": [
                    {
                        "root": "out",
                        "path": "../../escape",
                        "role": "firmware",
                        "hashes": {"sha256": "0" * 64},
                    },
                    {
                        "root": "work",
                        "path": "elsewhere.bin",
                        "role": "firmware",
                        "hashes": {"sha256": "0" * 64},
                    },
                ],
            },
        )
        emit(request, "invocation.finished", 1, status="success")
        return FakeProcess(0)

    docker.run_program = program
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")

    payload = frames[-1]["payload"]
    assert payload["artifacts"] == []
    # A successful build that declares nothing servable has produced
    # nothing the backend may serve, and an absent list is an empty
    # delivery rather than a permissive one.
    assert payload["status"] == "failure"


async def test_exit_zero_with_a_failing_document_is_a_contract_violation(
    client, config, docker
) -> None:
    """§5.3: the pessimistic reading wins **and** a violation is raised.

    The violation is carried to the client rather than only logged,
    because it is a statement about the *image* that the operator of the
    client is often the one who can act on — it names a container that
    contradicts itself.
    """

    def program(action, request, on_line):
        write_result(
            request,
            {
                "result": 1,
                "status": "failure",
                "action": action,
                "session": request["session"],
                "reason": "error.build.failed",
                "error": {"retryable": True, "message": "the linker said no", "details": {}},
            },
        )
        emit(request, "invocation.finished", 1, status="failure")
        return FakeProcess(0)

    docker.run_program = program
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        frames = await collect(ws, until="invocation.verdict")

    payload = frames[-1]["payload"]
    assert payload["status"] == "failure"
    assert "exited 0" in payload["contract_violation"]
    # The program's own promise is carried as information and is never
    # the envelope's `retryable`: that value is the server's, "derived
    # from the server's own registry precisely so the promise cannot be
    # forged".
    assert payload["error"]["retryable"] is False
    assert payload["error"]["details"]["reason"] == "error.build.failed"


async def test_an_unknown_status_is_read_as_failure(client, config, docker) -> None:
    """§5.4: "Consumers MUST treat unknown values as ``failure``"."""

    def program(action, request, on_line):
        write_result(
            request,
            {
                "result": 1,
                "status": "mostly-fine",
                "action": action,
                "session": request["session"],
            },
        )
        emit(request, "invocation.finished", 1, status="mostly-fine")
        return FakeProcess(1)

    docker.run_program = program
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        frames = await collect(ws, until="invocation.verdict")

    assert frames[-1]["payload"]["status"] == "failure"


@pytest.mark.parametrize("reason", ["error.patch.incomplete", "error.work.foreign"])
async def test_an_interrupted_patch_application_poisons_the_session(
    client, config, docker, state, reason
) -> None:
    """§6.2 and §6.3: both are terminal for the session, in one sentence.

    "The backend MUST refuse every further working action in that
    session. The client's remedy is a **new session** — a new container,
    hence pristine trees." ``session.poisoned`` is that refusal on the
    wire, and ``get-artifact`` and ``close-session`` stay permitted.

    Parametrized over both because only one of them was ever exercised:
    the reason table and the backend's poisoning set were two
    independent literals, and the set could lose ``error.work.foreign``
    with the suite green. It is derived from the table now, and this is
    the test that says the derivation is the right one.
    """

    def program(action, request, on_line):
        write_result(
            request,
            {
                "result": 1,
                "status": "failure",
                "action": action,
                "session": request["session"],
                "reason": reason,
                "error": {"retryable": False, "message": "zephyr half patched", "details": {}},
            },
        )
        emit(request, "invocation.finished", 1, status="failure")
        return FakeProcess(1)

    docker.run_program = program
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"patches/zephyr/0001.patch": PATCH})
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")
        again = await call(ws, "build", {"session_id": session_id}, frame_id="b2")

    assert frames[-1]["payload"]["error"]["code"] == "session.poisoned"
    assert again["error"]["code"] == "session.poisoned"


async def test_a_verify_mismatch_fails_the_invocation_without_poisoning(
    client, config, docker
) -> None:
    """An integrity mismatch is a failed invocation and a live session.

    The distinction is §6.2's: a session poisons when an interrupted
    patch application leaves trees no future build may trust, and a
    ``verify`` never touches a tree. Poisoning here would kill a session
    for having been checked — and the obvious next move after a mismatch
    is to look at what else the session holds, not to lose it.
    """

    def program(action, request, on_line):
        write_result(
            request,
            {
                "result": 1,
                "status": "failure",
                "action": "verify",
                "session": request["session"],
                "reason": "error.context.mismatch",
                "error": {
                    "retryable": False,
                    "message": "model/device-model.json",
                    "details": {"paths": ["model/device-model.json"]},
                },
            },
        )
        emit(request, "invocation.finished", 1, status="failure")
        return FakeProcess(1)

    docker.run_program = program
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        frames = await collect(ws, until="invocation.verdict")
        attached = await call(ws, "attach-session", {"session_id": session_id}, frame_id="a")

    assert frames[-1]["payload"]["error"]["code"] == "context.integrity-mismatch"
    assert attached["type"] == "result"


def _declaring(*entries: tuple[str, str, bytes], hashes=None):
    """A program that writes *entries* into ``out`` and declares them.

    Each entry is ``(path, role, payload)``. *hashes* replaces the
    declared digest of one path, which is how the two §7.2 cases that
    turn on the verified-versus-declared distinction are stated.
    """

    def program(action, request, on_line):
        out = Path(request["out"])
        declared = []
        for name, role, payload in entries:
            (out / name).write_bytes(payload)
            digest = (hashes or {}).get(name) or hashlib.sha256(payload).hexdigest()
            declared.append(
                {"root": "out", "path": name, "role": role, "hashes": {"sha256": digest}}
            )
        write_result(
            request,
            {
                "result": 1,
                "status": "success",
                "action": "build",
                "session": request["session"],
                "reason": None,
                "error": None,
                "context": manifest_id(request),
                "layers": {},
                "artifacts": declared,
            },
        )
        emit(request, "invocation.finished", 1, status="success")
        return FakeProcess(0)

    return program


REPORT = json.dumps(BUILD_REPORT).encode()


async def test_a_build_that_delivers_no_report_is_not_a_successful_build(
    client, config, docker
) -> None:
    """§7.2: "exactly one artifact with role ``report``".

    "The program is forbidden to sign and the client therefore has to: a
    build whose parameters the client cannot read produces an image
    nobody can sign." So a delivery without one is not a delivery, even
    though the firmware itself verified.
    """
    docker.run_program = _declaring(("firmware.hex", "firmware", b":00\n"))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")

    payload = frames[-1]["payload"]
    assert payload["status"] == "failure"
    assert any("role report" in problem for problem in payload["error"]["details"]["problems"])


async def test_a_build_with_two_reports_is_not_a_successful_build_either(
    client, config, docker
) -> None:
    """ "**Exactly** one", because the client that signs detached has to
    know which report describes the image it is signing."""
    docker.run_program = _declaring(
        ("firmware.hex", "firmware", b":00\n"),
        ("build-report.json", "report", REPORT),
        ("second-report.json", "report", REPORT + b" "),
    )
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")

    payload = frames[-1]["payload"]
    assert payload["status"] == "failure"
    assert any("2 artifacts with role report" in p for p in payload["error"]["details"]["problems"])


async def test_a_build_with_no_firmware_at_all_is_not_a_successful_build(
    client, config, docker
) -> None:
    """The other half of §7.2's minimum: "the unsigned image with role
    ``firmware``". A report about an image nobody received is not a
    delivery."""
    docker.run_program = _declaring(("build-report.json", "report", REPORT))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")

    payload = frames[-1]["payload"]
    assert payload["status"] == "failure"
    assert any("role firmware" in problem for problem in payload["error"]["details"]["problems"])


async def test_the_delivery_rule_is_measured_on_what_verified_and_not_on_what_was_declared(
    client, config, docker
) -> None:
    """The distinction the rule spends a paragraph defending.

    A build that *declares* a report and delivers one whose bytes do not
    re-hash has produced an image nobody can sign, exactly as surely as
    one that never declared it — the backend serves the intersection of
    declared and verified (§9.3), and the client receives the
    intersection. Measured on the declaration this case answers
    "success"; it is the only case that tells the two readings apart.
    """
    docker.run_program = _declaring(
        ("firmware.hex", "firmware", b":00\n"),
        ("build-report.json", "report", REPORT),
        hashes={"build-report.json": hashlib.sha256(b"a different report").hexdigest()},
    )
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")

    payload = frames[-1]["payload"]
    assert payload["status"] == "failure"
    assert [entry["path"] for entry in payload["artifacts"]] == ["firmware.hex"]
    problems = payload["error"]["details"]["problems"]
    assert any("role report" in problem for problem in problems), problems


async def test_a_declared_artifact_this_server_cannot_resolve_fails_the_build(
    client, config, docker
) -> None:
    """§9.3: a hash in the wrong rendering "is a **mismatch**, not a value
    to fold" — and a mismatch fails §5.3's sixth condition.

    Dropping the entry instead reported ``status: success`` with the
    artifact absent from the delivery and no error anywhere, which is
    the one failure a client has no way to notice: it asked for a build,
    it was told the build succeeded, and the file it needs is simply not
    in the list.
    """
    payload = b"\x00\x01\x02\x03"
    docker.run_program = _declaring(
        ("firmware.hex", "firmware", b":00\n"),
        ("build-report.json", "report", REPORT),
        ("firmware.bin", "firmware", payload),
        hashes={"firmware.bin": hashlib.sha256(payload).hexdigest().upper()},
    )
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")

    finished = frames[-1]["payload"]
    assert finished["status"] == "failure"
    assert [entry["path"] for entry in finished["artifacts"]] == [
        "firmware.hex",
        "build-report.json",
    ]
    assert any(
        "64 lowercase hex" in problem for problem in finished["error"]["details"]["problems"]
    )


async def test_a_build_that_reports_no_layers_for_a_patched_context_is_not_successful(
    client, config, docker
) -> None:
    """§5.4's ``layers`` row, compared against what the backend derived.

    "MUST, on success, **for every patched layer**", and "the backend
    compares the block against what it expects to have been applied".
    Checked as "is it a dict", a build on a context carrying
    ``patches/zephyr/`` that answered ``layers: {}`` was fully
    successful — a build that either did not apply those patches or did
    not say so, and the row exists so that the two cannot be told apart
    by omission.
    """

    def program(action, request, on_line):
        write_result(
            request,
            {
                "result": 1,
                "status": "success",
                "action": "build",
                "session": request["session"],
                "reason": None,
                "error": None,
                "context": manifest_id(request),
                "layers": {},
                "artifacts": [],
            },
        )
        emit(request, "invocation.finished", 1, status="success")
        return FakeProcess(0)

    docker.run_program = program
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"patches/zephyr/0001-fix.patch": PATCH})
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")

    payload = frames[-1]["payload"]
    assert payload["status"] == "failure"
    assert any(
        'no layers entry for "zephyr"' in problem
        for problem in payload["error"]["details"]["problems"]
    )


# --------------------------------------------------------------------------
# The shared cache (§10)
# --------------------------------------------------------------------------


@pytest.fixture
def cached(config, tmp_path):
    return replace(config, ccache_dir=tmp_path / "ccache")


async def test_the_shared_cache_is_offered_read_only_and_keyed_by_program_id(
    aiohttp_client, cached, docker
) -> None:
    """§10: "Shared backends MUST offer a shared cache read-only for
    untrusted work; cache warming is a deliberate operator invocation
    with a writable cache and trusted contexts only."

    A build server serves untrusted contexts by definition and has no
    warming verb, so read-only here has no option to change it — and the
    store is one subdirectory per ``program.id``, which is §10's own
    recommendation "so that two foreign images cannot corrupt each
    other's store". The whole path was dead in this suite: no test set
    ``ccache_dir``, so a silently inverted ``read_only`` would have been
    a cross-tenant write nobody noticed.
    """
    from mcuhome_buildserver.app import ServerState, create_app

    state = ServerState(cached)
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, cached)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")

    store = cached.ccache_dir / "org.mcuhome.build-container"
    assert docker.invocations[-1].request["ccache"] == {"path": str(store), "writable": False}
    started = next(argv for argv in docker.calls if "--detach" in argv)
    assert f"{store}:{store}:ro" in _volumes(started)


async def test_a_program_id_that_is_not_a_path_segment_gets_no_cache_at_all(
    aiohttp_client, cached, docker
) -> None:
    """§7.1.1 makes ``program.id`` opaque — "a backend compares it for
    equality and does nothing else with it".

    So an identity that is not a usable directory name gets no cache
    rather than a sanitized one: a third-party program may call itself
    anything, and a backend that repaired the name would be inventing an
    identity the program never claimed — and pointing two of them at one
    store.
    """
    from mcuhome_buildserver.app import ServerState, create_app

    docker.program["id"] = "../escape"
    state = ServerState(cached)
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, cached)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")

    assert "ccache" not in docker.invocations[-1].request
    started = next(argv for argv in docker.calls if "--detach" in argv)
    assert not any("ccache" in volume for volume in _volumes(started))


# --------------------------------------------------------------------------
# get-artifact
# --------------------------------------------------------------------------


async def test_get_artifact_announces_an_archive_and_streams_it(client, config) -> None:
    """E45: the mirror of the upload, and the bytes are a ``tar.zst``.

    The result frame **is** the announcement — size, SHA-256 and what is
    in the archive — and the BINARY frames follow it. There is no
    acknowledgement behind them for the reason the upload needs one and
    this does not: the receiving side is the client, and it knows the
    transfer is complete when it has taken the announced number of
    bytes.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

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
    assert [entry["path"] for entry in announcement["payload"]["artifacts"]] == [
        "firmware.hex",
        "firmware.bin",
        "build-report.json",
    ]

    import io
    import tarfile

    import zstandard

    raw = zstandard.ZstdDecompressor().decompress(archive, max_output_size=1 << 20)
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        assert sorted(tar.getnames()) == ["build-report.json", "firmware.bin", "firmware.hex"]


async def test_get_artifact_with_a_path_holds_exactly_that_one(client, config) -> None:
    """ "With ``path``, the archive holds exactly that declared artifact"."""
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")
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

    The refusal for an unknown path was named nowhere and is this
    server's own: the invocation exists and answered, so the statement
    is about the artifact rather than about the invocation.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")
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


async def test_the_programs_own_retryable_travels_as_the_programs_and_not_as_the_envelopes(
    client, config, docker
) -> None:
    """§5.4.1, both halves of it.

    ``error.retryable`` is "the program's promise about its own failure,
    and about nothing else", and a backend "MUST NOT relay it as the
    session protocol's ``retryable``". Carrying it under a name that
    says whose promise it is costs nothing and is the only way a client
    sees the program's opinion at all — and it was documented as
    happening while being dropped on the floor.
    """

    def program(action, request, on_line):
        write_result(
            request,
            {
                "result": 1,
                "status": "failure",
                "action": action,
                "session": request["session"],
                "reason": "error.build.failed",
                "error": {"retryable": True, "message": "flaky linker", "details": {"tries": 3}},
            },
        )
        emit(request, "invocation.finished", 1, status="failure")
        return FakeProcess(1)

    docker.run_program = program
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        frames = await collect(ws, until="invocation.verdict")

    error = frames[-1]["payload"]["error"]
    assert error["details"]["container_retryable"] is True
    assert error["details"]["container_details"] == {"tries": 3}
    assert error["retryable"] is False, "the envelope's promise is this server's"


async def test_a_runtime_that_dies_between_send_context_and_build_is_typed(
    client, config, docker, state
) -> None:
    """The pre-start refusal at *container start*, which had no test.

    ``send-context`` has already described the image and cached the
    answer, so nothing refuses ahead of the ``docker run`` — and a
    daemon that went away in between is ``builder.runtime-unavailable``,
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


async def test_the_verdict_frame_is_sent_and_never_offered(client, config, docker, monkeypatch):
    """E46's one frame with no second way to be learned.

    ``_publish`` says it plainly — "the ``invocation.verdict`` frame is
    sent instead, because it is the one frame a client is waiting on and
    there is no second way to learn it" — and the distinction between
    the two enqueue paths was asserted nowhere, so the completion frame
    could be made droppable with the suite green. The log and the
    program's events are offered, for the reason the same docstring
    gives: both survive a gap — the program's own ``invocation.finished``
    among them, since it is a line in the events file ``attach-session``
    replays from.
    """
    from mcuhome_buildserver.ws import Connection

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
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    def verdict(frames):
        return [frame for frame in frames if frame.get("event") == "invocation.verdict"]

    assert len(verdict(sent)) == 1
    assert verdict(offered) == []
    assert any(frame.get("type") == "log" for frame in offered)
    assert any(frame.get("event") == "artifact.collected" for frame in offered)
    # And the program's own §8 announcement is on the droppable side of
    # the same run (E58): same invocation, two frames, told apart by
    # name rather than by the absence of a field.
    assert any(frame.get("event") == "invocation.finished" for frame in offered)


async def test_the_per_invocation_directory_is_prepared_the_way_9_1_asks(
    client, config, docker, state
) -> None:
    """§9.1's preparation list, on disk, after the invocation finished.

    "An empty ``out``, an empty ``tmp``, the events file" — the events
    file created by the *backend* so that "not created yet" and "no
    events yet" are not the same thing for a reader, and the directory
    itself ``0o700`` for the same reason the session root is: everything
    under it is one client's.

    The program here emits **no events at all**, which is a conforming
    program (§8 requires none) and the only one that can see the
    difference: with an emitting program the file exists because the
    program made it, and the backend's own duty is invisible.
    """

    def silent(action, request, on_line):
        write_result(
            request,
            {
                "result": 1,
                "status": "success",
                "action": action,
                "session": request["session"],
                "reason": None,
                "error": None,
                "context": manifest_id(request),
            },
        )
        return FakeProcess(0)

    docker.run_program = silent
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")
        directory = state.sessions.require(session_id).paths.invocation("inv-1")

    assert (directory / "events.ndjson").exists()
    assert (directory / "tmp").is_dir()
    assert list((directory / "tmp").iterdir()) == []
    assert directory.stat().st_mode & 0o077 == 0
    assert (directory / "out").stat().st_mode & 0o077 == 0


# --------------------------------------------------------------------------
# attach-session, cancel, close-session
# --------------------------------------------------------------------------


async def test_nothing_filesystem_heavy_runs_on_the_event_loop(
    client, config, docker, monkeypatch
) -> None:
    """E45's archive and E48's SDK, off the loop.

    ``acquire_sdk`` hashes a multi-gigabyte package, streams a full zstd
    decompression to disk and untars it; ``harden`` re-hashes every
    artifact of a build; ``build_archive`` tars and compresses them all
    and then re-reads the spool. All three sat on the event loop, in the
    path of commands that promise to answer immediately — and the
    endpoint's thirty-second heartbeat means a long enough stall drops
    *unrelated* clients' connections.
    """
    from mcuhome_buildserver import artifacts, sdkstore

    threads: dict[str, threading.Thread] = {}

    def record(name, function):
        def wrapper(*arguments, **keywords):
            threads[name] = threading.current_thread()
            return function(*arguments, **keywords)

        return wrapper

    monkeypatch.setattr(sdkstore, "acquire_sdk", record("sdk", sdkstore.acquire_sdk))
    monkeypatch.setattr(artifacts, "harden", record("harden", artifacts.harden))
    monkeypatch.setattr(artifacts, "build_archive", record("archive", artifacts.build_archive))

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")
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

    assert set(threads) == {"sdk", "harden", "archive"}
    for name, thread in threads.items():
        assert thread is not threading.main_thread(), f"{name} ran on the event loop"


async def test_one_download_at_a_time_per_connection_and_never_one_spool(
    client, config, monkeypatch
) -> None:
    """Two ``get-artifact`` commands on one connection, and neither
    corrupts the other.

    Nothing enforced either half. Every command runs as its own task, so
    two downloads interleaved their BINARY frames — which carry no id,
    so a client cannot sort them — and the spool was named by invocation
    id alone, so two deliveries of one invocation wrote the same file and
    the first to finish unlinked it while the second was still streaming
    it. The announced size and hash and the delivered bytes then came
    from different archives.
    """
    from mcuhome_buildserver import artifacts
    from mcuhome_buildserver import sessions as session_module

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
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")
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


async def test_a_download_that_no_longer_matches_what_was_verified_is_refused(
    client, config, state
) -> None:
    """The blocker, over the wire: the session tree stays writable, so
    §9.3 is enforced again at delivery.

    The container of a session outlives every invocation in it, and its
    tree is mounted writable — so a later invocation can replace an
    earlier one's artifact with a link to a host file, and a
    ``get-artifact`` that trusted the earlier check would pack that
    file's bytes under the declared name.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

        out = state.sessions.require(session_id).paths.invocation("inv-1") / "out"
        outside = state.config.context_root / "outside"
        outside.write_bytes(b"a host file outside out/\n")
        (out / "firmware.hex").unlink()
        (out / "firmware.hex").symlink_to(outside)

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


async def test_attach_session_replays_before_it_joins_the_live_stream(
    client, config, monkeypatch
) -> None:
    """The boundary is a boundary, and the ordering is what makes it one.

    "Every event frame it sees before the answer is history, and
    everything after it is live" — which fails the moment the connection
    joins the audience *before* the replay: every ``await`` in the
    replay loop is a turn for the supervisor relaying an invocation that
    is still running, so live frames land among the replayed ones and an
    event the reader has not reached yet is delivered twice.

    Asserted on the order of the two operations rather than on a race,
    because a race that reproduces sometimes is a test that passes
    sometimes.
    """
    from mcuhome_buildserver.backend import ContainerBackend
    from mcuhome_buildserver.ws import Connection

    timeline: list[tuple[str, object]] = []
    real_attach = ContainerBackend.attach
    real_send = Connection.send

    def attach(self, session_id, connection, *, boundary=None):
        timeline.append(("attach", boundary))
        return real_attach(self, session_id, connection, boundary=boundary)

    async def send(self, frame):
        if frame.get("type") == "event":
            timeline.append(("event", frame["payload"].get("seq")))
        return await real_send(self, frame)

    monkeypatch.setattr(ContainerBackend, "attach", attach)
    monkeypatch.setattr(Connection, "send", send)

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")
        timeline.clear()
        answer = await call(
            ws,
            "attach-session",
            {"session_id": session_id, "invocation_id": "inv-1", "from_seq": 3},
            frame_id="a",
        )

    assert answer["payload"]["replayed"] == 4
    assert timeline == [
        ("event", 3),
        ("event", 4),
        ("event", 5),
        ("event", 6),
        ("attach", ("inv-1", 6)),
    ]


def test_an_event_already_replayed_is_not_relayed_to_that_connection_again(
    config, tmp_path
) -> None:
    """The other half of the boundary: history is not repeated as news.

    Joining after the replay closes the interleaving; the boundary
    closes the duplicate. An event the backend's own reader had not
    reached yet, and this connection already has from the file, is not
    delivered to it a second time — while it still reaches every other
    connection, which never saw it.
    """
    from mcuhome_buildserver import protocol
    from mcuhome_buildserver.backend import ContainerBackend, InvocationRecord

    class Fake:
        def __init__(self) -> None:
            self.frames: list[dict] = []

        def offer(self, frame):
            self.frames.append(frame)

    backend = ContainerBackend(config, docker=object())
    record = InvocationRecord(
        id="inv-1", session_id="s-1", action="build", directory=tmp_path, context_id="x"
    )
    replayed, fresh = Fake(), Fake()
    backend.attach("s-1", replayed, boundary=("inv-1", 6))
    backend.attach("s-1", fresh)

    for seq in (5, 6, 7):
        backend._publish(
            record, protocol.event_frame("build.image.started", {"seq": seq}), drop_when_full=True
        )

    assert [frame["payload"]["seq"] for frame in replayed.frames] == [7]
    assert [frame["payload"]["seq"] for frame in fresh.frames] == [5, 6, 7]


async def test_attach_session_replays_events_from_a_stated_seq(client, config) -> None:
    """E46: the NDJSON file on disk **is** the replay buffer.

    "It stays on disk until close-session and IS the replay buffer:
    attach-session replays from a client-stated seq by reading the
    file." No in-memory ring, so there is nothing a long reconnect can
    find already evicted — and the replayed frames go out before the
    verb's own answer, which is what makes the boundary readable.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

        await ws.send_json(
            {
                "id": "a",
                "type": "attach-session",
                "payload": {
                    "session_id": session_id,
                    "invocation_id": "inv-1",
                    "from_seq": 3,
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

    # The conforming program emits seq 1..6; from 3 that is four events.
    assert answer["payload"]["replayed"] == 4
    assert [entry["payload"]["seq"] for entry in replayed] == [3, 4, 5, 6]
    assert all(entry["payload"]["invocation_id"] == "inv-1" for entry in replayed)


async def test_cancel_creates_the_sentinel_file_the_request_named(
    client, config, docker, state
) -> None:
    """§8: "the **existence** of that file means stop".

    A cooperative sentinel rather than a signal, because killing a
    ``docker exec`` client does not kill the process inside the
    container and because the same mechanism works unchanged in the
    subprocess profile.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")
        session = state.sessions.require(session_id)
        session.invocations["inv-1"] = sessions.INVOCATION_RUNNING
        await call(ws, "cancel", {"session_id": session_id, "invocation_id": "inv-1"}, frame_id="c")
        sentinel = session.paths.invocation("inv-1") / "cancel"

    assert sentinel.exists()
    assert docker.invocations[-1].request["cancel"] == str(sentinel)


async def test_the_liveness_ladder_starts_with_the_sentinel_and_then_signals(
    aiohttp_client, config, docker
) -> None:
    """The ladder of §8, with a grace of zero so it runs in a test.

    The sentinel is first because it is the only rung that lets the
    program write a result document — ``status: "cancelled"``, with
    ``reason`` and ``error`` both null, because nothing was diagnosed.
    SIGTERM follows at ``cancel_grace_seconds``, and it is worth saying
    plainly that it does **not** reach the process inside the container:
    killing a ``docker exec`` client never has, which is exactly why the
    contract has a cooperative sentinel at all.
    """
    from mcuhome_buildserver.app import ServerState, create_app

    processes: list[FakeProcess] = []

    def program(action, request, on_line):
        process = FakeProcess(0, hang=True)
        processes.append(process)
        return process

    docker.run_program = program
    state = ServerState(
        replace(config, cancel_grace_seconds=0, allowed_patch_layers=sessions.PATCH_LAYERS)
    )
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await call(ws, "cancel", {"session_id": session_id, "invocation_id": "inv-1"}, frame_id="c")
        frames = await collect(ws, until="invocation.verdict")

    assert processes[0].terminated is True
    # No result document was ever written, so the invocation is the
    # infrastructure failure rather than a verdict on the context.
    assert frames[-1]["payload"]["error"]["code"] == "builder.crashed"


async def test_the_deadline_is_enforced_by_this_server(aiohttp_client, config, docker) -> None:
    """§9.1: ``limits.deadline_seconds`` is advisory to the program and
    "enforcement is the backend's".

    A program that honours it stops itself and says
    ``error.deadline.exceeded``; one that does not gets the same ladder
    a cancel gets, starting with the sentinel it agreed to poll.
    """
    from mcuhome_buildserver.app import ServerState, create_app

    processes: list[FakeProcess] = []
    docker.run_program = lambda action, request, on_line: (
        processes.append(FakeProcess(0, hang=True)) or processes[-1]
    )
    state = ServerState(replace(config, build_deadline_seconds=0, cancel_grace_seconds=0))
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        answer = await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")
        sentinel = (
            state.sessions.require(session_id).paths.invocation(answer["payload"]["invocation_id"])
            / "cancel"
        )

    assert sentinel.exists()
    assert processes[0].terminated is True


async def test_a_client_that_ignores_sigterm_is_killed(
    aiohttp_client, config, docker, monkeypatch
) -> None:
    """The last rung, and the shortest.

    By the time it is reached the program has ignored a sentinel it
    agreed to poll and a signal it agreed to handle. What actually reaps
    a program that ignored both is the container going away at
    ``close-session`` — one session is one container, so there is always
    that hammer behind this one.
    """
    from mcuhome_buildserver import backend
    from mcuhome_buildserver.app import ServerState, create_app

    monkeypatch.setattr(backend, "_KILL_AFTER_SECONDS", 0.0)
    processes: list[FakeProcess] = []

    def program(action, request, on_line):
        processes.append(FakeProcess(0, hang=True, ignores_terminate=True))
        return processes[-1]

    docker.run_program = program
    state = ServerState(replace(config, build_deadline_seconds=0, cancel_grace_seconds=0))
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")

    assert processes[0].terminated is True
    assert processes[0].killed is True


async def test_a_describe_that_writes_no_result_disqualifies_the_image(
    client, config, docker
) -> None:
    """§7.1: ``describe`` "doubles as the first conformance test: a
    program that cannot answer ``describe`` cannot be trusted with a
    build"."""
    docker.program = None
    docker.describe_exit = 66
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(
            ws, "send-context", session_id, buildable_context("a" * 63 + "0")
        )

    assert frame["error"]["code"] == "version.builder-unavailable"


async def test_an_action_describe_does_not_announce_is_never_invoked(
    client, config, docker
) -> None:
    """§7.1.1: "A backend MUST NOT invoke an action absent from the list."

    The image would answer ``unsupported.action`` legibly, which is
    precisely why there is no reason to make it: the refusal is already
    knowable, and making it costs a container start.
    """
    docker.program["actions"] = ["describe", "build"]
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        frame = await call(ws, "verify", {"session_id": session_id}, frame_id="v")

    error = frame["error"]
    assert error["code"] == "version.builder-unavailable"
    assert error["details"]["actions"] == ["build", "describe"]
    assert not any(argv[-2:-1] == ["verify"] for argv in docker.calls)


async def test_close_session_reaps_the_container(client, config, docker) -> None:
    """One session is one container, and the container goes with it."""
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")
        await call(ws, "close-session", {"session_id": session_id}, frame_id="x")

    assert docker.removed == docker.containers
    assert docker.removed


async def test_close_session_kills_the_container_before_it_deletes_the_tree(
    client, config, docker, state, monkeypatch
) -> None:
    """The order is the guarantee, and it was the other way round.

    E39 makes close an implicit cancel, and the cancel is best-effort:
    the sentinel is set for a program that happens to be between polls,
    the container is removed ``--force`` — which is the actual kill,
    since killing a ``docker exec`` client never reached the process
    inside — and only then is the tree deleted. Deleting first pulls the
    mount source out from under a program that is still running in it,
    and it also made the sentinel meaningless: it existed for the few
    microseconds between two statements.
    """
    from mcuhome_buildserver import container

    docker.run_program = lambda action, request, on_line: FakeProcess(0, hang=True)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        session = state.sessions.require(session_id)
        paths = session.paths

        seen: list[tuple[str, bool, bool]] = []
        real_run = docker.run

        async def recording(argv):
            if argv[1] == "rm":
                sentinel = paths.invocation("inv-1") / "cancel"
                seen.append(("rm", paths.root.exists(), sentinel.exists()))
            return await real_run(argv)

        monkeypatch.setattr(container, "run_docker", recording)
        await call(ws, "close-session", {"session_id": session_id}, frame_id="x")

    assert seen == [("rm", True, True)], "the tree was still there and the signal was set"
    assert not paths.root.exists(), "and the tree is gone once the container is"


async def test_one_invocation_at_a_time_per_session(client, config, docker) -> None:
    """§9.1: never two invocations against the same ``work``.

    "The program cannot check the first, so it is stated as a backend
    duty." Pre-registry, like the context verbs' own guard: no
    registered code means "this session is already doing work", and
    inventing one is a protocol decision.
    """
    docker.run_program = lambda action, request, on_line: FakeProcess(0, hang=True)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        second = await call(ws, "build", {"session_id": session_id}, frame_id="b2")
        await call(ws, "close-session", {"session_id": session_id}, frame_id="x")

    assert second["error"]["code"] == "bad_request"
    assert "one invocation at a time" in second["error"]["message"].lower()


# --------------------------------------------------------------------------
# The SDK, and the image
# --------------------------------------------------------------------------


async def test_a_pin_no_source_holds_is_sdk_unavailable(client, config) -> None:
    """E48: the pin is looked up, and "not here" is a final answer.

    The source list is searched in a fixed order and nothing is fetched
    from the url in the context — that value is a hint (ADR 0019 §8), and
    a backend that followed it would let a client point this server's
    fetcher wherever it liked.
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
    assert error["details"]["version"] == "2.4.0"
    # The client keeps what it can act on and no operator host path: the
    # searched source directories are filesystem layout and stay off the
    # wire (they are logged server-side instead).
    assert "sources" not in error["details"]
    assert "found" not in error["details"]
    assert str(config.sdk_sources[0]) not in str(frame)


async def test_a_package_with_the_right_name_and_wrong_bytes_is_refused(client, config) -> None:
    """§9.1: the content of ``trees.sdk`` matches the pinned hash.

    The name only makes a candidate findable. A file named for the right
    version whose bytes hash to something else is either a corrupted
    mirror or a package somebody replaced, and both are answers an
    operator has to see rather than a fallback this server can make.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, buildable_context(sha256))
        await call(ws, "lock-context", {"session_id": session_id}, frame_id="l")
        (config.sdk_sources[0] / "mcuhome-sdk-2.4.0.tar.zst").write_bytes(b"not the package")
        frame = await call(ws, "verify", {"session_id": session_id}, frame_id="v")

    assert frame["error"]["code"] == "sdk.unavailable"
    assert frame["error"]["details"]["sha256"] == sha256


async def test_the_sdk_is_unpacked_per_session_and_mounted_where_describe_asked(
    client, config, docker, state
) -> None:
    """``sdk`` reports ``path: null``, so the backend chooses — and it
    chooses inside the session's own directory, which is what makes a
    patched SDK a writable view without an overlay.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")
        paths = state.sessions.require(session_id).paths

    assert (paths.sdk / "mcuhome/__init__.py").read_bytes() == b"# the SDK\n"
    assert docker.invocations[-1].request["trees"]["sdk"]["path"] == str(paths.sdk)
    assert docker.invocations[-1].request["trees"]["sdk"]["writable"] is False


async def test_describe_is_asked_once_per_image_digest(client, config, docker) -> None:
    """Cached per digest for the life of the process, because that is
    what it is a property of: an image is identified by its digest, and
    a digest names bytes that do not change.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await locked(ws, config)
        await open_session(ws)
        sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
        second = await open_session(ws)
        await send_archive(ws, "send-context", second, buildable_context(sha256))

    describes = [argv for argv in docker.calls if argv[-2:-1] == ["describe"]]
    assert len(describes) == 1


@pytest.mark.parametrize(
    ("what", "change", "fragment"),
    [
        ("a contract version this server does not implement", {"contract": 2}, "contract version"),
        ("a request format this server does not write", {"request": [2]}, "request format"),
        ("a result format this server does not read", {"result": [2]}, "result format"),
        ("no trees block at all", {"trees": None}, "program.trees"),
        ("no id", {"id": None}, "program.id"),
    ],
)
async def test_every_pre_invocation_conformance_gate_disqualifies_an_image(
    client, config, docker, what: str, change: dict, fragment: str
) -> None:
    """§7.1.1's four gates, each on its own — "the first conformance test".

    "A backend that does not implement the value it finds here MUST NOT
    invoke a working action on this program — everything else in the
    result document is described by a specification the backend does not
    have." The same holds of a request format the program cannot parse,
    a result format it does not write, and a ``program`` block missing a
    field §7.1.1 makes mandatory.

    All four were unobserved: each could be disabled individually with
    the suite green, because the only lever any test pulled on the
    describe answer was the action list. The label cross-check passed
    through a *different* branch and kept firing, which is what made the
    gap invisible.
    """
    for name, value in change.items():
        if value is None:
            del docker.program[name]
        else:
            docker.program[name] = value

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(
            ws, "send-context", session_id, buildable_context("a" * 63 + "0")
        )

    error = frame["error"]
    assert error["code"] == "version.builder-unavailable", what
    assert error["retryable"] is False
    assert fragment in error["details"]["problem"], (what, error["details"]["problem"])
    # And no working action was ever attempted against it.
    assert not any(argv[-2:-1] in (["verify"], ["build"]) for argv in docker.calls)


async def test_a_label_that_contradicts_describe_disqualifies_the_image(
    client, config, docker
) -> None:
    """§2.1: "a backend MUST NOT rely on a label ``describe`` contradicts".

    §7.1.1 goes further for the one label with a counterpart in the
    block: where ``program.contract`` and ``org.mcuhome.contract``
    disagree, "``describe`` is authoritative and the disagreement is a
    contract violation against the image".
    """
    docker.images[IMAGE_REFERENCE]["Config"]["Labels"]["org.mcuhome.contract"] = "2"
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(
            ws, "send-context", session_id, buildable_context("a" * 63 + "0")
        )

    error = frame["error"]
    assert error["code"] == "version.builder-unavailable"
    assert "org.mcuhome.contract" in error["details"]["problem"]


async def test_an_image_missing_a_coupling_label_does_not_qualify(client, config, docker) -> None:
    """§2.1.1: "absence is never read as compatible".

    "An image that does not say what it builds against has not made the
    declaration the constraint is written against."

    Since E61 that has teeth earlier and a different code: the label is
    what a context's Zephyr line is matched against, so an image without
    one is not a candidate at all and this host ends up serving no line —
    ``version.builder-unsatisfiable``, with an empty ``available`` list
    saying exactly that. Under the digest-pinned format the same image
    was selected by digest first and only then failed the describe gate,
    which is why the refusal used to be the other code.
    """
    del docker.images[IMAGE_REFERENCE]["Config"]["Labels"]["org.mcuhome.zephyr"]
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(
            ws, "send-context", session_id, buildable_context("a" * 63 + "0")
        )

    assert frame["error"]["code"] == "version.builder-unsatisfiable"
    assert frame["error"]["details"]["required"] == ZEPHYR_LINE
    assert frame["error"]["details"]["available"] == []


async def test_the_newest_release_of_the_required_line_is_the_one_selected(
    client, config, docker
) -> None:
    """Several candidates, one deterministic choice (E61).

    It has to be deterministic — two sessions sending one context to one
    server must build in one image, or the manifests they get back
    describe different builds — and of the deterministic rules available
    it is the one ADR 0013 already argues for: "a line, never a frozen
    point release — patch releases with security backports are always
    taken".

    The image of another line is in the inventory throughout, and is
    never a candidate: this is a choice among the images that serve the
    requirement, not among the images that exist.
    """
    other = f"{IMAGE}:zephyr-4.4.2-r1"
    newer_digest = "sha256:" + "e" * 64
    docker.images[other] = {
        "Id": "sha256:" + "d" * 64,
        "RepoTags": [other],
        "RepoDigests": [f"{IMAGE}@{newer_digest}"],
        "Config": {"Labels": {**IMAGE_LABELS, "org.mcuhome.zephyr": "4.4.2"}},
    }
    wrong_line = f"{IMAGE}:zephyr-4.5.0-r1"
    docker.images[wrong_line] = {
        "Id": "sha256:" + "9" * 64,
        "RepoTags": [wrong_line],
        "RepoDigests": [f"{IMAGE}@{'9' * 64}"],
        "Config": {"Labels": {**IMAGE_LABELS, "org.mcuhome.zephyr": "4.5.0"}},
    }
    docker.listed = [wrong_line, f"{IMAGE}:zephyr-4.4.0-r4", other]

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, base_context())

    serving = frame["payload"]["container"]
    assert serving["digest"] == newer_digest
    assert serving["tag"] == "zephyr-4.4.2-r1"


async def test_the_chosen_image_is_invoked_by_digest_and_not_by_tag(client, config, docker) -> None:
    """A tag can be made to point at other bytes; a digest cannot.

    The selection reads a tag off ``docker image ls`` because that is
    what ``ls`` reports, and everything after it names the image the one
    way that cannot move underneath the session (ADR 0018 §7). The tag
    survives in the manifest's record beside the digest, which is where
    a human wants it.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"model/device-model.json": MODEL})
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")

    started = next(
        argv for argv in docker.calls if argv[:2] == ["docker", "run"] and "--detach" in argv
    )
    assert IMAGE_REFERENCE in started
    assert f"{IMAGE}:zephyr-4.4.0-r4" not in started


def _extra_image(docker, tag: str, *, release: str, digest: str, identity: str) -> str:
    """Put one more conforming build container on the fake host."""
    reference = f"{IMAGE}:{tag}"
    docker.images[reference] = {
        "Id": "sha256:" + identity * 64,
        "RepoTags": [reference],
        "RepoDigests": [f"{IMAGE}@sha256:{digest * 64}"],
        "Config": {"Labels": {**IMAGE_LABELS, "org.mcuhome.zephyr": release}},
    }
    docker.images[f"{IMAGE}@sha256:{digest * 64}"] = docker.images[reference]
    docker.listed = [*docker.listed, reference]
    return reference


async def test_an_image_pulled_after_the_lock_does_not_take_over_the_session(
    client, config, docker, state
) -> None:
    """One session, one build environment — the manifest is not a guess.

    ``send-context`` chooses the image and ``lock-context`` writes it
    into ``manifest.yaml``, where §3.2 makes it "the record of which
    build environment answered this context's requirement … the
    requirement says what was needed, this says what actually ran". An
    operator pulling a newer release of the same line into a running
    server is routine, and if the first ``build`` re-ran the selection it
    would win — ``max`` by release — and the artifacts would come out of
    an image the manifest does not name, with nothing able to notice: the
    recorded resolution is outside the ID by design and outside the
    per-invocation re-check's pin list.

    So the assertion is in two halves: the container starts from the
    image the manifest records, and the inventory is never even asked
    again. The second half is what makes the first one a rule rather than
    a coincidence of this fake's ordering.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"model/device-model.json": MODEL})
        listings = len([argv for argv in docker.calls if argv[1:3] == ["image", "ls"]])
        newer = _extra_image(docker, "zephyr-4.4.2-r1", release="4.4.2", digest="e", identity="d")
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")
        context = state.sessions.require(session_id).paths.context

    started = next(
        argv for argv in docker.calls if argv[:2] == ["docker", "run"] and "--detach" in argv
    )
    assert IMAGE_REFERENCE in started, "the image the manifest names"
    assert newer not in started and f"{IMAGE}@sha256:{'e' * 64}" not in started
    recorded = YAML(typ="safe", pure=True).load((context / "manifest.yaml").read_text())
    assert recorded["container"]["digest"] == IMAGE_DIGEST
    after = len([argv for argv in docker.calls if argv[1:3] == ["image", "ls"]])
    assert after == listings, "no second selection: the choice was made at send-context"


async def test_an_image_that_went_away_after_the_lock_is_a_typed_refusal(
    client, config, docker
) -> None:
    """The other half of holding the choice: it can be gone, not swapped.

    An operator may remove an image while a session sits locked. Another
    image of the same line then serves the requirement — and substituting
    it is exactly what must not happen, because ``manifest.yaml`` has
    already been answered and names the one that went. So the refusal is
    typed and names the missing image: ``version.builder-unavailable``,
    whose registry entry is "the image is not on this host", and which is
    not the retryable ``builder.runtime-unavailable`` because this server
    pulls nothing and "gone" is a final answer.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"model/device-model.json": MODEL})
        _extra_image(docker, "zephyr-4.4.2-r1", release="4.4.2", digest="e", identity="d")
        del docker.images[IMAGE_REFERENCE]
        frame = await call(ws, "build", {"session_id": session_id}, frame_id="b")

    error = frame["error"]
    assert error["code"] == "version.builder-unavailable"
    assert error["retryable"] is False
    assert error["details"]["digest"] == IMAGE_DIGEST
    assert error["details"]["image"] == IMAGE
    detached = [
        argv for argv in docker.calls if argv[:2] == ["docker", "run"] and "--detach" in argv
    ]
    assert detached == [], "no container was started in the substitute either"


async def test_a_rebuilt_tag_without_a_digest_is_described_again(client, config, docker) -> None:
    """The ``describe`` memo is keyed by bytes, never by a movable tag.

    An image built on this host and never pushed carries no repo digest —
    the case E61 made first-class with ``digest: null`` — and developing
    the build container itself means rebuilding one tag against a
    long-lived server. Keyed by the tag, every later session would be
    served the previous build's action set, tree paths and program
    version while ``docker exec`` ran against the new bytes. Docker's own
    image ID is content-addressed and changes on every rebuild, which is
    what makes it the honest stand-in.
    """
    reference = "localhost/build-container:dev"
    docker.images.clear()
    docker.images[reference] = {
        "Id": "sha256:" + "1" * 64,
        "RepoTags": [reference],
        "RepoDigests": [],
        "Config": {"Labels": dict(IMAGE_LABELS)},
    }
    docker.listed = [reference]

    async with client.ws_connect("/ws", headers=auth()) as ws:
        sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
        first = await open_session(ws)
        await send_archive(ws, "send-context", first, buildable_context(sha256))
        # The same tag, rebuilt: new bytes, new image id, same name.
        docker.images[reference] = {
            **docker.images[reference],
            "Id": "sha256:" + "2" * 64,
        }
        second = await open_session(ws)
        await send_archive(ws, "send-context", second, buildable_context(sha256))
        # And once more without a rebuild, which the memo must absorb.
        third = await open_session(ws)
        await send_archive(ws, "send-context", third, buildable_context(sha256))

    described = [argv for argv in docker.calls if argv[-2:-1] == ["describe"]]
    assert len(described) == 2, "once per set of bytes, not once per session"


async def test_capabilities_lists_the_local_build_container_inventory(client) -> None:
    """ADR 0019 §2: "tag + digest + contract labels", pre-session and cheap.

    Nothing here starts a container: a client asking what this server
    has is not yet asking any image to prove it, and ``describe`` costs
    a container start.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "capabilities")

    containers = frame["payload"]["containers"]
    assert len(containers) == 1
    assert containers[0]["digest"] == "sha256:" + "b" * 64
    assert containers[0]["labels"]["org.mcuhome.contract"] == "1"


async def test_capabilities_answers_an_empty_inventory_when_docker_is_down(client, docker) -> None:
    """The question is which images this server can serve, and "none" is
    a fact rather than an error. The refusal for a missing runtime
    belongs to the verb that actually needs a container.
    """
    docker.version_status = None
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "capabilities")

    assert frame["type"] == "result"
    assert frame["payload"]["containers"] == []


# --------------------------------------------------------------------------
# The context, re-measured
# --------------------------------------------------------------------------


async def test_the_locked_context_is_re_measured_before_every_invocation(
    client, config, state
) -> None:
    """The product owner's decision: contexts are small, so check them.

    What the re-check buys is the one thing the freeze cannot — the
    manifest and the files are compared *now*, so an invocation is never
    attributed to an identity that moved after it was answered. It does
    not poison: nothing was applied to any tree.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"model/device-model.json": MODEL})
        paths = state.sessions.require(session_id).paths
        (paths.context / "model/device-model.json").write_bytes(b"{}")
        frame = await call(ws, "build", {"session_id": session_id}, frame_id="b")
        attached = await call(ws, "attach-session", {"session_id": session_id}, frame_id="a")

    error = frame["error"]
    assert error["code"] == "context.integrity-mismatch"
    assert error["details"]["paths"] == ["model/device-model.json"]
    assert attached["type"] == "result"


async def test_a_rewritten_pin_is_caught_by_the_same_re_measurement(client, config, state) -> None:
    """§9.1's cross-check against "the header the session was admitted on".

    ADR 0018's amendment states the duty normatively because
    ``verify_context`` cannot establish it: a self-consistently forged
    manifest verifies clean. This server wrote the manifest itself, so
    what the check catches is a manifest that changed after it was
    written — which is exactly the gap the duty names.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        manifest = state.sessions.require(session_id).paths.context / "manifest.yaml"
        manifest.write_text(
            manifest.read_text().replace("nrf7002dk/nrf5340/cpuapp", "nrf5340dk/nrf5340/cpuapp")
        )
        frame = await call(ws, "verify", {"session_id": session_id}, frame_id="v")

    assert frame["error"]["code"] == "context.integrity-mismatch"
    assert "target.board" in frame["error"]["details"]["paths"]


async def test_a_rewritten_zephyr_line_is_caught_by_the_same_re_measurement(
    client, config, state
) -> None:
    """The requirement joined the cross-checked three, and earns its place.

    E61 took ``container.digest`` out of that list — it is this server's
    own record now, so comparing it to the pins would be comparing this
    server to itself — and put ``zephyr`` in. Unlike the other two,
    ``zephyr`` is hashed nowhere: the integrity list would not notice it
    moving, and neither would the recomputed ID. This comparison is the
    only thing that does.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        manifest = state.sessions.require(session_id).paths.context / "manifest.yaml"
        manifest.write_text(
            manifest.read_text().replace(f"zephyr: '{ZEPHYR_LINE}'", "zephyr: '9.9'")
        )
        frame = await call(ws, "verify", {"session_id": session_id}, frame_id="v")

    assert frame["error"]["code"] == "context.integrity-mismatch"
    assert "zephyr" in frame["error"]["details"]["paths"]


async def test_a_rewritten_context_format_version_is_caught_too(client, config, state) -> None:
    """``manifest.yaml``'s own format version is read back and compared.

    It is the last value in the document that nothing else measures: not
    an input of the ID, and not in the integrity list, because
    ``manifest.yaml`` carries that list and cannot be in it.
    ``context.yaml`` gets a hard version gate on every read and the
    session can only have been admitted on one number, so a manifest
    stating another is by construction a manifest that changed after it
    was written.

    Without the comparison the rewrite travelled all the way into the
    build container and came back as ``unsupported.context`` — mapped to
    ``version.context-format-unsupported``, whose own advice is "the
    client's move is a different container". The operator would be told
    the image was wrong.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        manifest = state.sessions.require(session_id).paths.context / "manifest.yaml"
        assert "context: 2" in manifest.read_text()
        manifest.write_text(manifest.read_text().replace("context: 2", "context: 1"))
        frame = await call(ws, "verify", {"session_id": session_id}, frame_id="v")

    assert frame["error"]["code"] == "context.integrity-mismatch"
    assert "context" in frame["error"]["details"]["paths"]


async def test_a_model_moved_to_another_line_after_the_lock_is_caught(
    client, config, state
) -> None:
    """The freeze's model cross-check, repeated before every invocation.

    ``zephyr`` may stay out of the context ID only because the line is
    "provably inside" the hashed device model (§3.3), and the check that
    makes that provable runs here as well as at the freeze — the same
    reason every other value in this pass is re-compared rather than
    trusted from the lock.

    It answers before the file-hash comparison it would also trip, and
    that ordering is deliberate: both fire, and "your two documents
    disagree about the Zephyr line" is the more specific news than "a
    file changed".
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(
            ws, config, **{"model/device-model.json": device_model(ZEPHYR_LINE)}
        )
        model = state.sessions.require(session_id).paths.context / "model/device-model.json"
        model.write_bytes(device_model("4.5"))
        frame = await call(ws, "verify", {"session_id": session_id}, frame_id="v")

    error = frame["error"]
    assert error["code"] == "context.integrity-mismatch"
    assert error["details"]["paths"] == ["zephyr vs model/device-model.json"]
    assert error["details"]["required"] == ZEPHYR_LINE
    assert error["details"]["stated"] == "4.5"


async def test_a_static_description_replaces_the_probe(client, config, docker, state) -> None:
    """§2.2.1: read the file where present, invoke describe otherwise.

    The static path exists for the image whose program body arrives with
    a mounted tree — undiscoverable before the mount point is known,
    and the mount point is what discovery would have supplied. The fake
    answers the `cat` with a describe result document, and the assertion
    is that NO describe container ran: the file replaced the probe, it
    did not precede it.
    """
    import json as _json

    docker.static_description = _json.dumps(
        {"result": 1, "status": "success", "action": "describe", "program": docker.program}
    )
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, base_context())
    assert docker.static_reads == ["/mcuhome/describe.json"]
    describe_runs = [
        call
        for call in docker.calls
        if call[1:2] == ["run"] and "--rm" in call and call[-2:-1] != ["cat"]
    ]
    assert describe_runs == [], "the file replaced the probe"


async def test_an_unreadable_static_description_falls_back_to_describe(
    client, config, docker
) -> None:
    """Half-readable must not be a third behaviour (§2.2.1).

    "There is no new failure mode in either direction, because the
    fallback is the thing that was already mandatory" — broken JSON in
    the file lands on exactly the probe path an image without the file
    gets, and the session proceeds.
    """
    docker.static_description = "{not json"
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, base_context())
    assert frame["payload"]["container"]["contract"] == 1
    describe_runs = [
        call
        for call in docker.calls
        if call[1:2] == ["run"] and "--rm" in call and call[-2:-1] != ["cat"]
    ]
    assert len(describe_runs) == 1, "the fallback probe ran"


async def test_the_sdk_keeps_its_executable_bit_and_nothing_else(tmp_path) -> None:
    """§6.1's `generate.program` is *executed*; 0600 across the board kills it.

    The context extractor strips every mode bit an archive could smuggle
    in, and that is right for contexts — nothing in model/, keys/ or
    patches/ is run. The SDK is the one tree with a program in it, so
    its unpack keeps exactly the owner's execute bit of regular files
    (0700) and still strips setuid/setgid/sticky/group/world. Found as
    a blocker by the B2 spec round: an SDK unpacked by this server
    answered exit 127 where code generation should be.
    """
    import io
    import tarfile

    import zstandard

    from mcuhome_buildserver import sdkstore

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        program = tarfile.TarInfo("bin/generate")
        payload = b"#!/usr/bin/env python3\n"
        program.size = len(payload)
        program.mode = 0o4775  # setuid + group/world bits: all must go
        tar.addfile(program, io.BytesIO(payload))
        quiet = tarfile.TarInfo("mcuhome-sdk.json")
        body = b'{"sdk": 1, "generate": {"program": "bin/generate", "runtime": "python3"}}'
        quiet.size = len(body)
        quiet.mode = 0o664
        tar.addfile(quiet, io.BytesIO(body))
    archive = zstandard.ZstdCompressor().compress(raw.getvalue())

    import hashlib

    source = tmp_path / "sources"
    source.mkdir()
    (source / "mcuhome-sdk-9.9.9.tar.zst").write_bytes(archive)
    into = tmp_path / "sdk"
    sdkstore.acquire_sdk(
        version="9.9.9",
        sha256=hashlib.sha256(archive).hexdigest(),
        sources=(source,),
        into=into,
        caps=sdkstore.SDK_CAPS,
        max_bytes=sdkstore.SDK_MAX_BYTES,
    )
    assert (into / "bin" / "generate").stat().st_mode & 0o7777 == 0o700
    assert (into / "mcuhome-sdk.json").stat().st_mode & 0o7777 == 0o600


async def test_the_sdk_is_not_held_to_the_clients_budget_shape(tmp_path) -> None:
    """The operator's material gets its own bounds, not the session caps.

    E44's numbers were argued for contexts (kilobytes to a few
    megabytes); an SDK is a source tree. Holding the operator's package
    to the client's budget shape would make the two knobs fight — an
    operator tightening context caps against abusive clients would
    break their own SDK. Pinned by the constant, not by a giant archive:
    the caps handed to the unpack are SDK_CAPS, and SDK_CAPS is roomier
    than any default context cap.
    """
    from mcuhome_buildserver import config as config_module
    from mcuhome_buildserver import sdkstore
    from mcuhome_buildserver.ingress import IngressCaps

    session_caps = IngressCaps.from_config(config_module.Config(token="t"))
    assert sdkstore.SDK_CAPS.compressed_bytes > session_caps.compressed_bytes
    assert sdkstore.SDK_CAPS.decompressed_bytes > session_caps.decompressed_bytes
    assert sdkstore.SDK_CAPS.entries > session_caps.entries
