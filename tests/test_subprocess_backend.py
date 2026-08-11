# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The subprocess backend, over the wire: argv, environment, child, verdict.

The sibling of :mod:`tests.test_backend`, and it mirrors it on purpose:
the same verbs over the same real socket, the same fake program driving
the same result documents, and the same assertions about what a backend
*is* — the argv it composes, the request documents it writes, what it
makes of what came back.

**The seam is process spawning, not docker.** :class:`FakeProgram`
replaces :func:`mcuhome_buildserver.program.run_program` and
:func:`~mcuhome_buildserver.program.spawn_program`, the two impure
functions that module goes through, and it is installed by an autouse
fixture for the same reason the docker fake is: a test that forgot to ask
for it would start a real compiler on the machine running the suite.

Three tests here start real child processes — the ones under "The tests
that start real processes" — because the whole argument for this profile
being a *subprocess* rather than an in-process call is that a build can
be killed without taking the server with it, and a fake that only records
``kill()`` cannot show that. Two of them go one level further and start a
*grandchild*, which is the only shape that can see the difference between
reaching the program and reaching the build it started: the program is
what runs west, and west is what runs ninja. They run Python snippets
that sleep, never a build, and every process they start is accounted for
in a ``finally``.

The autouse docker fake from :mod:`tests.conftest` is still installed,
and several tests assert it was never called: "no docker needed" is the
profile's whole point, and the cheapest way to keep that true is to look.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from mcuhome_buildserver import processes, sessions
from mcuhome_buildserver import program as program_seam
from mcuhome_buildserver.app import ServerState, create_app
from mcuhome_buildserver.config import load_config
from tests.conftest import (
    PROGRAM,
    ZEPHYR_LINE,
    FakeProcess,
    Invocation,
    auth,
    buildable_context,
    call,
    collect,
    conforming_program,
    device_model,
    send_archive,
    write_result,
    write_sdk_package,
)

MODEL = b'{"device": {"board": "nrf7002dk/nrf5340/cpuapp"}}'
PATCH = b"--- a/x\n+++ b/x\n"

#: How long a real-process assertion waits for something the kernel does
#: asynchronously. Signal delivery and reaping are not instant and this
#: suite runs on machines with four cores and a full test run in flight;
#: what the bound has to be is "long enough never to be the reason a
#: green assertion goes red", and every use of it below waits on a
#: condition rather than sleeping for it.
REAL_PROCESS_TIMEOUT = 10.0


async def until_true(condition: Callable[[], bool], *, timeout: float = 5.0) -> bool:
    """Poll *condition* until it holds or *timeout* passes. Answers whether."""
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if condition():
            return True
        await asyncio.sleep(0.01)
    return condition()


def alive(pid: int) -> bool:
    """Is *pid* a process that can still do work?

    Signal 0 asks without sending, and a zombie is filtered out on top of
    it: a process whose parent died before reaping it answers signal 0
    for as long as it is unreaped, and a test that counted that as alive
    would fail for the one reason it does not care about. What this test
    file asks about a grandchild is whether it is still *compiling*.
    """
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    try:
        status = Path(f"/proc/{pid}/stat").read_text()
    except OSError:  # pragma: no cover - /proc is there on every host this runs on
        return True
    return status.rpartition(")")[2].split()[0] != "Z"


def reap(pid: int | None) -> None:
    """Leave no process behind, whatever the assertions above did."""
    if pid is None:
        return
    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGKILL)


async def read_pid(path: Path) -> int:
    """The pid a real child wrote, once it has written it."""
    assert await until_true(lambda: path.is_file() and path.read_text().strip().isdigit()), (
        f"the child never wrote its grandchild's pid to {path}"
    )
    return int(path.read_text())


# --------------------------------------------------------------------------
# The seam: a program, faked where it would be started
# --------------------------------------------------------------------------


@dataclass
class FakeProgram:
    """The program as this suite has it: argv in, scripted answers out.

    The counterpart of :class:`tests.conftest.FakeDocker`, and smaller
    for the reason contract §2 gives: in this profile there is no image
    to inspect, no runtime to probe and no container to start, so the
    only two things that ever happen are ``describe`` and an invocation.
    """

    calls: list[list[str]] = field(default_factory=list)
    #: Every environment a child was started with — never ``None``,
    #: because §6.1's environment is stated and not inherited.
    environments: list[dict[str, str]] = field(default_factory=list)
    invocations: list[Invocation] = field(default_factory=list)
    #: The ``program`` block ``describe`` answers with, or ``None`` for a
    #: describe that writes no result document at all.
    program: dict[str, Any] | None = None
    describe_exit: int = 0
    describe_status: int | None = 0
    #: What one invocation does. Replaced by tests that want a failure,
    #: a crash or a hang.
    run_program: Any = None

    def __post_init__(self) -> None:
        if self.program is None:
            self.program = json.loads(json.dumps(PROGRAM))
        if self.run_program is None:
            self.run_program = conforming_program

    async def run(self, argv, *, env):
        """``describe``: short, bounded, its answer wanted as a value."""
        self.calls.append(list(argv))
        self.environments.append(dict(env))
        assert argv[-2] == "describe", argv
        if self.describe_status is None or self.program is None:
            return processes.Completed(status=self.describe_status, output="")
        document = json.loads(Path(argv[-1]).read_text())
        Path(document["result"]).write_text(
            json.dumps(
                {
                    "result": 1,
                    "status": "success",
                    "action": "describe",
                    "reason": None,
                    "error": None,
                    "program": self.program,
                }
            )
        )
        return processes.Completed(status=self.describe_exit, output="")

    async def spawn(self, argv, *, on_line, env):
        """One working invocation, started as a child of this process."""
        self.calls.append(list(argv))
        self.environments.append(dict(env))
        action, request_path = argv[-2], Path(argv[-1])
        request = json.loads(request_path.read_text())
        self.invocations.append(Invocation(action=action, argv=list(argv), request=request))
        return self.run_program(action, request, on_line)


@pytest.fixture(autouse=True)
def program(monkeypatch) -> FakeProgram:
    """The program, stubbed at the seam, for **every** test in this module."""
    fake = FakeProgram()
    monkeypatch.setattr(program_seam, "run_program", fake.run)
    monkeypatch.setattr(program_seam, "spawn_program", fake.spawn)
    return fake


@pytest.fixture
def config(config):
    """The suite's config, in the subprocess profile, with layers allowed.

    The patch layers are allowed for the same reason
    :mod:`tests.test_backend` allows them: the config **is** the patch
    policy and unlisted layers are denied everywhere else, which would
    mean no test here could reach a patched tree at all.
    """
    from dataclasses import replace

    return replace(config, backend_profile="subprocess", allowed_patch_layers=sessions.PATCH_LAYERS)


async def open_session(ws) -> dict[str, Any]:
    frame = await call(
        ws, "open-session", {"protocol_version": sessions.SESSION_PROTOCOL_VERSION}, frame_id="o"
    )
    return frame["payload"]


async def locked(ws, config, **files: bytes) -> tuple[str, str]:
    """A session with a frozen, buildable context. Returns ids."""
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    session_id = (await open_session(ws))["session"]["id"]
    sent = await send_archive(ws, "send-context", session_id, buildable_context(sha256, **files))
    assert sent["type"] == "result", sent
    frozen = await call(ws, "lock-context", {"session_id": session_id}, frame_id="l")
    assert frozen["type"] == "result", frozen
    return session_id, frozen["payload"]["context_id"]


# --------------------------------------------------------------------------
# The profile a client is told about
# --------------------------------------------------------------------------


async def test_open_session_declares_the_subprocess_profile(client, config) -> None:
    """§1.2's profile, in the field ADR 0019's amendment puts in this answer.

    It is the one thing a client learns about which promises are being
    made to it: no network isolation, no per-session resource limits, no
    container trust boundary. A client that could not see the profile
    would have to infer all three from behaviour.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        payload = await open_session(ws)

    assert payload["negotiated"]["backend_profile"] == "subprocess"


def test_the_profile_is_chosen_by_configuration(tmp_path) -> None:
    """The operator's switch, in both forms this server's config takes."""
    from mcuhome_buildserver.app import make_backend

    parsed = load_config(["--backend-profile", "subprocess"], env={})
    assert parsed.backend_profile == "subprocess"
    assert make_backend(parsed).profile == "subprocess"

    from_env = load_config([], env={"MCUHOME_BUILDSERVER_BACKEND_PROFILE": "subprocess"})
    assert from_env.backend_profile == "subprocess"

    # The default is the profile with the guarantees, because a profile
    # that makes none of them is a deliberate choice and never one an
    # operator inherits.
    assert load_config([], env={}).backend_profile == "container"
    assert make_backend(load_config([], env={})).profile == "container"

    with pytest.raises(SystemExit):
        load_config([], env={"MCUHOME_BUILDSERVER_BACKEND_PROFILE": "in-process"})


async def test_capabilities_answers_the_one_build_environment_it_serves(client, config) -> None:
    """One entry per served Zephyr line, and an honest label block.

    ADR 0019 §2 asks ``capabilities`` for "available builder images"; in
    this profile there is no image, but the question a client asks is
    what this server can build, and answering nothing would say nothing
    can be. ``org.mcuhome.toolchain`` is absent because §2.1's coupling
    labels are properties of an image and this backend cannot state the
    toolchain identity of a host it did not build — and §2.1.1's
    "absence is never read as compatible" is the correct reading of that.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        answer = await call(ws, "capabilities", frame_id="c")

    entries = answer["payload"]["containers"]
    assert [entry["labels"]["org.mcuhome.zephyr"] for entry in entries] == [ZEPHYR_LINE]
    entry = entries[0]
    assert entry["digest"] is None
    assert entry["reference"] == "org.mcuhome.build-container:2.4.0"
    assert entry["labels"] == {"org.mcuhome.contract": "1", "org.mcuhome.zephyr": ZEPHYR_LINE}
    assert "org.mcuhome.toolchain" not in entry["labels"]


async def test_a_program_that_cannot_describe_answers_an_empty_inventory(
    client, config, program
) -> None:
    """§7.1: describe "doubles as the first conformance test".

    And the same rule the container backend follows for a runtime it
    cannot reach: the question is what this server can serve, "none" is a
    fact rather than an error, and the refusal belongs to the verb that
    actually needs a build environment.
    """
    program.program = None
    program.describe_status = None
    async with client.ws_connect("/ws", headers=auth()) as ws:
        answer = await call(ws, "capabilities", frame_id="c")
        sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
        session_id = (await open_session(ws))["session"]["id"]
        refused = await send_archive(ws, "send-context", session_id, buildable_context(sha256))

    assert answer["payload"]["containers"] == []
    assert refused["type"] == "error"
    assert refused["error"]["code"] == "version.builder-unavailable"


# --------------------------------------------------------------------------
# The invocation: argv, environment, the request document
# --------------------------------------------------------------------------


async def test_a_build_runs_end_to_end_with_no_container_anywhere(
    client, config, docker, program
) -> None:
    """open → send → lock → build → verdict → get-artifact → close.

    The whole session, through the subprocess profile, against the real
    server app — and with the docker fake untouched at the end, which is
    the profile's entire promise about what it needs: nothing.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, context_id = await locked(ws, config, **{"model/device-model.json": MODEL})
        started = await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")
        announced = await call(
            ws,
            "get-artifact",
            {"session_id": session_id, "invocation_id": started["payload"]["invocation_id"]},
            frame_id="g",
        )
        while True:
            frame = await ws.receive()
            if frame.type.name == "BINARY":
                break
        closed = await call(ws, "close-session", {"session_id": session_id}, frame_id="x")

    verdict = frames[-1]["payload"]
    assert verdict["status"] == "success"
    assert verdict["context"] == context_id
    assert {entry["path"] for entry in verdict["artifacts"]} == {
        "firmware.hex",
        "firmware.bin",
        "build-report.json",
    }
    assert announced["type"] == "result"
    assert closed["payload"]["session"]["state"] == "closed"
    # The point of the profile, asserted rather than assumed.
    assert docker.calls == []
    assert program.invocations[-1].action == "build"


async def test_the_invocation_is_two_positional_operands_and_never_a_flag(
    client, config, program
) -> None:
    """§5.1, in the profile where the program's path is the backend's.

    ``<program> <action> <absolute path of the request document>``. The
    default program is the installed compiler through this server's own
    interpreter — ``sys.executable`` and not ``python3`` on ``PATH``,
    because a server in a virtual environment must reach *its own*
    compiler.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        await collect(ws, until="invocation.verdict")

    argv = program.invocations[-1].argv
    assert argv[:3] == [sys.executable, "-m", "mcuhome.compiler.abi"]
    assert argv[3] == "verify"
    assert Path(argv[4]).is_absolute()
    assert len(argv) == 5
    assert not [item for item in argv[3:] if item.startswith("-")]


async def test_a_configured_program_is_invoked_as_itself(tmp_path, config) -> None:
    """§2.2: "only the path is the backend's business".

    No interpreter in front of it and nothing looked up on ``PATH``: a
    third party may ship a compiled binary, and a Python interpreter this
    server chose would make MCUHome's implementation language a
    requirement on a program the contract lets anyone write.
    """
    from mcuhome_buildserver.program import invocation_command, program_argv

    argv = program_argv(tmp_path / "run")
    assert argv == (str(tmp_path / "run"),)
    assert invocation_command(argv, "build", tmp_path / "request.json") == [
        str(tmp_path / "run"),
        "build",
        str(tmp_path / "request.json"),
    ]
    assert load_config(["--program", str(tmp_path / "run")], env={}).program == tmp_path / "run"


async def test_the_environment_is_stated_and_never_implicitly_inherited(
    client, config, state, program
) -> None:
    """§6.1: the program assembles its build environment, the backend states one.

    The child is started with an explicit environment rather than by
    inheritance, and in this profile the honest statement is this
    process's own: the build environment **is** this filesystem, so the
    ``PATH`` the toolchain is reachable through is the server's.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    # Stated once, when the program object was built, and handed over
    # whole: the environment a child gets is the one this server declared
    # for it and never whatever `os.environ` happens to say at the moment
    # the child starts. (`os.environ` itself moves under a test runner —
    # pytest rewrites PYTEST_CURRENT_TEST per phase — which is precisely
    # the class of surprise a stated environment removes.)
    declared = state.backend.program.env
    assert declared["PATH"] == os.environ["PATH"]
    for stated in program.environments:
        assert stated == declared
    # A copy and not the mapping itself: nothing the server does to its
    # own environment later may reach a child it already promised
    # something else.
    assert declared is not os.environ
    assert isinstance(declared, dict)


async def test_the_stated_environment_leaves_this_servers_own_secrets_behind(
    aiohttp_client, config, program, monkeypatch
) -> None:
    """§5.1: "no environment variable carries information the program needs".

    So the statement is composed and not copied, and the one thing that
    must provably not be in it is this server's bearer token — which
    ``config.py`` reads from ``MCUHOME_BUILDSERVER_TOKEN`` and whose own
    help text recommends that channel over a command line. A copied
    environment would put it in ``/proc/<pid>/environ`` of west, ninja
    and every compiler child, and into the raw log stream (§8) of any
    build step that prints its environment — a stream a client may
    persist or export.

    The container profile never had to decide this: ``docker exec``
    passes no ``-e``, so the server's environment reaches the docker
    client and stops there.
    """
    marker = "mcuhome-secret-8f3c1d"
    monkeypatch.setenv("MCUHOME_BUILDSERVER_TOKEN", marker)
    monkeypatch.setenv("MCUHOME_BUILDSERVER_TOKEN_FILE", f"/run/{marker}")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", marker)
    monkeypatch.setenv("ZEPHYR_SDK_INSTALL_DIR", "/opt/zephyr-sdk")

    state = ServerState(config)
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    assert program.environments, "the program was never started"
    for stated in program.environments:
        assert marker not in stated.values()
        assert not [name for name in stated if name.startswith("MCUHOME_BUILDSERVER_")]
        # What makes this filesystem a build environment does travel:
        # dropping it would be the opposite failure, a program that
        # cannot find the toolchain it is supposed to run.
        assert stated["PATH"] == os.environ["PATH"]
        assert stated["ZEPHYR_SDK_INSTALL_DIR"] == "/opt/zephyr-sdk"


async def test_limits_jobs_reaches_the_request_document(aiohttp_client, config, program) -> None:
    """§5.2: ``limits.jobs`` is authoritative and mandatory for a working action.

    It is the one limit this profile can keep and therefore the one it
    must pass through: "in the ``subprocess`` profile the program runs
    directly on a shared host, so ``nproc`` reports the whole machine,
    and several concurrent sessions at ``nproc`` jobs each is an
    out-of-memory kill".
    """
    from dataclasses import replace

    state = ServerState(replace(config, build_jobs=3))
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    limits = program.invocations[-1].request["limits"]
    assert limits["jobs"] == 3
    # `memory_bytes` is absent in both profiles and for two different
    # reasons. Here it is the blunter one: there is no cgroup behind it,
    # so a number would be a promise nothing keeps.
    assert "memory_bytes" not in limits


async def test_no_limit_this_profile_cannot_keep_is_promised(client, config, program) -> None:
    """The reduced promises of §1.2, measured on what is actually sent.

    The operator's ``--container-*`` settings are container flags; this
    profile has no container and does not quietly reinterpret them as
    something else.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    request = program.invocations[-1].request
    assert set(request["limits"]) == {"jobs", "deadline_seconds", "cancel_grace_seconds"}
    # The deadline is kept because this server enforces it itself (§9.1),
    # and the cancel grace because the sentinel is this profile's too.
    assert request["limits"]["deadline_seconds"] == config.build_deadline_seconds
    assert request["cancel"].endswith("/cancel")


# --------------------------------------------------------------------------
# Trees: what this backend owns, and what it will not pretend to own
# --------------------------------------------------------------------------


async def test_the_sdk_is_the_only_tree_and_lives_in_the_session_directory(
    client, config, state, program
) -> None:
    """§4.1: ``sdk`` is supplied for every working action, and nothing else has to be.

    It sits at the per-session path it was unpacked into — no mount, no
    fixed path — which is what keeps two concurrent sessions apart in one
    filesystem namespace (§1.2).
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")
        paths = state.sessions.require(session_id).paths

    trees = program.invocations[-1].request["trees"]
    assert list(trees) == ["sdk"]
    assert trees["sdk"] == {"path": str(paths.sdk), "writable": False}
    assert Path(trees["sdk"]["path"]).is_relative_to(paths.root)


async def test_a_patched_sdk_is_handed_over_writable(client, config, program) -> None:
    """§6.2, and the one writable view this backend can construct for free.

    The SDK is unpacked per session and dies with the session, so a
    per-session copy **is** the writable view — no overlay, no second
    copy, and nothing that can outlive the session that patched it.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"patches/sdk/0001-x.patch": PATCH})
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    request = program.invocations[-1].request
    assert request["trees"]["sdk"]["writable"] is True
    assert request["required"] == ["/params/mode", "/trees/sdk"]


async def test_a_patched_persistent_layer_gets_no_tree_entry(client, config, program) -> None:
    """The reduced promise this profile has to state rather than fake.

    §6.2 makes the writable view of a patched layer the backend's to
    construct here — "a copy-on-write overlay on the host … or a copy as
    the conforming fallback" — and this backend constructs neither. So it
    names no entry, which is exactly the shape the container backend's
    own non-rule produces for a layer no path is known for: the pointer
    still goes into ``required``, and a conforming program refuses before
    it does any work.

    Asserting ``writable: true`` for the host's shared Zephyr instead
    would leak one session's patches into every later build on this host.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"patches/zephyr/0001-x.patch": PATCH})
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await collect(ws, until="invocation.verdict")

    request = program.invocations[-1].request
    assert "zephyr" not in request["trees"]
    assert "/trees/zephyr" in request["required"]


async def test_the_refusal_for_a_patched_persistent_layer_is_unsupported_required(
    client, config, program
) -> None:
    """The reason a conforming program actually gives, not the one it would.

    ``error.layer.unknown`` is what §6.2 defines for "``patches/<layer>/``
    for a layer it has no ``trees`` entry for" — but a conforming program
    never reaches that scan here, because this server also puts
    ``/trees/<layer>`` into the request's ``required`` list, and §5.2
    rule 2 makes a ``required`` pointer the program cannot honour a
    refusal it must make while *parsing*: ``unsupported.required``, with
    the pointer in ``error.details.required``.

    Both map to ``builder.failed`` in this server's reason table, so the
    wire hides the difference and only the ``reason`` shows it — which is
    exactly the string a client matches on and an operator greps the log
    for, and therefore the one this profile's docs must name.
    """

    def refuses_the_pointer(action, request, on_line):
        unhonourable = [
            pointer
            for pointer in request.get("required", ())
            if pointer.startswith("/trees/")
            and pointer.removeprefix("/trees/") not in request["trees"]
        ]
        write_result(
            request,
            {
                "result": 1,
                "status": "unsupported",
                "action": action,
                "session": request["session"],
                "reason": "unsupported.required",
                "error": {
                    "retryable": False,
                    "message": "no tree was supplied for a pointer this invocation must honour",
                    "details": {"required": unhonourable},
                },
            },
        )
        return FakeProcess(1)

    program.run_program = refuses_the_pointer
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"patches/zephyr/0001-x.patch": PATCH})
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")

    verdict = frames[-1]["payload"]
    assert verdict["status"] == "unsupported"
    assert verdict["error"]["code"] == "builder.failed"
    assert verdict["error"]["details"]["reason"] == "unsupported.required"
    assert verdict["error"]["details"]["container_details"] == {"required": ["/trees/zephyr"]}


async def test_a_program_requiring_a_fixed_sdk_path_cannot_serve_this_profile(
    client, config, program
) -> None:
    """§4's declared tree path, in the backend that cannot satisfy one.

    "A declared path is then a requirement the backend MUST satisfy" —
    and a backend "that cannot give each concurrent session its own view
    of that path cannot use that image. It learns so from ``describe``,
    before it starts a session and before it promises a client
    anything." That is this refusal, at exactly that moment.
    """
    program.program = json.loads(json.dumps(PROGRAM))
    program.program["trees"]["sdk"] = {"path": "/mcuhome/workspace/mcuhome"}
    async with client.ws_connect("/ws", headers=auth()) as ws:
        sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
        session_id = (await open_session(ws))["session"]["id"]
        refused = await send_archive(ws, "send-context", session_id, buildable_context(sha256))

    assert refused["type"] == "error"
    assert refused["error"]["code"] == "version.builder-unavailable"
    assert "/mcuhome/workspace/mcuhome" in refused["error"]["details"]["problem"]


# --------------------------------------------------------------------------
# One build environment: the line rule of §1.2
# --------------------------------------------------------------------------


async def test_a_context_requiring_another_line_is_refused_typed(client, config) -> None:
    """§1.2: "It MUST reject, typed, any session whose context requires a
    Zephyr line that build environment does not carry."

    A backend with exactly one build environment cannot choose, so it can
    only accept or refuse (ADR 0019's amendment). The refusal is the
    container profile's own code, with the details that let a client act
    without the operator: the line required, and the lines served.
    """
    from tests.conftest import CONTEXT_YAML, make_archive

    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    foreign = (
        CONTEXT_YAML.replace("sha256: " + "a" * 64, f"sha256: {sha256}")
        .replace(f"zephyr: '{ZEPHYR_LINE}'", "zephyr: '9.9'")
        .encode()
    )
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = (await open_session(ws))["session"]["id"]
        refused = await send_archive(
            ws, "send-context", session_id, make_archive({"context.yaml": foreign})
        )

    assert refused["type"] == "error"
    assert refused["error"]["code"] == "version.builder-unsatisfiable"
    assert refused["error"]["retryable"] is False
    assert refused["error"]["details"] == {"required": "9.9", "available": [ZEPHYR_LINE]}


@pytest.mark.parametrize(
    ("declared", "expected"),
    [
        # The two spellings of a release the field actually carries: the
        # contract's (§2.1.1) and west's, which is what `west list`
        # prints and what MCUHome's own workspace record stores. The
        # image's `org.mcuhome.zephyr` label already normalizes the same
        # way — "§2.1.1 asks for the version *without* west's leading v".
        ("4.4.0", ("4.4",)),
        ("v4.4.0", ("4.4",)),
        ("4.4", ("4.4",)),
        # A line this MCUHome release does not itself support. It is
        # still what this build environment says it carries, and this is
        # the assertion that says the answer is read off the program and
        # not off the `mcuhome-model` package installed beside the
        # server — whose SUPPORTED_ZEPHYR_LINES is ("4.4",).
        ("v4.3.0", ("4.3",)),
        # Revisions that name no release. A pre-release satisfies no line
        # including its own (§2.1.1), and a branch or a commit is not a
        # version at all — so nothing is served, because absence is never
        # read as compatible and neither is a guess.
        ("v4.5.0-rc1", ()),
        ("main", ()),
        ("c0ffee1234567890abcdef1234567890abcdef12", ()),
        ("", ()),
        (None, ()),
    ],
)
def test_the_served_line_is_read_off_the_program_and_not_off_this_server(
    declared, expected
) -> None:
    """§1.2's line, discovered from ``describe`` and from nowhere else.

    ``program.trees.zephyr.version`` is the build environment's own
    statement about the tree it carries (§7.1.1). A constant in a package
    installed beside the *server* describes the server, which is only the
    same thing while the program is the default one — and ``--program``
    (§2.2) exists precisely so that it need not be.
    """
    from mcuhome.model.toolchain import SUPPORTED_ZEPHYR_LINES

    from mcuhome_buildserver.subprocessbackend import HostProfile, served_lines

    block = json.loads(json.dumps(PROGRAM))
    if declared is None:
        block["trees"]["zephyr"].pop("version", None)
    else:
        block["trees"]["zephyr"]["version"] = declared
    assert served_lines(HostProfile(program=block)) == expected
    # The point of the parametrization, stated: one of the cases above
    # is a line this server's own package does not know, and it is
    # served anyway.
    assert SUPPORTED_ZEPHYR_LINES == ("4.4",)


async def test_a_program_over_another_zephyr_line_serves_that_line(client, config, program) -> None:
    """The configured-program case, end to end over the socket.

    An operator points ``--program`` at a third party's build
    environment carrying Zephyr 4.3. The server must advertise 4.3 and
    refuse this suite's 4.4 context — where the old constant would have
    advertised 4.4, accepted the context and frozen a manifest naming
    that program as what satisfied it.
    """
    program.program = json.loads(json.dumps(PROGRAM))
    program.program["trees"]["zephyr"]["version"] = "v4.3.0"
    async with client.ws_connect("/ws", headers=auth()) as ws:
        announced = await call(ws, "capabilities", frame_id="c")
        sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
        session_id = (await open_session(ws))["session"]["id"]
        refused = await send_archive(ws, "send-context", session_id, buildable_context(sha256))

    entries = announced["payload"]["containers"]
    assert [entry["labels"]["org.mcuhome.zephyr"] for entry in entries] == ["4.3"]
    assert refused["type"] == "error"
    assert refused["error"]["code"] == "version.builder-unsatisfiable"
    assert refused["error"]["details"] == {"required": ZEPHYR_LINE, "available": ["4.3"]}


async def test_a_program_carrying_no_zephyr_tree_is_refused_at_discovery(
    client, config, program
) -> None:
    """The ``pip install`` and nothing else host, refused where it is knowable.

    An installed compiler with no west workspace behind it answers
    ``describe`` with every tree ``null`` and no version anywhere — a
    legal answer, and one that says this environment carries no Zephyr.
    §2.1.1's rule for the missing label decides what to make of the
    missing field: absence is never read as compatible. So the inventory
    is empty and ``send-context`` refuses, instead of every build dying
    inside the program after the SDK package has been fetched, hashed and
    unpacked.
    """
    program.program = json.loads(json.dumps(PROGRAM))
    program.program["trees"] = {name: {"path": None} for name in program.program["trees"]}
    async with client.ws_connect("/ws", headers=auth()) as ws:
        announced = await call(ws, "capabilities", frame_id="c")
        sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
        session_id = (await open_session(ws))["session"]["id"]
        refused = await send_archive(ws, "send-context", session_id, buildable_context(sha256))

    assert announced["payload"]["containers"] == []
    assert refused["type"] == "error"
    assert refused["error"]["code"] == "version.builder-unavailable"
    assert "no version for its zephyr tree" in refused["error"]["details"]["problem"]


async def test_the_manifest_records_the_program_as_what_built_it(client, config, state) -> None:
    """§3.2's ``container:`` block, filled by a backend that has no image.

    "The record of which build environment answered this context's
    requirement … what reproduces the build years later." Here that is
    the program's own identity and version, with ``digest: null``,
    because there is no image and therefore nothing that names fetchable
    bytes — the value E61 already made first-class for the never-pushed
    image.
    """
    from ruamel.yaml import YAML

    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config, **{"model/device-model.json": device_model()})
        paths = state.sessions.require(session_id).paths
        manifest = YAML(typ="safe", pure=True).load((paths.context / "manifest.yaml").read_text())

    assert manifest["container"] == {
        "image": "org.mcuhome.build-container",
        "tag": "2.4.0",
        "digest": None,
    }
    assert manifest["zephyr"] == ZEPHYR_LINE


# --------------------------------------------------------------------------
# The child: cancellation, crashes, and two of them at once
# --------------------------------------------------------------------------


async def test_cancelling_reaches_the_child_itself(aiohttp_client, config, program) -> None:
    """§8's ladder, and the rung this profile keeps that the other cannot.

    The sentinel is first and works identically in both profiles — that
    is why the contract chose a file. What differs is the rung behind it:
    here SIGTERM goes to the program, not to a ``docker exec`` client
    that never passed it on. §1.2's "cancellability … remain[s]" is this.
    """
    from dataclasses import replace

    children: list[FakeProcess] = []

    def hangs(action, request, on_line):
        children.append(FakeProcess(0, hang=True))
        return children[-1]

    program.run_program = hangs
    state = ServerState(replace(config, cancel_grace_seconds=0))
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        await call(ws, "cancel", {"session_id": session_id, "invocation_id": "inv-1"}, frame_id="c")
        frames = await collect(ws, until="invocation.verdict")
        sentinel = state.sessions.require(session_id).paths.invocation("inv-1") / "cancel"

    assert sentinel.exists()
    assert children[0].terminated is True
    # No result document was written, so the invocation is the
    # infrastructure failure rather than a verdict on the context.
    assert frames[-1]["payload"]["error"]["code"] == "builder.crashed"


@pytest.mark.parametrize("stubborn", [False, True])
async def test_close_session_stops_a_child_that_is_still_running(
    aiohttp_client, config, program, stubborn
) -> None:
    """This profile's ``docker rm --force``, and it actually reaps.

    ``close-session`` sets the stop signal, then releases the build
    environment, then deletes the tree — and the middle step has to
    reach the build, or a compile keeps running against a directory that
    no longer exists. In the container profile removing the container is
    that step; here the child is this process's own.

    It is a **ladder and not a kill**: SIGTERM first, so that a program
    which stops its own compile gets to (ninja stops its edges on
    SIGTERM, and a build tree that unwinds itself leaves no half-written
    object files), then SIGKILL for whatever is still there when the
    bounded grace runs out. A child that goes away on the first rung is
    never killed; one that ignores it always is.
    """
    children: list[FakeProcess] = []

    def hangs(action, request, on_line):
        children.append(FakeProcess(0, hang=True, ignores_terminate=stubborn))
        return children[-1]

    program.run_program = hangs
    state = ServerState(config)
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        closed = await call(ws, "close-session", {"session_id": session_id}, frame_id="x")

    assert closed["type"] == "result"
    assert children[0].terminated is True
    assert children[0].killed is stubborn


async def test_a_close_session_racing_the_spawn_still_reaps_the_child(
    aiohttp_client, config, program, monkeypatch
) -> None:
    """The window between "the child exists" and "teardown can see it".

    The handle can only be published after the spawn returns, and
    ``close-session`` is deliberately not serialized against work in
    flight: it pops the runtime, releases it — finding no child, because
    the spawn has not returned yet — and then deletes the session's tree.
    A child started into that window would be a build against a deleted
    directory that this profile's only teardown hook has already walked
    past.

    The race is not simulated here, it is *run*: the seam that starts the
    program calls ``release`` before it hands the handle back, which is
    exactly the interleaving, deterministically.
    """
    state = ServerState(config)
    children: list[FakeProcess] = []
    session_ids: list[str] = []

    async def releases_while_spawning(argv, *, on_line, env):
        children.append(FakeProcess(0, hang=True))
        # close-session's own teardown path, at the one instant the
        # runtime holds no child yet.
        await state.backend.release(session_ids[0])
        return children[-1]

    monkeypatch.setattr(program_seam, "spawn_program", releases_while_spawning)
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, state.config)
        session_ids.append(session_id)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        # Not `collect`: `release` took this connection out of the
        # session's audience along with the runtime, so the verdict has
        # nobody left to reach. What is waited on is the kill itself.
        await until_true(lambda: bool(children) and children[0].killed)

    assert len(children) == 1
    assert children[0].killed is True


async def test_a_crash_without_a_result_document_is_a_failed_invocation(
    client, config, program
) -> None:
    """§9.1: "an ``out`` directory without a result document at ``result``
    is a failed invocation by definition".

    ``builder.crashed`` and retryable, because it is an infrastructure
    failure rather than a verdict on the context — a segfault or an
    out-of-memory kill of a child process, which is precisely the case
    this profile is a subprocess for.
    """
    program.run_program = lambda action, request, on_line: FakeProcess(139)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id, _ = await locked(ws, config)
        await call(ws, "build", {"session_id": session_id}, frame_id="b")
        frames = await collect(ws, until="invocation.verdict")

    verdict = frames[-1]["payload"]
    assert verdict["status"] == "failure"
    assert verdict["error"]["code"] == "builder.crashed"
    assert verdict["error"]["retryable"] is True
    assert verdict["error"]["details"]["exit_code"] == 139


async def test_two_concurrent_sessions_do_not_collide_in_one_filesystem(
    client, config, program
) -> None:
    """§1.2: "several concurrent sessions live side by side in one
    namespace and cannot all have the same context, work or output
    directory".

    Two sessions on two sockets, overlapping in time, and every path
    either of them is handed is its own — which is the reason contract v1
    defines no mount points at all (§4).
    """
    async with (
        client.ws_connect("/ws", headers=auth()) as first,
        client.ws_connect("/ws", headers=auth()) as second,
    ):
        one, _ = await locked(first, config)
        two, _ = await locked(second, config)
        assert one != two
        await call(first, "build", {"session_id": one}, frame_id="b1")
        await call(second, "build", {"session_id": two}, frame_id="b2")
        first_frames = await collect(first, until="invocation.verdict")
        second_frames = await collect(second, until="invocation.verdict")

    assert first_frames[-1]["payload"]["status"] == "success"
    assert second_frames[-1]["payload"]["status"] == "success"
    requests = [entry.request for entry in program.invocations]
    assert len(requests) == 2
    for field_name in ("context", "out", "work", "tmp", "result", "events", "cancel"):
        named = {request[field_name] for request in requests}
        assert len(named) == 2, f"{field_name} collided between two sessions"
    assert {request["trees"]["sdk"]["path"] for request in requests} == {
        requests[0]["trees"]["sdk"]["path"],
        requests[1]["trees"]["sdk"]["path"],
    }
    assert requests[0]["trees"]["sdk"]["path"] != requests[1]["trees"]["sdk"]["path"]


# --------------------------------------------------------------------------
# The tests that start real processes
# --------------------------------------------------------------------------

#: A child that starts a child of its own and then sleeps: the shape of
#: this profile's real invocation, three levels deep. The program is not
#: the build — it is what runs west, which runs ninja, which runs the
#: compilers — and every level below the first inherits the merged log
#: pipe (§8), exactly as a program using ``cmd.Stdout = os.Stdout`` would.
#: ``{pidfile}`` receives the grandchild's pid, ``{last}`` is what the
#: middle process does after it has started one.
_THREE_LEVELS = (
    "import pathlib, subprocess, sys, time;"
    "grandchild = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)']);"
    "pathlib.Path({pidfile!r}).write_text(str(grandchild.pid));"
    "print('running', flush=True);"
    "{last}"
)


async def test_spawn_program_really_starts_a_child_and_a_kill_ends_it(tmp_path) -> None:
    """The plumbing under the seam, with a real child and no server.

    The whole argument for this profile being a subprocess rather than an
    in-process call is that a build can be stopped without taking the
    server with it (§1.2, ADR 0019). A fake that records ``kill()``
    cannot show that, so this one runs a real interpreter: it streams a
    line of its merged output, it stays addressable, and killing it ends
    it with a non-zero status while this process carries on.

    It calls :func:`~mcuhome_buildserver.processes.spawn_command`, which
    is the whole body of :func:`~mcuhome_buildserver.program.spawn_program`
    — the seam itself is stubbed for every test in this module, and a
    test that undid that stub to prove one thing would take the guard off
    for the rest.
    """
    lines: list[str] = []
    marker = tmp_path / "started"
    child = await processes.spawn_command(
        [
            sys.executable,
            "-c",
            f"import pathlib,sys,time;print('hello');sys.stdout.flush();"
            f"pathlib.Path({str(marker)!r}).write_text('x');time.sleep(30)",
        ],
        on_line=lines.append,
        env=program_seam.stated_environment(),
    )
    assert await until_true(marker.exists)
    child.kill()
    status = await child.wait()

    assert status != 0
    assert lines == ["hello"]


async def test_a_kill_reaches_the_grandchild_and_not_only_the_program(tmp_path) -> None:
    """The defect this profile's one promise stands or falls on.

    In the ``subprocess`` profile the immediate child is the program, and
    the program is not the compile: it starts west, which starts cmake,
    which starts ninja, which starts the compilers. A signal to that one
    pid leaves the whole tree running — reparented to init, unreaped,
    writing into a session directory ``close-session`` is about to delete,
    on a host that by §1.2 has no per-session memory, CPU or PID ceiling.

    So this test is three levels deep, which is the only depth at which
    the difference is visible: a leaf process cannot fail this assertion.
    The fix is one property of :func:`spawn_command` — the child is a
    session leader, so its pid is a process-group id — and one of
    ``ChildProcess``: every signal goes to that group.
    """
    lines: list[str] = []
    pidfile = tmp_path / "grandchild.pid"
    grandchild: int | None = None
    child = await processes.spawn_command(
        [sys.executable, "-c", _THREE_LEVELS.format(pidfile=str(pidfile), last="time.sleep(300)")],
        on_line=lines.append,
        env=program_seam.stated_environment(),
    )
    try:
        grandchild = await read_pid(pidfile)
        assert alive(grandchild)

        child.kill()
        status = await asyncio.wait_for(child.wait(), REAL_PROCESS_TIMEOUT)

        assert status != 0
        assert await until_true(lambda: not alive(grandchild)), (
            "the grandchild outlived the kill: the signal reached the program and not the build"
        )
    finally:
        reap(grandchild)


async def test_stop_walks_the_ladder_over_the_whole_group(tmp_path) -> None:
    """Teardown's own escalation, on a real group: SIGTERM, then SIGKILL.

    ``close-session`` calls this and then deletes the session's tree, so
    what it has to end is the tree of processes and not the entry point.
    SIGTERM goes first because a program that stops its own compile
    should get to — ninja stops its edges on SIGTERM — and the group is
    signalled because the program is not what is compiling.

    The middle process here exits on SIGTERM while its grandchild ignores
    it, which is the ordinary shape of a build tree: what proves the
    second rung fired on the *group* is the grandchild being gone, since
    nothing else in this test ever addresses it.
    """
    lines: list[str] = []
    pidfile = tmp_path / "grandchild.pid"
    grandchild: int | None = None
    child = await processes.spawn_command(
        [
            sys.executable,
            "-c",
            "import signal;signal.signal(signal.SIGTERM, signal.SIG_IGN);"
            + _THREE_LEVELS.format(pidfile=str(pidfile), last="time.sleep(300)"),
        ],
        on_line=lines.append,
        env=program_seam.stated_environment(),
    )
    try:
        grandchild = await read_pid(pidfile)

        await asyncio.wait_for(child.stop(), REAL_PROCESS_TIMEOUT)
        status = await asyncio.wait_for(child.wait(), REAL_PROCESS_TIMEOUT)

        assert status == -signal.SIGKILL
        assert await until_true(lambda: not alive(grandchild))
    finally:
        reap(grandchild)


async def test_wait_answers_when_a_descendant_still_holds_the_log_pipe(
    tmp_path, monkeypatch, caplog
) -> None:
    """The invocation ends when the child does, not when the pipe closes.

    The log pump ends on EOF, and EOF needs every write end of the pipe
    closed — which a descendant that inherited the child's stdout does
    not do when the child exits. Awaiting the pump *before* the exit
    status therefore made an invocation whose child is provably dead
    unfinishable: the supervisor spins, ``runtime.busy`` is never
    cleared, the session refuses every further invocation and no
    ``invocation.verdict`` is ever published. §8 anticipates exactly this
    program — "a Go implementer writing the idiomatic ``cmd.Stdout =
    os.Stdout``" — and §2.2 sanctions it in any language.

    The grace is shortened here rather than waited out: what is under
    test is that it is *bounded*, and the number itself is policy.
    """
    monkeypatch.setattr(processes, "_PUMP_GRACE_SECONDS", 0.2)
    lines: list[str] = []
    pidfile = tmp_path / "grandchild.pid"
    grandchild: int | None = None
    child = await processes.spawn_command(
        # The middle process exits at once and its grandchild keeps the
        # inherited pipe open for five minutes.
        [sys.executable, "-c", _THREE_LEVELS.format(pidfile=str(pidfile), last="sys.exit(7)")],
        on_line=lines.append,
        env=program_seam.stated_environment(),
    )
    try:
        grandchild = await read_pid(pidfile)

        status = await asyncio.wait_for(child.wait(), REAL_PROCESS_TIMEOUT)

        assert status == 7
        assert "running" in lines
        assert alive(grandchild), "the grandchild was meant to outlive its parent here"
        # The operator is told, because a pipe still held after its owner
        # died is the state the process group exists to prevent.
        assert any("log pipe is still held" in record.message for record in caplog.records)
    finally:
        reap(grandchild)
