# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""What a context can make this server execute, which is one thing.

This server puts a *build* library — the workbench's orchestrator —
inside a network service, and the obvious question about that
arrangement is whether a context can reach the host through it. By
design it cannot: everything a build context is executed *by* has
already been executed before the context exists (the client creates and
locks it), and what reaches this server is data — a model to hash, keys
to copy, patch files to mount. The orchestrator's whole job here is to
start container commands.

By design is not a test, which is why these are here. They assert the
property from the outside: the only executable a context can select is a
build environment its operator allowed, and nothing a context *contains*
ever becomes part of a command this server runs.

**A context never names an image, not even that one.** It pins the
environment's packages — workspace and tools, by name, version and hash
— and this server finds the delivering image itself. The one thing a
client can still choose is stated outside the context entirely, in the
``container_image`` field of ``send-context``, which is why the allowlist
test below states its forbidden repository there and not in a context
file.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from mcuhome.workbench.containerbuild import ENTRY_POINT_PATH

from mcuhome.buildserver import sessions
from mcuhome.buildserver.app import ServerState, create_app
from tests.python.conftest import (
    BUILD_CONTEXT_BYTES,
    ENVIRONMENT_DENIED,
    IMAGE,
    IMAGE_REFERENCE,
    IMAGE_RUNNABLE,
    auth,
    call,
    collect,
    context_yaml,
    make_archive,
    refused_with,
    send_archive,
    write_sdk_package,
)

#: Strings planted in a context, each somewhere a naive implementation
#: might pass a value through to a command line.
MARKERS = {
    "device": "pwned-device-name",
    "board": "nrf7002dk/nrf5340/cpuapp; touch /tmp/pwned",
    "patch": "$(touch /tmp/pwned)",
    "key": "-----BEGIN PUBLIC KEY-----\n`touch /tmp/pwned`\n",
}


async def open_session(ws) -> str:
    frame = await call(
        ws, "open-session", {"protocol_version": sessions.SESSION_PROTOCOL_VERSION}, frame_id="o"
    )
    return frame["payload"]["session"]["id"]


def hostile_model() -> bytes:
    """A device model whose every free-text field carries a marker."""
    return json.dumps(
        {
            "model_version": 2,
            "device": {
                "name": MARKERS["device"],
                "friendly_name": "$(id)",
                "board": MARKERS["board"],
                "power_source": "mains",
            },
            "network": {"transport": "thread", "matter_enabled": True},
            "toolchain": {
                "zephyr_line": "4.4",
                "zephyr_constraint": "~=4.4.0",
                "blob_usage": "auto",
                "blobs": {},
            },
            "sources": {"sdk": "sdk/mcuhome-sdk", "build_environment": "; rm -rf /"},
            "hardware": {"buses": [], "peripherals": []},
            "endpoints": [],
            "channels": [],
            "build": {"snippets": ["--privileged"], "kconfig": []},
        }
    ).encode()


def hostile_context(sha256: str) -> bytes:
    return make_archive(
        {
            "build-context.json": BUILD_CONTEXT_BYTES,
            "context.yaml": context_yaml(sdk_sha256=sha256),
            "model/device-model.json": hostile_model(),
            "keys/signing.pub": MARKERS["key"].encode(),
            "patches/sdk/0001-x.patch": f"--- a/x\n+++ b/{MARKERS['patch']}\n".encode(),
        }
    )


@pytest.fixture
async def hostile(aiohttp_client, config):
    """A server that accepts the hostile context, patches and all.

    Patch policy is deny-by-default, so a suite that left it at the
    default would be testing a context this server never unpacked — and
    a patch file's *path* is one of the places a value could plausibly
    reach a command line.
    """
    state = ServerState(replace(config, allowed_patch_layers=("sdk",)))
    return await aiohttp_client(create_app(state))


async def test_no_marker_from_a_context_ever_reaches_a_command(hostile, config, docker) -> None:
    """The load-bearing one.

    A context is data on this side: a model to hash, keys to copy, patch
    files to put where a program will read them. None of it is a value
    this server interpolates into anything it runs, and the way to keep
    that true is to look at every argv after a whole build.
    """
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    async with hostile.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        sent = await send_archive(ws, "send-context", session_id, hostile_context(sha256))
        assert sent["type"] == "result", sent
        frozen = await call(ws, "lock-context", {"session_id": session_id}, frame_id="l")
        assert frozen["type"] == "result", frozen
        started = await call(ws, "build", {"session_id": session_id}, frame_id="b")
        assert started["type"] == "result", started
        await collect(ws, until="invocation.verdict")

    # The assertion below is only worth anything if a whole build ran: a
    # context that was refused reaches no command line by accident. A
    # build is one `docker run` of the environment's entry point — there
    # is no `docker exec` any more, since generation 3 enters a step by
    # starting one fresh container rather than by reaching into one that
    # is already running.
    assert any(argv[1] == "run" and ENTRY_POINT_PATH in argv for argv in docker.calls), docker.calls

    flattened = "\n".join(" ".join(argv) for argv in docker.calls)
    for name, marker in MARKERS.items():
        assert marker not in flattened, f"the {name} marker reached a command line"


async def test_every_command_is_the_program_the_operator_configured(
    hostile, config, docker
) -> None:
    """And it is the *first* word of every one of them.

    A build names an environment, and that image is started — under the
    allowlist, which is the gate that makes it an operator's decision.
    What a build must never do is choose the **program**: that is
    ``--docker``, and it is the operator's alone.
    """
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    async with hostile.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, hostile_context(sha256))

    assert docker.calls
    assert {argv[0] for argv in docker.calls} == {config.docker}


async def test_nothing_from_a_context_is_ever_run_directly(hostile, config, docker) -> None:
    """Every process this server starts is a container command.

    Not "no shell" — there is no shell anywhere near this — but the
    stronger statement a reader wants: the executable is always the
    container runtime, and what follows it is always one of the runtime's
    own verbs. A context that could reach past that would be a context
    choosing what runs on the host.
    """
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    async with hostile.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, hostile_context(sha256))

    verbs = {argv[1] for argv in docker.calls}
    assert verbs <= {"version", "image", "run", "rm", "pull"}


async def test_the_image_a_build_names_still_has_to_pass_the_allowlist(
    client, config, docker
) -> None:
    """The one thing a build *does* select, and the gate on it.

    A build environment is executable, and this is the one place a build
    can still name one: the ``container_image`` field of ``send-context``.
    A context file cannot — build environment specification §4 has a
    context pin packages, never an image — so unlike the equivalent test
    against the old contract, the forbidden name is stated here as the
    verb's own field rather than smuggled into ``context.yaml``, and the
    refusal is exactly as early either way: before any registry or
    runtime is asked anything.
    """
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    context = make_archive(
        {
            "build-context.json": BUILD_CONTEXT_BYTES,
            "context.yaml": context_yaml(sdk_sha256=sha256),
        }
    )
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(
            ws,
            "send-context",
            session_id,
            context,
            container_image="registry.evil.test/x/y",
        )

    assert refused_with(frame, ENVIRONMENT_DENIED)
    assert docker.calls == [], "and it is refused before the runtime is asked anything"


async def test_a_pinned_environment_is_the_only_executable_input(hostile, config, docker) -> None:
    """Stated as an inventory rather than as prose.

    Everything this server runs is: the configured container runtime,
    with one of its verbs, naming either nothing or the allowlisted image
    the build resolved to.
    """
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    async with hostile.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, hostile_context(sha256))

    images = {
        argument
        for argv in docker.calls
        for argument in argv
        if argument.startswith("ghcr.io/") or argument.startswith("registry.")
    }
    assert images <= {IMAGE_REFERENCE, IMAGE_RUNNABLE, IMAGE}, images
