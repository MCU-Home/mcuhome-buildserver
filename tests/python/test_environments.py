# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Which build environments this server runs, and when it decides that.

The allowlist is the one gate here that is not a conformance check, and
it exists because every conformance check costs a network round trip or a
container: reading an image's labels means asking a registry, and running
it costs a container start. A repository name is a string anybody can
publish under.

So these tests assert two things above all: that an unlisted repository
is refused, and that it is refused **before anything else is asked at
all** — the second being the whole point of the first.

**A build context never names an image.** It pins the environment's
*packages* (workspace and tools, by name, version and hash), and this
server finds the image that delivers that set. The only per-build
override a client has is the ``container_image`` field of ``send-context``
itself — never a value inside the context — so every test here that wants
to name an image states it there.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from mcuhome.buildserver import environments, sessions
from mcuhome.buildserver.app import ServerState, create_app
from mcuhome.buildserver.config import load_config
from mcuhome.buildserver.errors import SessionError
from tests.python.conftest import (
    BUILD_CONTEXT_BYTES,
    ENVIRONMENT_DENIED,
    IMAGE,
    IMAGE_DIGEST,
    IMAGE_LABELS,
    auth,
    call,
    context_yaml,
    make_archive,
    refused_with,
    send_archive,
    write_sdk_package,
)

ELSEWHERE = "registry.example.test/somebody/else"


def mcuhome_context(sha256: str) -> bytes:
    """A context pinning MCUHome's own package set — the ordinary one."""
    return make_archive(
        {
            "build-context.json": BUILD_CONTEXT_BYTES,
            "context.yaml": context_yaml(sdk_sha256=sha256),
        }
    )


async def open_session(ws) -> str:
    frame = await call(
        ws, "open-session", {"protocol_version": sessions.SESSION_PROTOCOL_VERSION}, frame_id="o"
    )
    return frame["payload"]["session"]["id"]


# --------------------------------------------------------------------------
# The check itself
# --------------------------------------------------------------------------


def test_a_listed_repository_passes_whatever_tag_or_digest_it_carries() -> None:
    """The list holds repositories, so the moving parts of a reference are not compared."""
    for reference in (
        IMAGE,
        f"{IMAGE}:zephyr-4.4.0-r10",
        f"{IMAGE}@{IMAGE_DIGEST}",
        f"{IMAGE}:zephyr-4.4.0-r10@{IMAGE_DIGEST}",
    ):
        environments.check_allowed(reference, allowed=(IMAGE,), what="the context")


def test_an_unlisted_repository_is_refused_and_the_refusal_names_the_list() -> None:
    """A refusal an operator can act on: what was asked for, and what is served."""
    with pytest.raises(SessionError) as excinfo:
        environments.check_allowed(
            f"{ELSEWHERE}@{IMAGE_DIGEST}", allowed=(IMAGE,), what="the context"
        )
    error = excinfo.value
    assert error.code == "policy.environment-denied"
    assert error.details["repository"] == ELSEWHERE
    assert error.details["allowed"] == [IMAGE]


def test_docker_hubs_two_spellings_are_one_repository() -> None:
    """``busybox`` and ``docker.io/library/busybox`` name the same thing.

    An operator's list would otherwise mean whichever of the two they
    happened to type, which is exactly the kind of near-miss an
    allowlist must not have.
    """
    environments.check_allowed(
        "busybox:latest", allowed=("docker.io/library/busybox",), what="the context"
    )


def test_there_are_no_wildcards() -> None:
    """``ghcr.io/*`` would read as "our images" and mean "everybody's"."""
    with pytest.raises(SessionError):
        environments.check_allowed(
            "ghcr.io/somebody/else", allowed=("ghcr.io/*",), what="the context"
        )


def test_a_reference_that_does_not_parse_is_refused_as_itself() -> None:
    """Quoting a normalization of a broken name back at its author helps nobody."""
    with pytest.raises(SessionError) as excinfo:
        environments.check_allowed("NOT A REFERENCE", allowed=(IMAGE,), what="the context")
    assert excinfo.value.details["repository"] == "NOT A REFERENCE"


# --------------------------------------------------------------------------
# The configuration
# --------------------------------------------------------------------------


def test_the_default_list_is_mcuhomes_own_build_environment() -> None:
    """A server nobody configured serves the images it exists to run, and no others."""
    assert load_config(["--token", "x" * 32], env={}).allowed_environments == (IMAGE,)


def test_stating_the_option_replaces_the_default_rather_than_adding_to_it() -> None:
    """An operator who lists their own images must be able to stop serving ours."""
    config = load_config(["--token", "x" * 32, "--allow-environment", ELSEWHERE], env={})
    assert config.allowed_environments == (ELSEWHERE,)


def test_the_option_refuses_a_tag_or_a_digest() -> None:
    for entry in (f"{IMAGE}:zephyr-4.4.0-r10", f"{IMAGE}@{IMAGE_DIGEST}"):
        with pytest.raises(SystemExit):
            load_config(["--token", "x" * 32, "--allow-environment", entry], env={})


def test_the_option_wants_the_registry_named() -> None:
    """Silently normalizing would make the list read back differently than it compares."""
    with pytest.raises(SystemExit):
        load_config(["--token", "x" * 32, "--allow-environment", "other/environment"], env={})


def test_auto_pull_is_on_by_default_and_switchable_both_ways() -> None:
    assert load_config(["--token", "x" * 32], env={}).auto_pull is True
    assert load_config(["--token", "x" * 32, "--no-auto-pull"], env={}).auto_pull is False
    assert (
        load_config(["--token", "x" * 32], env={"MCUHOME_BUILDSERVER_AUTO_PULL": "no"}).auto_pull
        is False
    )


# --------------------------------------------------------------------------
# Over the wire: where the gate sits
# --------------------------------------------------------------------------


async def test_a_send_context_naming_an_unlisted_repository_is_refused(
    client, config, docker
) -> None:
    """The client's own spelling, checked at ``send-context``.

    A build context pins packages and never an image (build environment
    specification §4), so the one thing a client can name here is the
    ``container_image`` field of ``send-context`` itself — never a value
    inside the context, which would change nothing about what is being
    built and everything about which bytes it is built in.
    """
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(
            ws,
            "send-context",
            session_id,
            mcuhome_context(sha256),
            container_image=f"{ELSEWHERE}@{IMAGE_DIGEST}",
        )
    assert refused_with(frame, ENVIRONMENT_DENIED)
    assert frame["error"]["details"]["repository"] == ELSEWHERE


async def test_the_refusal_happens_before_docker_is_asked_anything(client, config, docker) -> None:
    """The load-bearing assertion of this file.

    Reading an image's labels means asking a registry, and running one
    means starting a container — a gate that sat after either would
    decide whether a stranger's image may execute *by asking about it or
    running it*. Nothing may reach the runtime first, which is why the
    assertion is on the whole call list and not on a subset of it.
    """
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(
            ws,
            "send-context",
            session_id,
            mcuhome_context(sha256),
            container_image=f"{ELSEWHERE}@{IMAGE_DIGEST}",
        )
    assert refused_with(frame, ENVIRONMENT_DENIED)
    assert docker.calls == []


async def test_an_operator_who_lists_another_repository_can_serve_it(
    aiohttp_client, config, docker, registry
) -> None:
    """The other direction: the list decides, not the repository MCUHome ships.

    The image is found by its labels, in whichever repositories the
    operator searches — here, one that is not MCUHome's own — and this
    host already has the exact bytes the search settles on, so the build
    is served rather than fetched.
    """
    registry.repositories = {ELSEWHERE: IMAGE_LABELS}
    docker.images[f"{ELSEWHERE}@{IMAGE_DIGEST}"] = {"Id": "sha256:" + "c" * 64}
    state = ServerState(replace(config, allowed_environments=(ELSEWHERE,)))
    client = await aiohttp_client(create_app(state))
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, mcuhome_context(sha256))
    assert frame["type"] == "result", frame
    served = frame["payload"]["container"]["build_environment"]
    assert served.startswith(f"{ELSEWHERE}:") and served.endswith(f"@{IMAGE_DIGEST}"), served
