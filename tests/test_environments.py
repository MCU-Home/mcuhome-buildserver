# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Which build environments this server runs, and when it decides that.

The allowlist is the one gate here that is not a conformance check, and
it exists because every conformance check costs a container: reading an
image's static self-description runs it (``docker run <image> cat …``
does not displace an image's ``ENTRYPOINT``), and ``describe`` runs its
program on purpose. A label is a string in somebody's Dockerfile.

So these tests assert two things above all: that an unlisted repository
is refused, and that it is refused **before docker is asked anything at
all** — the second being the whole point of the first.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from mcuhome.buildserver import environments
from mcuhome.buildserver.app import ServerState, create_app
from mcuhome.buildserver.config import Config, load_config
from mcuhome.buildserver.errors import SessionError
from tests.conftest import (
    IMAGE,
    IMAGE_DIGEST,
    IMAGE_LABELS,
    auth,
    context_yaml,
    make_archive,
    write_sdk_package,
)
from tests.test_backend import open_session, send_archive

ELSEWHERE = "registry.example.test/somebody/else"


def mcuhome_context(sha256: str) -> bytes:
    """A context pinning MCUHome's own build container — the ordinary one."""
    return make_archive({"context.yaml": context_yaml(sdk_sha256=sha256)})


def elsewhere_context(sha256: str) -> bytes:
    """A context pinning a repository no default list carries."""
    return make_archive(
        {
            "context.yaml": context_yaml(
                sdk_sha256=sha256, build_environment=f"{ELSEWHERE}@{IMAGE_DIGEST}"
            )
        }
    )


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


def test_the_default_list_is_mcuhomes_own_build_container() -> None:
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
        load_config(
            ["--token", "x" * 32, "--allow-environment", "mcu-home/build-container"], env={}
        )


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


@pytest.fixture
def config(tmp_path) -> Config:
    """The suite's config, with this file's own image kept off the list."""
    return Config(
        host="127.0.0.1",
        port=0,
        token="test-token-000000000000000000000000",
        pair_file=None,
        context_root=tmp_path / "sessions",
        sdk_sources=(tmp_path / "packages",),
    )


async def test_a_context_pinning_an_unlisted_repository_is_refused(client, config, docker) -> None:
    """The client's own spelling, checked at ``send-context``."""
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    context = elsewhere_context(sha256)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, context)
    assert frame["error"]["code"] == "policy.environment-denied"
    assert frame["error"]["details"]["repository"] == ELSEWHERE


async def test_the_refusal_happens_before_docker_is_asked_anything(client, config, docker) -> None:
    """The load-bearing assertion of this file.

    Reading an image's labels means running it, so a gate that sat after
    the conformance checks would decide whether a stranger's image may
    execute *by executing it*. Nothing may reach the runtime first — not
    even the liveness check, which is why the assertion is on the whole
    command list and not on a subset of it.
    """
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    context = elsewhere_context(sha256)
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, context)
    assert frame["error"]["code"] == "policy.environment-denied"
    assert docker.calls == []


def only_image_is_elsewhere(docker) -> None:
    """This host has exactly one build environment, and it is not MCUHome's.

    Its repo digest is the one every context in this file pins, which is
    what puts the two claims in disagreement: the reference names one
    repository, the digest finds another.
    """
    docker.images.clear()
    docker.listed = [f"{ELSEWHERE}:latest"]
    docker.images[f"{ELSEWHERE}:latest"] = {
        "Id": "sha256:" + "c" * 64,
        "RepoTags": [f"{ELSEWHERE}:latest"],
        "RepoDigests": [f"{ELSEWHERE}@{IMAGE_DIGEST}"],
        "Config": {"Labels": dict(IMAGE_LABELS)},
    }


async def test_an_allowed_name_over_a_digest_that_found_another_repository_is_refused(
    client, config, docker
) -> None:
    """An image is matched by digest alone, so the name is only a claim.

    A context that names a listed repository while its pin belongs to an
    image from somewhere else is the case a check on the client's
    spelling would wave through — and it is the reachable one, because
    the digest is what decides which of this host's images is started.
    """
    only_image_is_elsewhere(docker)
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, mcuhome_context(sha256))
    assert frame["error"]["code"] == "policy.environment-denied"
    assert frame["error"]["details"]["repository"] == ELSEWHERE


async def test_an_operator_who_lists_another_repository_can_serve_it(
    aiohttp_client, config, docker
) -> None:
    """The other direction: the list decides, not the name MCUHome ships."""
    only_image_is_elsewhere(docker)
    state = ServerState(replace(config, allowed_environments=(ELSEWHERE,)))
    client = await aiohttp_client(create_app(state))
    sha256 = write_sdk_package(config.sdk_sources[0], "2.4.0")
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        frame = await send_archive(ws, "send-context", session_id, elsewhere_context(sha256))
    assert frame["type"] == "result", frame
