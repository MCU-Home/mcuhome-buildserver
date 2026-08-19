# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The docker plumbing: composed argv, mount order, and the pre-start refusals.

Nothing here runs a container either. What it exercises is the module
that would — :mod:`mcuhome_buildserver.container` — through the two seam
functions everything in it goes through, which is what makes the whole
backend testable on a machine with no container runtime at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from mcuhome.model.buildimage import CONTRACT_LABEL, TOOLCHAIN_LABEL, ZEPHYR_LABEL

from mcuhome_buildserver import container
from mcuhome_buildserver.container import Completed, Docker, Mount
from mcuhome_buildserver.errors import SessionError


def _runner(answers):
    """A seam that answers from a list and records what it was asked."""
    calls: list[list[str]] = []

    async def run(argv):
        calls.append(list(argv))
        return answers.pop(0) if answers else Completed(status=0, output="")

    run.calls = calls
    return run


def test_a_read_only_mount_says_so_and_a_writable_one_does_not() -> None:
    """``read_only`` is the whole of a mount's mode, because it is the
    whole of what §9.1 asks for: ``context`` and every non-``writable``
    tree write-protected "with the strongest means its profile has"."""
    assert Mount(Path("/a"), Path("/b")).to_argument() == "/a:/b"
    assert Mount(Path("/a"), Path("/b"), read_only=True).to_argument() == "/a:/b:ro"


def test_the_describe_container_is_composed_line_by_line_too() -> None:
    """``describe`` is an invocation, so §9.1 applies to it unchanged.

    "No network during an invocation" is not a session-container nicety,
    and the probe mount is what makes the request document readable
    inside the container at all — both were unasserted, and both could
    be deleted with the suite green, because the fake read the request
    off the host filesystem where no mount is needed.
    """
    argv = container.describe_run_command(
        docker="docker",
        image="example@sha256:" + "a" * 64,
        mounts=[Mount(Path("/probe/x"), Path("/probe/x"))],
        request=Path("/probe/x/request.json"),
        user="1000:1000",
    )
    assert argv[:5] == ["docker", "run", "--rm", "--init", "--network=none"]
    assert argv[5:7] == ["--user", "1000:1000"]
    assert argv[7:9] == ["--volume", "/probe/x:/probe/x"]
    assert argv[9:] == [
        "example@sha256:" + "a" * 64,
        "/mcuhome/run",
        "describe",
        "/probe/x/request.json",
    ]


async def test_no_docker_binary_and_no_daemon_are_told_apart() -> None:
    """Two of the three pre-start refusals, and they share one wire code
    because they share one property: nothing about the context is wrong,
    and the same command works once the runtime is up.

    They are still *said* apart, because they have different fixes and
    "a build that dies ten seconds in with somebody else's error text
    does not tell them apart".
    """
    absent = Docker("docker", runner=_runner([Completed(status=None, output="")]))
    with pytest.raises(SessionError) as missing:
        await absent.require_runtime()
    assert missing.value.code == "builder.runtime-unavailable"
    assert missing.value.to_envelope()["retryable"] is True
    assert "PATH" in missing.value.message

    down = Docker("docker", runner=_runner([Completed(status=1, output="cannot connect")]))
    with pytest.raises(SessionError) as unreachable:
        await down.require_runtime()
    assert "daemon" in unreachable.value.message


async def test_an_image_this_host_has_not_is_absent_rather_than_an_error() -> None:
    """``None`` and not a refusal, because two callers want different
    refusals from the same absence: a pinned context that names it is
    ``version.builder-unavailable``, and an inventory listing simply
    leaves it out."""
    docker = Docker("docker", runner=_runner([Completed(status=1, output="Error: No such image")]))
    assert await docker.image("ghcr.io/x@sha256:" + "a" * 64) is None


async def test_the_repo_digest_is_read_and_never_the_image_id() -> None:
    """A manifest's ``container.digest`` records the repo digest.

    ``Id`` is the local image ID, which never compares equal to one — so
    reading it instead would make every pinned context fail a
    cross-check it should pass.
    """
    inspected = (
        '{"Id": "sha256:'
        + "c" * 64
        + '", "RepoTags": ["ghcr.io/x:tag"], "RepoDigests": ["ghcr.io/x@sha256:'
        + "d" * 64
        + '"], "Config": {"Labels": {"'
        + CONTRACT_LABEL
        + '": "1"}}}'
    )
    docker = Docker("docker", runner=_runner([Completed(status=0, output=inspected)]))
    facts = await docker.image("ghcr.io/x:tag")
    assert facts is not None
    assert facts.digest == "sha256:" + "d" * 64
    assert facts.image_id == "sha256:" + "c" * 64


async def test_the_digest_taken_is_the_one_of_this_references_own_repository() -> None:
    """One image, several repositories, one digest that is *its* name.

    A build container pulled from ghcr.io and also pushed to a local
    mirror carries one ``RepoDigests`` entry per repository, each with
    that registry's own digest. Taking the first entry regardless of
    repository would compose ``mirror/build-container@<the ghcr digest>``
    — a reference docker resolves nowhere, handed to ``docker run`` on a
    server that pulls nothing, and written into ``manifest.yaml`` as the
    record of what built the artifacts.
    """
    inspected = (
        '{"Id": "sha256:' + "c" * 64 + '", '
        '"RepoTags": ["ghcr.io/mcu-home/build-container:r6", "registry.local/bc:mirror"], '
        '"RepoDigests": ["registry.local/bc@sha256:' + "b" * 64 + '", '
        '"ghcr.io/mcu-home/build-container@sha256:' + "a" * 64 + '"], '
        '"Config": {"Labels": {"' + CONTRACT_LABEL + '": "1"}}}'
    )
    docker = Docker("docker", runner=_runner([Completed(status=0, output=inspected)] * 2))
    ghcr = await docker.image("ghcr.io/mcu-home/build-container:r6")
    mirror = await docker.image("registry.local/bc:mirror")
    assert ghcr is not None and mirror is not None
    assert ghcr.digest == "sha256:" + "a" * 64, "not the first entry — the ghcr one"
    assert mirror.digest == "sha256:" + "b" * 64


async def test_the_inventory_reports_only_the_three_contract_labels() -> None:
    """ADR 0019 §2 asks ``capabilities`` for "tag + digest + contract
    labels". An image's other labels are its own business and are not
    this server's to publish to every client that asks.

    The ``<none>:<none>`` line in the listing is the dangling-image case,
    and it is asserted where it is actually decided — on the ``image
    inspect`` argv. Asserting it on the *result* proves nothing: the
    reference would find no image and drop out of the answer anyway, so
    the filter could be deleted with the count unchanged.
    """
    listing = Completed(
        status=0, output="ghcr.io/x:tag\tghcr.io/x@<none>\n<none>:<none>\t<none>@<none>\n"
    )
    inspected = Completed(
        status=0,
        output=(
            '{"Id": "sha256:c", "RepoTags": ["ghcr.io/x:tag"], '
            '"RepoDigests": ["ghcr.io/x@sha256:'
            + "d" * 64
            + '"], "Config": {"Labels": {"'
            + CONTRACT_LABEL
            + '": "1", "'
            + ZEPHYR_LABEL
            + '": "4.4.0", "'
            + TOOLCHAIN_LABEL
            + '": "zephyr-sdk-1.0.1", '
            '"maintainer": "someone@example.org"}}}'
        ),
    )
    runner = _runner([listing, inspected])
    docker = Docker("docker", runner=runner)
    found = await docker.inventory()
    assert len(found) == 1
    assert set(found[0].to_wire()["labels"]) == {
        CONTRACT_LABEL,
        ZEPHYR_LABEL,
        TOOLCHAIN_LABEL,
    }
    assert runner.calls[0][:5] == ["docker", "image", "ls", "--digests", "--filter"]
    assert "<none>:<none>" not in runner.calls[1]
    assert runner.calls[1][-1] == "ghcr.io/x:tag"


async def test_an_image_with_no_tag_is_asked_about_by_its_digest() -> None:
    """The pinned fetch's own image, which had no name this could see.

    ``docker pull repo:tag@sha256:…`` stores the bytes under
    ``repo@sha256:…`` and leaves the tag ``<none>``. Listing tags alone,
    this server pulled a gigabyte and then reported that it could not
    fetch it — the pull succeeded and the presence check behind it was
    blind to what had arrived. Observed on a real remote build.

    The reference stays repository-qualified, which is what makes
    ``RepoDigests`` matchable: a digest is only a name within its own
    repository.
    """
    digest = "sha256:" + "e" * 64
    listing = Completed(status=0, output=f"ghcr.io/x:<none>\tghcr.io/x@{digest}\n")
    inspected = Completed(
        status=0,
        output=(
            '{"Id": "sha256:c", "RepoTags": [], '
            f'"RepoDigests": ["ghcr.io/x@{digest}"], '
            '"Config": {"Labels": {"' + CONTRACT_LABEL + '": "1"}}}'
        ),
    )
    runner = _runner([listing, inspected])
    found = await Docker("docker", runner=runner).inventory()

    assert runner.calls[1][-1] == f"ghcr.io/x@{digest}"
    assert len(found) == 1
    # And the digest survives the round trip, which is what a pin is
    # matched against — an image ID would not have found it.
    assert found[0].digest == digest


async def test_a_partial_inspect_answer_never_mis_attributes_an_image() -> None:
    """The reference an object is published under is the one it names.

    ``docker image inspect a b c`` with ``b`` missing prints objects for
    ``a`` and ``c``, exits non-zero, and says so on stderr — which this
    module merges into the same stream. The Nth line is then not the Nth
    reference, and positional matching published ``c``'s digest and
    labels under ``b``'s name: the tag→digest pair a workbench resolves
    a pin from, wrong.
    """

    def _object(name: str, letter: str) -> str:
        # The repo digest belongs to the same repository as the tag, which
        # is what makes it *this* image's digest — see
        # `test_a_digest_of_another_repository_is_not_this_references_digest`.
        repository = name.partition(":")[0]
        return (
            '{"Id": "sha256:' + letter * 4 + '", "RepoTags": ["' + name + '"], '
            '"RepoDigests": ["' + repository + "@sha256:" + letter * 64 + '"], '
            '"Config": {"Labels": {"' + CONTRACT_LABEL + '": "1"}}}'
        )

    answer = Completed(
        status=1,
        output=_object("a:1", "a") + "\n" + _object("c:1", "c") + "\nError: No such image: b:1\n",
    )
    docker = Docker("docker", runner=_runner([answer]))
    found = await docker._inspect("a:1", "b:1", "c:1")
    assert {facts.reference: facts.digest for facts in found} == {
        "a:1": "sha256:" + "a" * 64,
        "c:1": "sha256:" + "c" * 64,
    }
