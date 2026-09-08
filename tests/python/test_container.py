# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Docker discovery: the pre-start refusals, and what an inventory reports.

Nothing here runs a container. What it exercises is the module that
would — :mod:`mcuhome.buildserver.container` — through its one seam, which
is what makes the whole thing testable on a machine with no container
runtime at all. Starting a step belongs to the workbench's container
profile and is covered where that profile is driven; this module is
**discovery only**: is there a runtime, and which build environments does
this host already have.
"""

from __future__ import annotations

import pytest
from mcuhome.model.buildenvironment import LABEL_PREFIX, SPEC_GENERATION_MEMBER

from mcuhome.buildserver import container
from mcuhome.buildserver.container import Completed, Docker
from mcuhome.buildserver.errors import SessionError

#: A minimal declaration, in the shape §5.2 has an image mirror it under.
#: Only ``spec-generation`` is required for these tests: the filter and
#: the labels are about which strings travel, not about a declaration a
#: container profile could act on.
_DECLARATION_LABELS = {f"{LABEL_PREFIX}{SPEC_GENERATION_MEMBER}": "3"}


def _runner(answers):
    """A seam that answers from a list and records what it was asked."""
    calls: list[list[str]] = []

    async def run(argv):
        calls.append(list(argv))
        return answers.pop(0) if answers else Completed(status=0, output="")

    run.calls = calls
    return run


# --------------------------------------------------------------------------
# The two pre-start refusals
# --------------------------------------------------------------------------


async def test_no_docker_binary_and_no_daemon_are_told_apart() -> None:
    """One wire code, ``builder.runtime-unavailable``, because they share
    one property: nothing about a session is wrong, and the same command
    works once the runtime is up. They are still *said* apart, because
    they have different fixes — a build that dies ten seconds in with
    somebody else's error text does not tell them apart.
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


async def test_the_probe_asks_the_daemon_for_its_version_and_nothing_else() -> None:
    """``require_runtime`` is one command, not a build's worth of probing."""
    runner = _runner([Completed(status=0, output="29.7.2\n")])
    await Docker("docker", runner=runner).require_runtime()
    assert runner.calls == [["docker", "version", "--format", "{{.Server.Version}}"]]


# --------------------------------------------------------------------------
# The inventory: what is asked, and what is dropped
# --------------------------------------------------------------------------


async def test_the_inventory_filter_names_the_declaration_label() -> None:
    """``docker image ls`` is filtered on the one label every build
    environment carries (§5.2's ``spec-generation`` member) — an image
    that is not a build environment at all is never worth an ``inspect``.
    """
    runner = _runner([Completed(status=0, output="")])
    found = await Docker("docker", runner=runner).inventory()
    assert found == ()
    assert runner.calls == [
        [
            "docker",
            "image",
            "ls",
            "--digests",
            "--filter",
            f"label={container.ENVIRONMENT_LABEL}",
            "--format",
            "{{.Repository}}:{{.Tag}}\t{{.Repository}}@{{.Digest}}",
        ]
    ]


async def test_a_runtime_that_cannot_be_reached_makes_the_inventory_empty() -> None:
    """``inventory`` answers "none" rather than raising when there is no
    runtime at all — the refusal belongs to a verb that actually needs a
    container, and a discovery call is not one."""
    unreachable = Docker("docker", runner=_runner([Completed(status=1, output="no daemon")]))
    assert await unreachable.inventory() == ()

    absent = Docker("docker", runner=_runner([Completed(status=None, output="")]))
    assert await absent.inventory() == ()


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
            f'"Config": {{"Labels": {_json_labels(_DECLARATION_LABELS)}}}}}'
        ),
    )
    runner = _runner([listing, inspected])
    found = await Docker("docker", runner=runner).inventory()

    assert runner.calls[1][-1] == f"ghcr.io/x@{digest}"
    assert len(found) == 1
    # And the digest survives the round trip, which is what a pin is
    # matched against — an image ID would not have found it.
    assert found[0].digest == digest


async def test_the_dangling_image_line_has_nothing_worth_asking_about() -> None:
    """``<none>:<none>`` both halves is docker's spelling for "no name at
    all", and the only line :func:`~mcuhome.buildserver.container._addressable`
    drops rather than turning into a request nobody could answer.
    """
    listing = Completed(status=0, output="<none>:<none>\t<none>@<none>\n")
    runner = _runner([listing])
    found = await Docker("docker", runner=runner).inventory()
    assert found == ()
    # No second call at all: with nothing addressable, `inspect` is never asked.
    assert len(runner.calls) == 1


# --------------------------------------------------------------------------
# ImageFacts.to_wire(): declaration labels only
# --------------------------------------------------------------------------


async def test_the_inventory_reports_only_declaration_labels() -> None:
    """An image's other labels are its author's business and none of this
    server's — only what §5.2 says an image mirrors travels to a client
    asking ``capabilities``.
    """
    listing = Completed(status=0, output="ghcr.io/x:tag\tghcr.io/x@<none>\n")
    labels = {**_DECLARATION_LABELS, "maintainer": "someone@example.org"}
    inspected = Completed(
        status=0,
        output=(
            '{"Id": "sha256:c", "RepoTags": ["ghcr.io/x:tag"], '
            '"RepoDigests": ["ghcr.io/x@sha256:' + "d" * 64 + '"], '
            f'"Config": {{"Labels": {_json_labels(labels)}}}}}'
        ),
    )
    runner = _runner([listing, inspected])
    found = await Docker("docker", runner=runner).inventory()
    assert len(found) == 1
    wire = found[0].to_wire()
    assert wire["reference"] == "ghcr.io/x:tag"
    assert wire["digest"] == "sha256:" + "d" * 64
    assert set(wire["labels"]) == set(_DECLARATION_LABELS)
    assert "maintainer" not in wire["labels"]


# --------------------------------------------------------------------------
# _facts_from, through _inspect: the repo digest and never the image id
# --------------------------------------------------------------------------


async def test_the_repo_digest_is_read_and_never_the_image_id() -> None:
    """A manifest's ``digest`` records the repo digest.

    ``Id`` is the local image ID, which never compares equal to one — so
    reading it instead would make every pinned context fail a
    cross-check it should pass.
    """
    inspected = Completed(
        status=0,
        output=(
            '{"Id": "sha256:'
            + "c" * 64
            + '", "RepoTags": ["ghcr.io/x:tag"], "RepoDigests": ["ghcr.io/x@sha256:'
            + "d" * 64
            + f'"], "Config": {{"Labels": {_json_labels(_DECLARATION_LABELS)}}}}}'
        ),
    )
    docker = Docker("docker", runner=_runner([inspected]))
    found = await docker._inspect("ghcr.io/x:tag")
    assert len(found) == 1
    assert found[0].digest == "sha256:" + "d" * 64
    assert found[0].image_id == "sha256:" + "c" * 64


async def test_the_digest_taken_is_the_one_of_this_references_own_repository() -> None:
    """One image, several repositories, one digest that is *its* name.

    A build environment pulled from ghcr.io and also pushed to a local
    mirror carries one ``RepoDigests`` entry per repository, each with
    that registry's own digest. Taking the first entry regardless of
    repository would compose ``mirror/build-environment@<the ghcr
    digest>`` — a reference docker resolves nowhere, handed to ``docker
    run`` on a server that pulls nothing, and published to a client as
    the digest of an image that is not the one it names.
    """

    def _object(name: str) -> str:
        return (
            '{"Id": "sha256:' + "c" * 64 + '", '
            '"RepoTags": ["ghcr.io/mcu-home/build-environment:r6", "registry.local/be:mirror"], '
            '"RepoDigests": ["registry.local/be@sha256:' + "b" * 64 + '", '
            '"ghcr.io/mcu-home/build-environment@sha256:' + "a" * 64 + '"], '
            f'"Config": {{"Labels": {_json_labels(_DECLARATION_LABELS)}}}}}'
        )

    # `_reference_of` matches an object to the first of *its* requested
    # references it names — one object per call is this test's way of
    # asking about each repository-qualified name on its own, exactly as
    # `inventory` does one reference at a time within a single answer.
    docker = Docker(
        "docker",
        runner=_runner(
            [
                Completed(status=0, output=_object("ghcr.io/mcu-home/build-environment:r6")),
                Completed(status=0, output=_object("registry.local/be:mirror")),
            ]
        ),
    )
    ghcr = await docker._inspect("ghcr.io/mcu-home/build-environment:r6")
    mirror = await docker._inspect("registry.local/be:mirror")
    assert ghcr[0].digest == "sha256:" + "a" * 64, "not the first entry — the ghcr one"
    assert mirror[0].digest == "sha256:" + "b" * 64


async def test_an_image_with_a_tag_but_no_pushed_digest_answers_digest_none() -> None:
    """A locally built image, never pushed anywhere, is still identifiable
    by its image id — it simply names no bytes anybody could fetch, and
    ``digest: null`` is the honest answer rather than a crash or a guess.
    """
    inspected = Completed(
        status=0,
        output=(
            '{"Id": "sha256:' + "c" * 64 + '", "RepoTags": ["local/build-environment:dev"], '
            '"RepoDigests": [], '
            f'"Config": {{"Labels": {_json_labels(_DECLARATION_LABELS)}}}}}'
        ),
    )
    docker = Docker("docker", runner=_runner([inspected]))
    found = await docker._inspect("local/build-environment:dev")
    assert len(found) == 1
    assert found[0].digest is None
    assert found[0].to_wire()["digest"] is None


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
        repository = name.partition(":")[0]
        return (
            '{"Id": "sha256:' + letter * 4 + '", "RepoTags": ["' + name + '"], '
            '"RepoDigests": ["' + repository + "@sha256:" + letter * 64 + '"], '
            f'"Config": {{"Labels": {_json_labels(_DECLARATION_LABELS)}}}}}'
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


async def test_inspect_answering_no_runtime_is_the_same_refusal_as_the_probe() -> None:
    """``_inspect`` runs a docker command too, so a runtime that vanished
    between the probe and here is told apart the same way."""
    docker = Docker("docker", runner=_runner([Completed(status=None, output="")]))
    with pytest.raises(SessionError) as excinfo:
        await docker._inspect("ghcr.io/x:tag")
    assert excinfo.value.code == "builder.runtime-unavailable"


def _json_labels(labels: dict[str, str]) -> str:
    """One line's worth of a ``Config.Labels`` object, hand-composed.

    ``json.dumps`` would work as well; this keeps every fixture in this
    file free of the import, and the shape is trivial enough to write out.
    """
    return "{" + ", ".join(f'"{key}": "{value}"' for key, value in labels.items()) + "}"
