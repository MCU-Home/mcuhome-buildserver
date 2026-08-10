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


def test_a_nested_mount_comes_after_the_parent_it_sits_inside() -> None:
    """Docker applies bind mounts in the order it is given them.

    A mount that sits inside another has to come after it, or the outer
    one buries it — which, for a read-only mount under a writable one,
    is §9.1's kernel-enforced write protection silently not happening.

    The backend no longer *relies* on that nesting: it mounts the pieces
    of a session tree individually rather than carving read-only holes
    out of one big writable mount, precisely because the hole is only as
    good as the ordering. This stays because a mount set that does nest
    must not depend on the caller's list order to be correct.
    """
    ordered = container.mounts_for(
        [
            Mount(Path("/s/context"), Path("/s/context"), read_only=True),
            Mount(Path("/s"), Path("/s")),
            Mount(Path("/s/sdk/inner"), Path("/s/sdk/inner")),
        ]
    )
    assert [str(mount.target) for mount in ordered] == ["/s", "/s/context", "/s/sdk/inner"]


def test_the_session_container_command_is_the_backends_to_choose() -> None:
    """§2.2: ``docker run`` overrides both ``ENTRYPOINT`` and ``CMD``, a
    conforming image "MUST NOT depend on its own", and it "MUST provide a
    POSIX shell at ``/bin/sh``" so that there is always a command to
    name. This is that command — POSIX, not ``sleep infinity``, because
    the contract promises a shell rather than GNU coreutils."""
    argv = container.session_run_command(
        docker="docker",
        image="example@sha256:" + "a" * 64,
        mounts=[Mount(Path("/s"), Path("/s"))],
        session_id="s-1",
        user="1000:1000",
    )
    assert argv[:5] == ["docker", "run", "--detach", "--init", "--network=none"]
    assert argv[5:7] == ["--user", "1000:1000"]
    assert "--volume" in argv and "/s:/s" in argv
    assert argv[-4] == "example@sha256:" + "a" * 64
    assert argv[-3:] == list(container.IDLE_COMMAND)


def test_the_session_container_is_given_the_resource_limits_it_promises() -> None:
    """§1.2's ``container`` row promises "per-session resource limits and
    disk quota" and §9.1 makes them "the backend's to set and to
    enforce" — and nothing was set.

    They go on the ``run`` that creates the container rather than on the
    ``exec`` that uses it: an exec limit bounds one process tree, and the
    promise is about the session. ``--memory`` is also what makes the
    request document's silence about ``limits.memory_bytes`` honest — the
    runtime enforces the number, so the program is not asked to.
    """
    argv = container.session_run_command(
        docker="docker",
        image="i",
        mounts=[],
        session_id="s-1",
        limits=container.ResourceLimits(memory="8g", cpus="2.5", pids=4096),
    )
    assert argv[argv.index("--memory") + 1] == "8g"
    assert argv[argv.index("--cpus") + 1] == "2.5"
    assert argv[argv.index("--pids-limit") + 1] == "4096"


def test_an_unset_resource_limit_is_not_a_flag_with_no_value() -> None:
    """``--cpus`` is unset by default, and unset means the flag is absent.

    ``limits.jobs`` already bounds the parallelism a conforming program
    asks for, so a hard CPU ceiling on top of it is an operator's choice
    rather than a safety property — and a default of "" passed to docker
    would be an argument error rather than an absence.
    """
    argv = container.session_run_command(
        docker="docker",
        image="i",
        mounts=[],
        session_id="s-1",
        limits=container.ResourceLimits(memory="8g", cpus=None, pids=None),
    )
    assert "--cpus" not in argv
    assert "--pids-limit" not in argv
    assert "--memory" in argv


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


async def test_the_exec_carries_the_user_the_run_does() -> None:
    """§9.3 is a permissions problem otherwise.

    "Everything the program writes lands on a bind mount this server has
    to read back … a build that left root-owned files behind would make
    egress a permissions problem" — and it is the *exec* that writes
    them, not the idle main process the container was started with.
    """
    spawned: list[list[str]] = []

    async def spawner(argv, *, on_line):
        spawned.append(list(argv))
        return None

    docker = Docker("docker", spawner=spawner)
    await docker.invoke(
        container="c" * 64,
        action="build",
        request=Path("/s/invocations/inv-1/request.json"),
        on_line=lambda line: None,
        user="1000:1000",
    )
    assert spawned[0][:4] == ["docker", "exec", "--user", "1000:1000"]


async def test_a_container_that_does_not_start_is_a_typed_refusal() -> None:
    """The third pre-start refusal, and the one with no test.

    A daemon that dies between ``send-context`` and ``build`` answers
    the ``run`` non-zero, and the image profile is already cached by
    then so nothing else refuses first. ``builder.runtime-unavailable``
    and retryable, because nothing about the context is wrong.
    """
    refused = Completed(status=1, output="docker: Error response from daemon: no space left\n")
    docker = Docker("docker", runner=_runner([refused]))
    with pytest.raises(SessionError) as excinfo:
        await docker.start(image="i", mounts=[], session_id="s-1")
    assert excinfo.value.code == "builder.runtime-unavailable"
    assert excinfo.value.to_envelope()["retryable"] is True

    # And an answer that is not a container id is the same refusal: every
    # later command puts this string in an argv.
    nonsense = Completed(status=0, output="Unable to find image 'i' locally\n")
    with pytest.raises(SessionError):
        await Docker("docker", runner=_runner([nonsense])).start(
            image="i", mounts=[], session_id="s-1"
        )


def test_the_container_carries_the_label_that_finds_it_again() -> None:
    """Backend policy, which §11 leaves free, and it earns its place:
    a server that is killed outright leaves its containers behind, and
    there is deliberately no startup sweep — two servers on one host is a
    configuration, and a sweep would reap the other's live sessions."""
    argv = container.session_run_command(docker="docker", image="i", mounts=[], session_id="s-42")
    assert "org.mcuhome.build-server.session=s-42" in argv


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
    """A context's ``container.digest`` pin names the repo digest.

    ``Id`` is the local image ID, which never compares equal to one — so
    reading it instead would make every pinned context fail a
    cross-check it should pass.
    """
    inspected = (
        '{"Id": "sha256:'
        + "c" * 64
        + '", "RepoTags": ["ghcr.io/x:tag"], "RepoDigests": ["ghcr.io/x@sha256:'
        + "d" * 64
        + '"], "Config": {"Labels": {"org.mcuhome.contract": "1"}}}'
    )
    docker = Docker("docker", runner=_runner([Completed(status=0, output=inspected)]))
    facts = await docker.image("ghcr.io/x:tag")
    assert facts is not None
    assert facts.digest == "sha256:" + "d" * 64
    assert facts.image_id == "sha256:" + "c" * 64


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
    listing = Completed(status=0, output="ghcr.io/x:tag\n<none>:<none>\n")
    inspected = Completed(
        status=0,
        output=(
            '{"Id": "sha256:c", "RepoTags": ["ghcr.io/x:tag"], '
            '"RepoDigests": ["ghcr.io/x@sha256:'
            + "d"
            * 64
            + '"], "Config": {"Labels": {"org.mcuhome.contract": "1", '
            '"org.mcuhome.zephyr": "4.4.0", "org.mcuhome.toolchain": "zephyr-sdk-1.0.1", '
            '"maintainer": "someone@example.org"}}}'
        ),
    )
    runner = _runner([listing, inspected])
    docker = Docker("docker", runner=runner)
    found = await docker.inventory()
    assert len(found) == 1
    assert set(found[0].to_wire()["labels"]) == {
        "org.mcuhome.contract",
        "org.mcuhome.zephyr",
        "org.mcuhome.toolchain",
    }
    assert runner.calls[0][:4] == ["docker", "image", "ls", "--filter"]
    assert "<none>:<none>" not in runner.calls[1]
    assert runner.calls[1][-1] == "ghcr.io/x:tag"


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
        return (
            '{"Id": "sha256:' + letter * 4 + '", "RepoTags": ["' + name + '"], '
            '"RepoDigests": ["ghcr.io/x@sha256:' + letter * 64 + '"], '
            '"Config": {"Labels": {"org.mcuhome.contract": "1"}}}'
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


async def test_removing_a_container_never_raises() -> None:
    """Every caller is already closing something, and a cleanup that
    turned a refusal into the news would tell the client the wrong
    story."""
    docker = Docker("docker", runner=_runner([Completed(status=1, output="No such container")]))
    await docker.remove("deadbeefcafe")
