# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Docker, and the one seam every call to it goes through.

**This module is the whole of this server's container plumbing.** It
composes argv, it runs it, and it says what came back; it knows nothing
about sessions, contexts or the invocation ABI. That split is what makes
the rest of the backend testable without a container runtime, and it is
the same shape the reference workbench backend uses
(``mcuhome/compiler/container.py``) — which this server may read and may
never import: that module is the **workbench-side** backend of the same
contract, and a build server importing it would make the fat half of the
product a dependency of the thin one (ADR 0003, ADR 0020 decision 4).

**Two impure functions, and everything goes through them.**
:func:`run_docker` runs a short command to completion and answers its
exit status and its output; :func:`spawn_docker` starts a long one and
hands back a handle that streams its merged output line by line. Both
are module-level and both are resolved **at call time** through
:class:`Docker`'s optional constructor arguments, for the reason the
reference states about its own seam: a default bound at definition time
cannot be replaced by monkeypatching the module, and a test that thinks
it stubbed docker out but did not is a test that starts a real build.

Both are one line each over :mod:`mcuhome_buildserver.processes`, which
owns the child-process plumbing every profile needs — the log pump, the
line cap, the signal-an-exited-process rule. They stay *here* as their
own names anyway, because they are this profile's seam: a suite that
stubs docker out must not thereby stub the ``subprocess`` profile's
program out as well, and a shared function would be one seam for two
things nobody ever wants replaced together.

**Three refusals before anything else, because they have three
different fixes.** No docker binary, no daemon, no image: a build that
dies ten seconds in with somebody else's error text does not tell them
apart. The first two are one wire code here —
``builder.runtime-unavailable``, retryable, because a daemon that is
down comes back — and the third is ``version.builder-unavailable``,
which is not retryable because the image this server does not have is
not going to appear on its own. Contract v1 for this server pulls
nothing (product-owner decision): the digest pin is resolved against
the **local** inventory, so "not here" is a final answer rather than a
fetch this server declined to make.

**What the composed argv says, line by line**, is in
:func:`session_run_command`. Two of its flags are the contract's and the
rest is this backend's policy, which §11 leaves free: ``--network=none``
because §9.1 forbids the network during an invocation and this is the
only mechanism that makes the statement checkable rather than asserted,
and ``--init`` because a build spawns hundreds of short-lived children
and PID 1 has to reap them.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcuhome.model.context import ContainerResolution

from mcuhome_buildserver.errors import SessionError
from mcuhome_buildserver.processes import (
    Completed,
    LineSink,
    Process,
    run_command,
    spawn_command,
)

__all__ = [
    "CONTRACT_LABEL",
    "IDLE_COMMAND",
    "PROGRAM",
    "TOOLCHAIN_LABEL",
    "ZEPHYR_LABEL",
    "Completed",
    "Docker",
    "ImageFacts",
    "Mount",
    "Process",
    "ResourceLimits",
    "describe_run_command",
    "run_docker",
    "session_run_command",
    "spawn_docker",
]

logger = logging.getLogger(__name__)

#: The program every conforming image carries, at the one absolute path
#: contract §2.2 fixes. Not looked up on ``PATH``: ``PATH`` inside the
#: image is the image author's, ``docker exec`` inherits the environment
#: fixed at container creation, and the invocation is resolved without a
#: shell — so there is no lookup to fall back on.
PROGRAM = "/mcuhome/run"

#: The three labels of contract §2.1. They are **pre-start scheduling
#: data**: they let this server pick an image before paying for a
#: container start. They are not authoritative about what the program can
#: do — ``describe`` is — which is why :mod:`mcuhome_buildserver.backend`
#: cross-checks them against it before relying on them.
CONTRACT_LABEL = "org.mcuhome.contract"
ZEPHYR_LABEL = "org.mcuhome.zephyr"
TOOLCHAIN_LABEL = "org.mcuhome.toolchain"

#: What the session's container runs as its main process. Contract §2.2
#: makes starting the container the backend's business — ``docker run``
#: overrides both ``ENTRYPOINT`` and ``CMD``, an image must not depend on
#: its own, and the image "MUST provide a POSIX shell at ``/bin/sh``" so
#: that there is always a command to name. This is that command, and it
#: is deliberately POSIX rather than ``sleep infinity``: the contract
#: promises a POSIX shell, not GNU coreutils.
IDLE_COMMAND = ("/bin/sh", "-c", "while :; do sleep 86400; done")

#: How this server labels the containers it starts. A **container**
#: label, not an image one: contract §2.1 governs image labels and this
#: is backend policy, which §11 leaves free. It exists so that an
#: operator can find the containers of a build server that was killed
#: outright — there is deliberately no startup sweep, for the reason
#: :meth:`~mcuhome_buildserver.sessions.SessionManager.shutdown` gives
#: about the context root: two servers sharing one host is a
#: configuration, and a sweep would answer it by reaping the other's live
#: sessions.
SESSION_LABEL = "org.mcuhome.build-server.session"

#: A container id as docker writes it back — 64 hex digits, of which the
#: first twelve are the short form. Checked because every later command
#: puts this string in an argv.
_CONTAINER_ID = re.compile(r"[0-9a-f]{12,64}\Z")


async def run_docker(argv: Sequence[str]) -> Completed:
    """Run *argv* to completion, capturing its merged output.

    The impure half of this module, and one of exactly two. Everything
    that is not a build — probing the daemon, inspecting an image,
    starting and removing a container — is short, bounded and wants its
    output as a value, so it comes through here.

    A ``docker`` client is told nothing about its environment: it is a
    client of a daemon, it reads ``DOCKER_HOST`` and the operator's own
    configuration out of the environment this server was started in, and
    stating one here would be this server deciding how an operator
    reaches their runtime.
    """
    return await run_command(argv)


async def spawn_docker(argv: Sequence[str], *, on_line: LineSink) -> Process:
    """Start *argv* and stream its merged output into *on_line*.

    The other impure half. It exists separately from :func:`run_docker`
    because an invocation is neither short nor bounded: its output is the
    build log, which has to reach the client while the build runs rather
    than as a value at the end, and the process has to stay addressable
    so that liveness policy can reach it.
    """
    return await spawn_command(argv, on_line=on_line)


@dataclass(frozen=True)
class Mount:
    """One bind mount, host source to container destination.

    ``read_only`` is the whole of the mode. Contract §9.1 requires the
    backend to "write-protect ``context`` and every non-``writable``
    tree with the strongest means its profile has", and in the container
    profile that means is a read-only bind mount — kernel-enforced,
    rather than a promise the program is asked to keep.
    """

    source: Path
    target: Path
    read_only: bool = False

    def to_argument(self) -> str:
        suffix = ":ro" if self.read_only else ""
        return f"{self.source}:{self.target}{suffix}"


@dataclass(frozen=True)
class ImageFacts:
    """What ``docker image inspect`` says about one image.

    ``digest`` is the **repo digest** — the value a backend names a
    chosen image by, and records in ``manifest.yaml``'s ``container``
    block — and not the image ID: contract §3.3.1 fixes the spelling and
    ADR 0018 makes it the one name for an image that cannot be moved to
    other bytes. It is ``None`` for an image that was built locally and
    never pushed, which is a perfectly ordinary image; such an image is
    served and recorded with ``digest: null``, because it names no bytes
    anybody could fetch. It is ``None`` for the same reason when
    :attr:`reference`'s repository is not one of the repositories the
    image was pushed to — a digest belongs to its repository and to no
    other, so there is nothing here to borrow.
    """

    reference: str
    image_id: str
    digest: str | None
    labels: dict[str, str] = field(default_factory=dict)

    def to_wire(self) -> dict[str, Any]:
        """One entry of ``capabilities``' container inventory.

        Tag, digest and the contract labels, which is exactly what
        ADR 0019 §2 lists: enough for a workbench to resolve a pin
        before it opens a session, and nothing about the image's
        contents, which ``describe`` answers and this does not.
        """
        return {
            "reference": self.reference,
            "digest": self.digest,
            "labels": {
                name: value
                for name, value in sorted(self.labels.items())
                if name in (CONTRACT_LABEL, ZEPHYR_LABEL, TOOLCHAIN_LABEL)
            },
        }


def _no_runtime(program: str, what: str) -> SessionError:
    """No docker, or no daemon. **Retryable**, and that is the point.

    Two of the three pre-start refusals share one code because they
    share one property: nothing about the *context* is wrong. A daemon
    that is down comes back, an operator installs the binary, and the
    same session's same command then works — which is precisely what
    ``retryable: true`` promises. The third refusal, a missing image,
    is not that and does not share the code.
    """
    return SessionError(
        "builder.runtime-unavailable",
        f"This build server drives build containers and {what}. It orchestrates builds "
        "and is never itself a build environment, so there is nothing it can fall back "
        "to; the session is untouched and the command can be retried once the container "
        "runtime is up.",
        program=program,
        problem=what,
    )


class Docker:
    """The container runtime, as this server uses it.

    One object per server process, holding the program name and the two
    seam functions. Nothing here is cached — :class:`ImageFacts` are
    cheap and ``describe`` is what the backend caches, because
    ``describe`` is what costs a container start.
    """

    def __init__(
        self,
        program: str = "docker",
        *,
        runner: Callable[[Sequence[str]], Any] | None = None,
        spawner: Callable[..., Any] | None = None,
    ) -> None:
        self.program = program
        self._runner = runner
        self._spawner = spawner

    async def _run(self, *arguments: str) -> Completed:
        argv = [self.program, *arguments]
        logger.debug("docker: %s", shlex.join(argv))
        runner = run_docker if self._runner is None else self._runner
        return await runner(argv)

    async def _spawn(self, argv: Sequence[str], *, on_line: LineSink) -> Process:
        logger.debug("docker: %s", shlex.join(argv))
        spawner = spawn_docker if self._spawner is None else self._spawner
        return await spawner(argv, on_line=on_line)

    # ----------------------------------------------------------------
    # Is there a runtime at all, and what does it hold?
    # ----------------------------------------------------------------

    async def require_runtime(self) -> None:
        """Refuse before anything else, naming which of the two is wrong.

        ``docker version --format`` answers both questions in one call:
        the program is missing when it cannot be executed at all, and
        the daemon is unreachable when the client runs and reports a
        non-zero status.
        """
        completed = await self._run("version", "--format", "{{.Server.Version}}")
        if completed.status is None:
            raise _no_runtime(self.program, f"cannot find {self.program} on its PATH")
        if completed.status != 0:
            raise _no_runtime(self.program, f"found {self.program} but cannot reach its daemon")

    async def image(self, reference: str) -> ImageFacts | None:
        """One image's facts, or ``None`` when this host does not have it.

        ``None`` rather than a refusal, because the two callers want
        different refusals from the same absence: a pinned context that
        names an image this host lacks is ``version.builder-unavailable``,
        while an inventory listing simply leaves it out.
        """
        found = await self._inspect(reference)
        return found[0] if found else None

    async def inventory(self) -> tuple[ImageFacts, ...]:
        """Every local image that claims contract conformance.

        The filter is the ``org.mcuhome.contract`` label, which is what
        §2.1 calls it: pre-start scheduling data. It is a *hint* here in
        the strongest sense — an image lands in this list for carrying a
        label, and what it can actually do is settled by ``describe``
        when a context names it.

        Two calls rather than one because ``docker image ls`` reports no
        labels and no digest: it names the references, and one
        ``image inspect`` over all of them answers the rest.
        """
        listed = await self._run(
            "image",
            "ls",
            "--filter",
            f"label={CONTRACT_LABEL}",
            "--format",
            "{{.Repository}}:{{.Tag}}",
        )
        if not listed.ok:
            return ()
        references = [
            line.strip()
            for line in listed.output.splitlines()
            if line.strip() and "<none>" not in line
        ]
        if not references:
            return ()
        return await self._inspect(*references)

    async def _inspect(self, *references: str) -> tuple[ImageFacts, ...]:
        """``docker image inspect``, parsed. Absent images are absent.

        ``--format '{{json .}}'`` yields one JSON object per line, which
        is what makes a partial answer usable: inspecting five images of
        which one is missing exits non-zero and still reports the four,
        and an inventory that dropped all five over one gap would be
        wrong about the four.

        **Each object is matched back to the reference it is an answer
        about, and never to the reference at its position.** A missing
        image is simply absent from stdout, and its error text goes to
        stderr, which this module merges into the same stream — so the
        Nth line is not the Nth reference the moment anything is missing
        or anything is said. Positional matching there is worse than
        dropping the image: it publishes one image's digest and labels
        under another image's name, which is the tag→digest pair a
        workbench resolves a pin from. The object says which image it is
        (``RepoTags``, ``RepoDigests``, ``Id``), so that is what decides;
        an object matching none of the references asked about is dropped
        rather than attributed to one of them.
        """
        completed = await self._run("image", "inspect", "--format", "{{json .}}", *references)
        if completed.status is None:
            raise _no_runtime(self.program, f"cannot find {self.program} on its PATH")
        facts: list[ImageFacts] = []
        for line in completed.output.splitlines():
            if not line.strip().startswith("{"):
                continue
            try:
                data = json.loads(line)
            except ValueError:  # pragma: no cover - docker emits JSON or nothing
                continue
            if not isinstance(data, dict):  # pragma: no cover - defensive
                continue
            reference = _reference_of(data, references)
            if reference is None:
                logger.warning("docker image inspect answered about an image nobody asked for")
                continue
            facts.append(_facts_from(reference, data))
        return tuple(facts)

    # ----------------------------------------------------------------
    # Containers
    # ----------------------------------------------------------------

    async def start(
        self,
        *,
        image: str,
        mounts: Sequence[Mount],
        session_id: str,
        user: str | None = None,
        limits: ResourceLimits | None = None,
    ) -> str:
        """Start the session's container and answer its id.

        One session is one container instance is the trust boundary
        (contract §1.2), and the container is discarded at
        ``close-session`` — which is what makes E47's writable view free:
        the image's own trees are writable inside the container by
        construction and cannot outlive the session that patched them.
        """
        argv = session_run_command(
            docker=self.program,
            image=image,
            mounts=mounts,
            session_id=session_id,
            user=user,
            limits=limits,
        )
        completed = await self._run(*argv[1:])
        identity = completed.output.strip().splitlines()[-1:] or [""]
        if not completed.ok or _CONTAINER_ID.fullmatch(identity[0]) is None:
            raise _no_runtime(
                self.program,
                f"could not start a container for this session ({_first_line(completed.output)})",
            )
        return identity[0]

    async def invoke(
        self,
        *,
        container: str,
        action: str,
        request: Path,
        on_line: LineSink,
        user: str | None = None,
    ) -> Process:
        """``docker exec`` the program: the contract's whole invocation.

        Exactly two positional operands after the program — the action
        and an absolute path to the request document — and never a flag
        (§5.1). This argv is frozen and never grows: extensibility runs
        through the request document, because an unknown JSON field
        costs an older program nothing while a new argv operand breaks
        every third-party container that does not know it.
        """
        argv = [self.program, "exec"]
        if user is not None:
            argv += ["--user", user]
        argv += [container, PROGRAM, action, str(request)]
        return await self._spawn(argv, on_line=on_line)

    async def describe(
        self,
        *,
        image: str,
        mounts: Sequence[Mount],
        request: Path,
        user: str | None = None,
    ) -> Completed:
        """Run ``describe`` in a throwaway container.

        ``describe`` is a property of the **image**, not of a session:
        it needs only the preamble, never touches a context and writes
        nothing but its result document. So it runs in its own
        ``--rm`` container rather than in a session's, which keeps
        container materialization lazy where ADR 0019 §2 puts it — a
        session that never builds never starts a container of its own.
        """
        argv = describe_run_command(
            docker=self.program, image=image, mounts=mounts, request=request, user=user
        )
        return await self._run(*argv[1:])

    async def read_file(self, *, image: str, path: str) -> str | None:
        """One file out of an image, without starting the program (§2.2.1).

        A throwaway ``--rm`` run whose command is ``cat`` — the cheapest
        read an image allows a backend that must not depend on the
        program being invocable yet (the static self-description exists
        for exactly the image whose program body arrives with a mount).
        ``--network=none`` and no mounts: reading a file grants nothing.

        ``None`` for every failure — image absent, file absent, runtime
        down — because the caller's fallback is invoking ``describe``,
        which was already mandatory and reports its own refusals.
        """
        completed = await self._run("run", "--rm", "--network=none", image, "cat", path)
        if completed.status != 0:
            return None
        return completed.output

    async def remove(self, container: str) -> None:
        """Reap the container. Never raises.

        ``--force`` because the session's lifetime is over and the
        program's result document is not a client deliverable at this
        point (E39): ``close-session`` on a busy session sets the stop
        signal first, and the guarantee that the result is still written
        orders the *program's* shutdown rather than promising anybody a
        document. Never raises because every caller is already closing
        something and a failed cleanup must not become the news.
        """
        completed = await self._run("rm", "--force", "--volumes", container)
        if not completed.ok:
            logger.warning(
                "could not remove container %s: %s", container, _first_line(completed.output)
            )


def _first_line(output: str) -> str:
    for line in output.splitlines():
        if line.strip():
            return line.strip()
    return "no output"


def _reference_of(data: dict[str, Any], references: Sequence[str]) -> str | None:
    """Which of *references* this ``image inspect`` object is about.

    The three fields that name an image, in the order the two callers
    use them: :meth:`Docker.inventory` asks by ``repository:tag`` and
    :meth:`Docker.image` asks by ``repository@digest``, and the id is
    there because ``docker image inspect`` accepts one and an operator's
    reference may be one.
    """
    names = {str(entry) for entry in _string_list(data.get("RepoTags"))}
    names |= {str(entry) for entry in _string_list(data.get("RepoDigests"))}
    identity = str(data.get("Id", ""))
    for reference in references:
        if reference in names:
            return reference
        if identity and (reference == identity or identity.partition(":")[2] == reference):
            return reference
    return None


def _string_list(value: Any) -> list[str]:
    return [str(entry) for entry in value] if isinstance(value, list) else []


def _facts_from(reference: str, data: dict[str, Any]) -> ImageFacts:
    """One ``docker image inspect`` object, as facts.

    The repo digest is picked out of ``RepoDigests`` rather than read
    from ``Id``: ``Id`` is the local image ID, which is not the value a
    manifest's ``container.digest`` records and never compares equal to
    one.

    **The entry taken is the one belonging to this reference's own
    repository**, and there is no fallback to another. One image is
    routinely tagged into several repositories — pulled from ghcr.io and
    also pushed to a local mirror, or simply retagged for a private name
    — and ``RepoDigests`` then holds one entry per repository, each with
    that registry's own digest. A digest is only a name *within* its
    repository: ``mirror/build-container@sha256:<the ghcr digest>``
    resolves nowhere, so pairing across repositories would compose a
    reference this host cannot answer and hand it to ``docker run`` on a
    server whose whole invariant is that it pulls nothing — and would
    write that same non-existent pair into ``manifest.yaml`` as the
    record of what built the artifacts.

    A repository with a tag but no pushed digest therefore gets
    ``digest=None``, which is the honest answer for it and the same one
    a never-pushed image gets:
    :meth:`~mcuhome.model.context.ContainerResolution.reference` then
    names it by the tag this host lists it under, which is a name that
    does resolve.
    """
    config = data.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    digests = data.get("RepoDigests")
    repository = ContainerResolution.from_reference(reference, digest=None).image
    digest = None
    if isinstance(digests, list):
        for entry in digests:
            listed, at_sign, candidate = str(entry).partition("@")
            if at_sign and candidate and listed == repository:
                digest = candidate
                break
    return ImageFacts(
        reference=reference,
        image_id=str(data.get("Id", "")),
        digest=digest,
        labels={str(k): str(v) for k, v in labels.items()} if isinstance(labels, dict) else {},
    )


@dataclass(frozen=True)
class ResourceLimits:
    """What one session's container may consume, as ``docker run`` flags.

    Contract §1.2 lists "per-session resource limits and disk quota"
    among the ``container`` profile's guarantees and §9.1 makes them the
    backend's "to set and to enforce", and this is the whole of the
    setting: three flags on the run that creates the container, because
    a limit applied anywhere else is a limit a build can step around.

    ``memory`` is why :func:`~mcuhome_buildserver.abi.request_document`
    can leave ``limits.memory_bytes`` out and still be truthful — the
    runtime enforces the number rather than the program being asked to
    respect it, which is what "advisory to the program, enforcement is
    the backend's" means when the backend has a kernel behind it.

    ``pids`` bounds the fork bomb a hostile context's build script is,
    and ``cpus`` is unset by default on purpose: a build server's whole
    job is to compile, ``limits.jobs`` already bounds the parallelism
    the program asks for, and an operator who wants a hard CPU ceiling
    on top of it says so.
    """

    memory: str | None = None
    cpus: str | None = None
    pids: int | None = None

    def to_arguments(self) -> list[str]:
        argv: list[str] = []
        if self.memory:
            argv += ["--memory", self.memory]
        if self.cpus:
            argv += ["--cpus", self.cpus]
        if self.pids is not None:
            argv += ["--pids-limit", str(self.pids)]
        return argv


def session_run_command(
    *,
    docker: str,
    image: str,
    mounts: Sequence[Mount],
    session_id: str,
    user: str | None = None,
    limits: ResourceLimits | None = None,
) -> list[str]:
    """The ``docker run`` that gives a session its container.

    Separate from :meth:`Docker.start` so that the argv can be asserted
    without running anything, which is how this server's suite reads it:
    the composed command is the interface between the contract and the
    runtime, and it is worth pinning line by line.

    * ``--detach`` because the container is the session's *place* for the
      whole session — invocations are ``docker exec`` into it, and how a
      backend keeps its container running between invocations is
      explicitly not part of the contract (§2.2).
    * ``--init`` because a build spawns hundreds of short-lived children
      and PID 1 has to reap them.
    * ``--network=none`` because §9.1 forbids the network during an
      invocation, and because it is the only way that statement can be
      checked rather than asserted: a step that fetches something
      succeeds on the machine that has a network and fails on the one
      that does not.
    * ``--user`` because everything the program writes lands on a bind
      mount this server has to read back — ``out``, ``work``, the result
      document — and a build that left root-owned files behind would
      make egress (§9.3) a permissions problem.
    * ``--memory``, ``--pids-limit`` and optionally ``--cpus``, because
      §1.2's ``container`` row promises "per-session resource limits"
      and §9.1 makes them the backend's to set. They go on the *run*
      that creates the container rather than on the exec that uses it:
      a limit on the exec bounds one process tree, and a limit on the
      container bounds the session.
    * The mounts are **path-identical**, host path to the same container
      path. That is workbench convenience rather than contract (§4 fixes
      no mount points at all and forbids a program from depending on
      one); it is kept because the request document then names paths
      that mean the same thing on both sides of the boundary, which is
      what makes a stalled build inspectable from the host — and, since
      the session tree is mounted piece by piece rather than wholesale,
      what makes the request document's paths *exactly* the set the
      container can see.
    """
    argv = [docker, "run", "--detach", "--init", "--network=none"]
    if user is not None:
        argv += ["--user", user]
    argv += (limits or ResourceLimits()).to_arguments()
    argv += ["--label", f"{SESSION_LABEL}={session_id}"]
    for mount in mounts:
        argv += ["--volume", mount.to_argument()]
    argv.append(image)
    argv += list(IDLE_COMMAND)
    return argv


def describe_run_command(
    *,
    docker: str,
    image: str,
    mounts: Sequence[Mount],
    request: Path,
    user: str | None = None,
) -> list[str]:
    """The throwaway ``docker run`` that asks an image what it is.

    Separate from :meth:`Docker.describe` for the same reason
    :func:`session_run_command` is separate from :meth:`Docker.start`:
    the composed command is the interface between the contract and the
    runtime, and it can only be asserted line by line if there is a
    function that composes it and runs nothing.

    ``describe`` is an invocation, so §9.1's "no network during an
    invocation" applies to it exactly as it applies to a build —
    ``--network=none`` is not a session-container nicety. ``--rm``
    because the container's only output is the result document on the
    mount, ``--init`` for the same child-reaping reason a build needs
    one, and one ``--volume`` per mount: the probe directory holds the
    request document the program is about to read and the result
    document it is about to write, and neither is reachable inside the
    container without it.
    """
    argv = [docker, "run", "--rm", "--init", "--network=none"]
    if user is not None:
        argv += ["--user", user]
    for mount in mounts:
        argv += ["--volume", mount.to_argument()]
    argv += [image, PROGRAM, "describe", str(request)]
    return argv


def current_user() -> str | None:
    """``uid:gid`` of whoever runs this server, where that is a thing."""
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if getuid is None or getgid is None:  # pragma: no cover - not POSIX
        return None
    return f"{getuid()}:{getgid()}"


def mounts_for(entries: Iterable[Mount]) -> tuple[Mount, ...]:
    """Bind mounts ordered so that a nested one wins over its parent.

    Docker applies bind mounts in the order it is given them, so a mount
    that sits inside another has to come *after* it or the outer one
    buries it — which, for a read-only mount under a writable one, is
    §9.1's kernel-enforced write protection silently not happening.

    The backend no longer relies on that nesting for anything: it mounts
    the pieces of a session tree individually rather than mounting the
    tree and carving read-only holes out of it, precisely because the
    hole is only as good as the ordering. This ordering stays because it
    costs nothing and because a mount set that *does* nest — an SDK the
    image asks for under a path the backend also supplies — must not
    depend on the caller's list order to be correct.
    """
    return tuple(sorted(entries, key=lambda mount: len(mount.target.parts)))
