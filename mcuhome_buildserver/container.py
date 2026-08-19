# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Docker, and the one seam every call to it goes through.

**This module is the whole of this server's container plumbing.** It
composes argv, it runs it, and it says what came back; it knows nothing
about sessions, contexts or the invocation ABI. That split is what makes
the rest of the backend testable without a container runtime, and it is
the same shape the workbench's own orchestrator uses
(``mcuhome/workbench/orchestrator.py`` in mcu-home/mcuhome) — which this
server may read and, today, does not import: that module drives the same
contract from a host, and the two are the same lifecycle written for two
worlds (a session state machine over a socket here, one blocking drive
there). Which of the two survives is the open question of the rebuild;
until it is answered, this stays this server's own.

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
which is not retryable once this server has decided it will not have
that image: the pin is resolved against the **local** inventory, and
when :attr:`~mcuhome_buildserver.config.Config.auto_pull` allows it
(the default) a miss becomes a :meth:`Docker.pull` rather than a
refusal. What never depends on that switch is *which* images may run at
all — that is the allowlist
(:mod:`mcuhome_buildserver.environments`), checked before any command
here names the image.

**Starting a container is not here any more.** The session's build
environment is the workbench's orchestrator's — the same object a local
build gets — so the ``docker run`` that creates it, the ``docker exec``
that is the invocation and the ``docker rm`` that ends it are composed
there, once, for both. What is left here is discovery: is there a
runtime, which images does this host have, fetch one, and what does an
image say about itself before a session is answered.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

# The three image labels of contract §2.1 are **pre-start scheduling
# data**: they let this server recognize a build environment before
# paying for a container start. They are not authoritative about what the
# program can do — ``describe`` is — which is why
# :mod:`mcuhome_buildserver.backend` cross-checks them against it before
# relying on them. Imported rather than spelled: the names belong to the
# contract, and the repository that publishes an environment writes
# exactly these strings onto it, so a second copy here is how one side
# starts looking for a label the other stopped writing.
from mcuhome.model.buildimage import CONTRACT_LABEL, TOOLCHAIN_LABEL, ZEPHYR_LABEL

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
    "PROGRAM",
    "TOOLCHAIN_LABEL",
    "ZEPHYR_LABEL",
    "Completed",
    "Docker",
    "ImageFacts",
    "Mount",
    "Process",
    "describe_run_command",
    "run_docker",
    "spawn_docker",
]

logger = logging.getLogger(__name__)

#: The program every conforming image carries, at the one absolute path
#: contract §2.2 fixes. Not looked up on ``PATH``: ``PATH`` inside the
#: image is the image author's, ``docker exec`` inherits the environment
#: fixed at container creation, and the invocation is resolved without a
#: shell — so there is no lookup to fall back on.
PROGRAM = "/mcuhome/run"

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
    #: A path inside the container, and POSIX whatever the host is:
    #: ``str()`` of a ``WindowsPath`` would hand docker backslashes.
    target: PurePosixPath | Path
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

    async def pull(self, reference: str, *, on_line: LineSink) -> bool:
        """Fetch *reference*, forwarding docker's own progress line by line.

        Spawned rather than run, because a pull is minutes long and a
        client watching one wants to see it happen; docker's layer
        counts and percentages are that report, and inventing a spinner
        over them would say less.

        *reference* is pinned to a digest by the time it reaches here —
        that is what makes fetching a mechanical step rather than a
        decision: exactly one set of bytes answers to it, and either
        they arrive or they do not. Whether this server may run them at
        all was settled before the pull
        (:mod:`mcuhome_buildserver.environments`).

        ``False`` for every failure — no runtime, no network, a registry
        that wants a login, a digest nothing answers to — because the
        caller's next move is the same in each case and it names the
        image rather than the mechanism.
        """
        process = await self._spawn([self.program, "pull", reference], on_line=on_line)
        return await process.wait() == 0

    async def inventory(self) -> tuple[ImageFacts, ...]:
        """Every local image that claims contract conformance.

        The filter is the ``org.mcuhome.build-environment.contract`` label, which is what
        §2.1 calls it: pre-start scheduling data. It is a *hint* here in
        the strongest sense — an image lands in this list for carrying a
        label, and what it can actually do is settled by ``describe``
        when a context names it.

        Two calls rather than one because ``docker image ls`` reports no
        labels: it names the references, and one ``image inspect`` over
        all of them answers the rest.

        **An image is asked about by its digest where it has no tag**,
        and that is not a nicety: an image *fetched by a pinned
        reference* has none. ``docker pull repo:tag@sha256:…`` stores the
        bytes under ``repo@sha256:…`` and leaves the tag ``<none>``, so
        listing tags alone made this server pull a gigabyte and then
        report that it could not fetch it — the pull succeeded, the
        presence check behind it could not see what had arrived. Observed
        on a real remote build; CI never saw it because the workflow
        pulls by tag before the job starts.

        The reference stays **repository-qualified** either way, which is
        what an image ID would not be: the repository is the key
        :func:`_facts_from` matches a ``RepoDigests`` entry against, and
        a digest is only a name within its own repository.
        """
        listed = await self._run(
            "image",
            "ls",
            "--digests",
            "--filter",
            f"label={CONTRACT_LABEL}",
            "--format",
            "{{.Repository}}:{{.Tag}}\t{{.Repository}}@{{.Digest}}",
        )
        if not listed.ok:
            return ()
        references = [
            reference
            for reference in (_addressable(line) for line in listed.output.splitlines())
            if reference is not None
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


def _first_line(output: str) -> str:
    for line in output.splitlines():
        if line.strip():
            return line.strip()
    return "no output"


def _addressable(line: str) -> str | None:
    """One ``image ls`` line as a reference to inspect, or nothing.

    Two candidates per line — ``repository:tag`` and
    ``repository@digest`` — and the tag is preferred because it is what a
    person recognizes and what ``capabilities`` publishes. ``<none>``
    is docker's word for "this image has no such name": an untagged image
    has it in the first, a never-pushed one in the second, and a dangling
    image in both, which is the only case with nothing to ask about.
    """
    for candidate in line.strip().split("\t"):
        if candidate and "<none>" not in candidate and not candidate.endswith("@"):
            return candidate
    return None


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


def _repository_of(reference: str) -> str:
    """*reference* with any digest and tag removed, spelled as docker spells it.

    A tag is what follows the last colon when that tail carries no slash
    — a colon inside a registry's ``host:port`` is not one.
    """
    name, _, _ = reference.partition("@")
    head, colon, tail = name.rpartition(":")
    return head if colon and "/" not in tail else name


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
    a never-pushed image gets. Such an image is still identifiable —
    :attr:`ImageFacts.image_id` is what a context pinned on this host
    names it by — it is simply not identifiable anywhere else.
    """
    config = data.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    digests = data.get("RepoDigests")
    # The repository half of the listed reference, with tag and any
    # digest taken off — the key a RepoDigests entry has to match.
    # Deliberately *not* expanded to a fully qualified name: docker elides
    # `docker.io/` on both sides of this comparison, and normalizing one
    # side would stop a Hub image from ever matching its own digest.
    repository = _repository_of(reference)
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
