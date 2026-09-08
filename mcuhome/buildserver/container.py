# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Docker, as this server *asks* it questions.

**Discovery, and nothing else.** Is there a container runtime, and which
build environments does this host already have — that is the whole of
this module. Everything that *runs* something belongs to the workbench's
container profile (:mod:`mcuhome.workbench.containerbuild`): the
``docker run`` that is a step, the limits it is given, the removal that
reaps it. The two halves are split by concurrency shape rather than by
taste — discovery is asked from verb handlers on the event loop and
wants its answer as a value, while driving a build blocks a worker
thread for minutes.

**One impure function, and everything goes through it.**
:func:`run_docker` runs a short command to completion and answers its
exit status and its output. It is module-level and resolved **at call
time** through :class:`Docker`'s optional constructor argument, for the
reason the seam exists at all: a default bound at definition time cannot
be replaced by monkeypatching the module, and a test that thinks it
stubbed docker out but did not is a test that starts a real container.

**Two refusals, because they have two different fixes.** No docker
binary and no daemon are one wire code — ``builder.runtime-unavailable``,
retryable, because a daemon that is down comes back — and a build that
dies ten seconds in with somebody else's error text tells neither of
them. Which images may run at all is a different question again, and it
is the operator's allowlist (:mod:`mcuhome.buildserver.environments`),
checked before any command here names an image.
"""

from __future__ import annotations

import json
import logging
import shlex
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

# An image that delivers a build environment mirrors its whole
# declaration as ``org.mcuhome.build-environment.<member>`` labels
# (build environment specification §5.2), and the spec generation is one
# of the members every one of them must carry. That makes it the filter
# for "is this image a build environment at all". Imported rather than
# spelled: the names belong to the specification, the party that
# publishes an image writes exactly these strings onto it, and a second
# copy here is how one side starts looking for a label the other stopped
# writing.
from mcuhome.model.buildenvironment import LABEL_PREFIX, SPEC_GENERATION_MEMBER

from mcuhome.buildserver.errors import SessionError
from mcuhome.buildserver.processes import Completed, run_command

__all__ = [
    "DECLARATION_LABEL_PREFIX",
    "ENVIRONMENT_LABEL",
    "Completed",
    "Docker",
    "ImageFacts",
    "run_docker",
]

logger = logging.getLogger(__name__)

#: The label prefix a build-environment image mirrors its declaration
#: under (§5.2), and the one member of it that says "this is a build
#: environment": every declaration states the specification generation it
#: implements, so an image carrying that label is one, and an image
#: without it is not.
DECLARATION_LABEL_PREFIX = f"{LABEL_PREFIX}"
ENVIRONMENT_LABEL = f"{LABEL_PREFIX}{SPEC_GENERATION_MEMBER}"


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
        """One entry of ``capabilities``' environment inventory.

        Reference, digest and the declaration the image's labels mirror
        (§5.2) — its package set above all, which is what makes an image
        findable at all. Only the labels under the specification's own
        prefix travel: an image's other labels are its author's business
        and none of this server's.
        """
        return {
            "reference": self.reference,
            "digest": self.digest,
            "labels": {
                name: value
                for name, value in sorted(self.labels.items())
                if name.startswith(DECLARATION_LABEL_PREFIX)
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

    One object per server process, holding the program name and the one
    seam function. Nothing is cached: :class:`ImageFacts` are two cheap
    commands, and nothing here is asked often enough to be worth a memo
    that could come to mean a different image.
    """

    def __init__(
        self,
        program: str = "docker",
        *,
        runner: Callable[[Sequence[str]], Any] | None = None,
    ) -> None:
        self.program = program
        self._runner = runner

    async def _run(self, *arguments: str) -> Completed:
        argv = [self.program, *arguments]
        logger.debug("docker: %s", shlex.join(argv))
        runner = run_docker if self._runner is None else self._runner
        return await runner(argv)

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

    async def inventory(self) -> tuple[ImageFacts, ...]:
        """Every local image that declares itself a build environment.

        The filter is the specification-generation label, which every
        declaration carries (§5.2). It is pre-start scheduling data in
        the strongest sense — an image lands in this list for carrying a
        label, and whether it serves a given context is decided by its
        package labels against what that context pins.

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
            f"label={ENVIRONMENT_LABEL}",
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

    The three fields that name an image, in the order the caller uses
    them: :meth:`Docker.inventory` asks by ``repository:tag`` or by
    ``repository@digest``, and the id is there because ``docker image
    inspect`` accepts one and an operator's reference may be one.
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
