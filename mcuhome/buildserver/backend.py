# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The backend: this server's half of one session's build.

:class:`SessionBackend` is what one build-server process knows about
running builds. It is **not** a build environment and it is not a
builder: the environment is delivered as a container image that declares
its own package set, and the whole of what happens inside it belongs to
the build environment specification. What stays here is what a
*protocol* has and a build does not: which image serves a session,
whether this operator allows it, invocation ids, the audience watching
them, the replay boundary, egress and the verdict frame.

**The orchestrating side is the workbench's container profile.** The
launcher that starts a step, the image lookup by package labels, the
checks a declaration has to pass and the judgement of what came back are
:mod:`mcuhome.workbench.containerbuild` and
:mod:`mcuhome.workbench.buildenvsession` — the same code a local
container build runs, so a fix to either is a fix to both. This module
supplies what only a server has: the operator's allowlist, the
per-session directories, the invocation record and the wire.

**It may rely on the specification and on nothing else.** The image is
found by its ``packages.`` labels (§5.2), started at the entry point §6
fixes, handed the tree of §4 and the cache tiers of §8, and told what it
should fit in through the request document's ``limits`` (§6.1) while the
runtime is told to hold it to the same numbers. Where the image keeps
its workspace, what a builder does with it, which source trees exist:
none of it is knowable from here and none of it is assumed.

The layering, from the outside in:

* :mod:`mcuhome.buildserver.sessions` owns the verbs and the state
  machine and calls into this module through ``state.backend``;
* this module owns the *lifecycle* — image resolution, the session's
  builder session, the invocation record, the event and log relay, and
  what an invocation is worth at the end of it;
* :mod:`mcuhome.buildserver.container` owns docker discovery,
  :mod:`mcuhome.buildserver.events` owns the NDJSON stream and
  :mod:`mcuhome.buildserver.artifacts` owns egress.

**Two things this backend deliberately does not do.**

*No environment of its own.* A session runs the image whose labels
declare exactly the package set its context pins, from a repository this
server's operator listed, or it runs nothing. An image that declares
something else is a different environment, and building in it would
attribute firmware to a context that does not describe it.

*No signing, and no key.* A build environment does not sign and this
server holds no private key; ``keys/signing.pub`` is the client's to put
in the context. What a build produces here is an unsigned image plus its
report, and signing happens on the machine that holds the key.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcuhome.model.buildenvironment import Declaration, PackageMember
from mcuhome.model.context import (
    BUILD_CONTEXT_FILE,
    DeveloperEnvironment,
    format_generator_chain,
)
from mcuhome.model.errors import BuildError, MCUHomeError
from mcuhome.model.jobs import BuildLimits
from mcuhome.model.sdkindex import SDK_PACKAGE_NAME
from mcuhome.workbench import api as workbench
from mcuhome.workbench import (
    buildenvsession,
    containerbuild,
    packagefetch,
    packageregistry,
    resolve_pins,
)
from mcuhome.workbench import resolve_image as image_lookup
from mcuhome.workbench.buildenvsession import LocalOutcome
from mcuhome.workbench.buildprocess import current_user
from mcuhome.workbench.contextdir import read_generator_chain
from mcuhome.workbench.resolve_image import ImageMatch

from mcuhome.buildserver import (
    artifacts,
    container,
    environments,
    errors,
    protocol,
)
from mcuhome.buildserver.config import Config
from mcuhome.buildserver.contextstore import (
    ContextPins,
    SessionPaths,
    developer_context_refusal,
)
from mcuhome.buildserver.errors import SessionError
from mcuhome.buildserver.processes import LineSink

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "ACTION_BUILD",
    "ACTION_VERIFY",
    "REGISTRY_CACHE_DIR",
    "SPEC_GENERATION",
    "EnvironmentProfile",
    "InvocationRecord",
    "SessionBackend",
    "SessionRuntime",
    "session_limits",
]

logger = logging.getLogger(__name__)

#: The one action a build environment is asked to do (build actions §2),
#: and the one this server answers itself. ``verify`` is not an action of
#: the specification — "the orchestrator creates the context, hashes it,
#: and delivers it … there is nothing an environment could confirm that
#: the orchestrator does not already know from its own bytes" — so the
#: verb is answered here, from this server's own measurement of the
#: locked context, and starts no container.
ACTION_BUILD = "build"
ACTION_VERIFY = "verify"

#: The build-environment specification generation this server speaks. It
#: is the workbench's, because the request document is written by the
#: workbench's session object and there is exactly one generation in
#: play at a time.
SPEC_GENERATION = buildenvsession.SPEC_GENERATION

#: Where the package registry's verified documents are kept: under the
#: context root, beside the session directories and never inside one. It
#: is the server's own state — one operator directory holds everything
#: this process writes — and it survives the sessions that filled it.
REGISTRY_CACHE_DIR = ".registry"

#: The statuses a verdict frame carries. Three of them are the result
#: document's (§6.2); ``cancelled`` is this server's own, for an
#: invocation it stopped — the specification has no cancelled status, so
#: a stopped step is a step that wrote no result document, and the side
#: that asked for it is the only side that can say why.
STATUS_SUCCESS = buildenvsession.STATUS_SUCCESS
STATUS_FAILURE = buildenvsession.STATUS_FAILURE
STATUS_UNSUPPORTED = buildenvsession.STATUS_UNSUPPORTED
STATUS_CANCELLED = "cancelled"

#: What the orchestrator's liveness ladder can still cost **after** the
#: grace period, and the whole of what :meth:`SessionBackend.release`
#: adds to ``cancel_grace_seconds`` when it waits for a supervisor to
#: come back. It is that ladder read off and not a second policy beside
#: it: SIGTERM one grace period after the sentinel, SIGKILL ten seconds
#: later, thirty more before the supervisor gives up on a process that
#: survived SIGKILL. Forty of the forty-five are those two rungs; the
#: remaining five are the slack the ladder walks on — it looks at the
#: world every half second and the log pump is joined for up to four of
#: those ticks, so about two seconds — and the judgement that follows
#: the supervisor: reading the result document and re-hashing every
#: declared artifact.
#:
#: **It is a bound and not a promise.** Re-hashing a full egress budget
#: of artifacts can outlast the three seconds left over, and the wait
#: would then run out on an invocation that is merely finishing. That
#: is no longer expensive: a release that runs out of time keeps the
#: session, and the reaper retries it until it succeeds.
_LADDER_TAIL_SECONDS = 45.0


def _ladder_seconds(config: Config) -> float:
    """The whole ladder, from the cancel sentinel to the last rung.

    The grace period is the operator's number and the tail is the
    orchestrator's; a caller that has to wait for a cancelled invocation
    waits for both, and for nothing it made up itself.
    """
    return config.cancel_grace_seconds + _LADDER_TAIL_SECONDS


# --------------------------------------------------------------------------
# What a build environment is, and what a session runs on
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class EnvironmentProfile:
    """The build environment one session runs in, and how it was reached.

    An image, and the declaration its labels carry (§5.2). There is no
    second discovery channel and no runtime probe: the labels **are** the
    self-description, they are read before anything is started, and they
    are what made this image a candidate in the first place — its
    ``packages.`` members are exactly the set the context pinned.

    :attr:`fetched` says whether those bytes had to be pulled onto this
    host, which is worth a line in the log and nothing else.
    """

    match: ImageMatch
    fetched: bool = False

    @property
    def reference(self) -> str:
        """The full explicit form — what a session and a report record."""
        return str(self.match.reference)

    @property
    def runnable(self) -> str:
        """How the runtime is told to run those bytes: by digest."""
        return self.match.reference.runnable()

    @property
    def digest(self) -> str:
        """The digest of the manifest whose labels were checked."""
        return self.match.reference.digest or ""

    @property
    def declaration(self) -> Declaration:
        return self.match.declaration

    @property
    def environment(self) -> str:
        """How this host names the environment serving the session."""
        return self.reference

    def to_wire(self) -> dict[str, Any]:
        """What ``send-context`` answers about the serving environment.

        An **acknowledgement**: the context pinned a package set, this
        server found an image that delivers it, and this is what that
        image is — its digest and the declaration it carries. The client
        already knows which packages it asked for; what it cannot know is
        which delivery of them this host chose, and that is the whole
        content of this block.
        """
        declaration = self.declaration
        return {
            "build_environment": self.reference,
            "digest": self.digest,
            "spec_generation": declaration.spec_generation,
            "zephyr_version": declaration.zephyr_version,
            "generator_constraint": declaration.generator_constraint,
            "packages": {
                name: member.value() for name, member in sorted(declaration.packages.items())
            },
            # What a client may ask this session for, which is this
            # server's answer and not the image's: `build` is the one
            # action an environment is started for, and `verify` is
            # answered here without starting anything.
            "actions": [ACTION_BUILD, ACTION_VERIFY],
        }


@dataclass
class SessionRuntime:
    """The build environment one session works in, and what it was given.

    One record per session, holding the two things a build needs and a
    verb handler must not build twice: the image this session was
    answered with, and the :class:`~mcuhome.workbench.api.BuilderSession`
    that enters a step in it. The session object owns ``out`` — created
    empty when the session starts and surviving every step of it (§7) —
    the SDK tree, the cache tiers and the limits every request document
    of this session states.

    :attr:`started` is the list the launcher appends every container name
    to, so that a step which was stopped can be reaped by name rather
    than by hope.
    """

    session_id: str
    #: The image serving this session, as its labels declare it.
    image: EnvironmentProfile
    paths: SessionPaths
    #: The workbench's session against that environment. ``None`` only in
    #: the window before it has been materialized.
    builder: Any = None
    #: The container runtime seam this session's steps are started
    #: through — one per session, so a test can replace it.
    runtime: Any = None
    #: Container names the launcher started, for the sweep at release.
    started: list[str] = field(default_factory=list)
    #: One invocation at a time per session (§3: steps are strictly
    #: sequential). The environment cannot check it, so it is a backend
    #: duty; this flag is the whole of it.
    busy: bool = False


@dataclass
class InvocationRecord:
    """One invocation, from the id this server assigned to what it produced."""

    id: str
    session_id: str
    action: str
    #: The backend-owned directory of this invocation: the events file
    #: this server writes and nothing else. The step's own tree belongs
    #: to the builder session and is replaced by the next step.
    directory: Path
    context_id: str
    #: Where the artifacts of this session are — the builder session's
    #: ``out``, shared by every step of the session (§7).
    out: Path
    started_at: float = field(default_factory=time.monotonic)
    #: The prepared step, from ``prepare`` until the verdict is out. It
    #: carries the stop sentinel a cancel raises and the result document
    #: the judgement reads. ``None`` for an invocation this server
    #: answers itself, which starts no step at all.
    step: Any = None
    #: Whether a cancel was signalled for this invocation. It is what
    #: turns "the step ended without a result document" into the honest
    #: verdict ``cancelled``.
    cancelled: bool = False
    #: The task running :meth:`SessionBackend._drive` for this
    #: invocation, from ``invoke`` until the verdict is out. It is here
    #: because :meth:`SessionBackend.release` has to wait for it: the
    #: task holds a worker thread that is supervising a container, and a
    #: thread still in that supervisor when the session's directory is
    #: deleted is the one state neither half can recover from. ``None``
    #: only in the window before ``invoke`` has started it.
    drive: asyncio.Task[None] | None = None
    #: Filled when the invocation ends. Until then the artifact list is
    #: empty, which is the truthful answer to ``get-artifact``: nothing
    #: has been declared, so nothing has been verified.
    outcome: LocalOutcome | None = None
    artifacts: tuple[Any, ...] = ()
    log_seq: int = 0
    #: The counter of the events **this server** writes for this
    #: invocation. The build environment writes none — the specification
    #: has no event channel — so the file that ``attach-session`` replays
    #: is this server's own record of what it did.
    event_seq: int = 0

    @property
    def events(self) -> Path:
        return self.directory / "events.ndjson"


# --------------------------------------------------------------------------
# The backend seam: everything §9 asks of a backend in either profile
# --------------------------------------------------------------------------


class SessionBackend:
    """Everything one build-server process knows about running builds.

    One instance per :class:`~mcuhome.buildserver.app.ServerState`. It
    holds no session state of its own beyond what a build environment
    needs — the session record stays in
    :class:`~mcuhome.buildserver.sessions.Session` — because the two have
    different lifetimes: a session exists from ``open-session``, and its
    build environment exists from the first command that needs one.

    **It is not a builder.** The orchestrating side is the workbench's
    container profile — the image lookup, the launcher, the checks and
    the judgement — and what is left here is what a *protocol* has and a
    build does not: which image serves a session, whether this operator
    allows it, invocation ids, the audience watching them, the replay
    boundary and the verdict frame.

    **Two seams onto one runtime, and they answer different questions.**
    :attr:`docker` is discovery: is there a runtime, and which build
    environments does this host already have. It is asynchronous because
    it is asked from verb handlers, on the event loop. The container
    profile's own :class:`~mcuhome.workbench.containerbuild.Runtime` is
    synchronous and used inside a worker thread, because driving a
    container means blocking on a build. Merging them would mean giving
    one of the two the other's concurrency shape for nothing.
    """

    #: What this server answers at ``open-session`` as
    #: ``negotiated.backend_profile``: it builds in containers and is not
    #: one itself.
    profile = "container"

    def __init__(
        self,
        config: Config,
        *,
        docker: container.Docker | None = None,
        runtime: containerbuild.Runtime | None = None,
        registry: Any = None,
        images: Any = None,
    ) -> None:
        self.config = config
        self.docker = container.Docker(config.docker) if docker is None else docker
        #: The container profile's runtime seam, shared by every session
        #: of this process: it holds no state beyond the program name.
        self.runtime = containerbuild.Runtime(config.docker) if runtime is None else runtime
        #: The package registry a session's SDK and package index come
        #: from, and the OCI registry an image's labels are read from.
        #: Both are seams a test replaces; left ``None`` they are the
        #: real ones.
        self._registry = registry
        self._images = images
        self._runtimes: dict[str, SessionRuntime] = {}
        self._records: dict[tuple[str, str], InvocationRecord] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        #: Which connections want a session's live stream, and from
        #: which point. More than one connection, because "connection
        #: loss is not abandonment": a running build continues detached
        #: and a reconnecting client re-joins the audience through
        #: ``attach-session`` while the invocation is still going. The
        #: value is that client's replay boundary — ``(invocation id,
        #: seq)`` — or ``None`` for a connection that replayed nothing.
        self._audience: dict[str, dict[Any, tuple[str, int] | None]] = {}

    # ----------------------------------------------------------------
    # Discovery
    # ----------------------------------------------------------------

    async def inventory(self) -> list[dict[str, Any]]:
        """The build environments this host already has, for ``capabilities``.

        A label-filtered ``docker image ls`` plus one ``inspect``: cheap,
        pre-session, unmetered, and honest about what it is — a list of
        what is *here*, not of what this server can serve. Which images
        it will serve is the operator's allowlist plus the labels of
        whatever the registry holds, and answering that would mean
        walking every allowed repository on a verb that promises to be
        cheap.

        A runtime that cannot be reached answers an empty list rather
        than a refusal. The question is "which environments does this
        server have", the answer without a runtime is "none", and that is
        a fact rather than an error — the refusal belongs to the verb
        that actually needs a container, where it can be acted on.
        """
        try:
            found = await self.docker.inventory()
        except SessionError:
            return []
        return [facts.to_wire() for facts in found]

    async def resolve_image(
        self,
        pins: ContextPins,
        context: Path,
        *,
        image_pin: str | None = None,
        on_progress: LineSink | None = None,
    ) -> EnvironmentProfile:
        """Which image serves this session, and may it run here.

        Called from ``send-context``, which is where it belongs: only
        with the pins in hand does this server know which environment the
        session needs, and refusing before the context is frozen is what
        lets a client go to another server without having paid for a
        lock.

        The four steps, in the order that makes each refusal cheap.

        **The pin the client sent narrows the search** and never widens
        it (:func:`~mcuhome.workbench.resolve_image.parse_image_pin`). A
        pin naming a repository — on its own or canonically — has to name
        one this operator allows, and that is checked here rather than
        inside the lookup: the allowlist is this server's own boundary,
        the refusal is the operator's to explain, and a pin that fails it
        must not cost a registry request. A pin that names only a tag or
        a digest is looked for in the allowed repositories, in order.

        **The image is found by its labels.** The context pins the
        environment's *packages*, an image declares the concrete set it
        was assembled from (§5.2), and the lookup is the workbench's own
        — the same call a local container build makes, so the two cannot
        drift apart. The tools pin is a family and is resolved to this
        host's platform through the package index first, which is what
        makes one context buildable on two architectures.

        **What it declares is checked** before anything is started
        (:func:`~mcuhome.workbench.containerbuild.check_image`): the
        specification generation this server speaks, and the build
        contexts the environment accepts against the generator chain of
        the context that just arrived.

        **And then the bytes have to be here.** An image this host does
        not have is pulled by digest when the operator allows it, with
        the pull's own output as the progress report.
        """
        environment = pins.build_environment
        if isinstance(environment, DeveloperEnvironment):
            # Unreachable through the wire — such a context is refused
            # when it is parsed, before a pin is ever read — and kept
            # because an embedder can call this directly.
            raise developer_context_refusal()
        try:
            pin = image_lookup.parse_image_pin(image_pin)
        except BuildError as unreadable:
            # A pin this server cannot read is a frame it did not
            # understand, and it says so at that layer: the typed codes
            # describe what a *session* did, and a value that is not a
            # reference has not got that far.
            raise protocol.ProtocolError(
                f'"send-context" carries a container_image this server cannot read: '
                f"{unreadable.message} {unreadable.hint}".strip()
            ) from unreadable
        if pin.repository:
            environments.check_allowed(
                pin.repository,
                allowed=self.config.allowed_environments,
                what="the image this build was pinned to",
            )
        await asyncio.to_thread(self._require_runtime)
        # The two halves are asked separately because they fail
        # differently and a client can act on exactly one of the two
        # answers. **Which packages** this host needs is a question about
        # packages: the index does not carry the version, it carries it
        # under other bytes, or it cannot be read at all — and none of
        # that is a statement about any image. **Which image delivers
        # them** is the question that comes after, and only its refusal
        # may say that no image declares the set.
        try:
            wanted = await asyncio.to_thread(self._concrete_packages, environment)
        except workbench.MCUHomeError as unresolvable:
            raise _unresolvable_packages(unresolvable) from unresolvable
        try:
            match = await asyncio.to_thread(
                image_lookup.image_for_packages,
                wanted,
                registry=self._images,
                repositories=tuple(self.config.allowed_environments),
                pin=pin,
            )
        except workbench.MCUHomeError as refusal:
            raise _no_image_for_a_package_set(
                pins, refusal, allowed=self.config.allowed_environments
            ) from refusal
        profile = EnvironmentProfile(match=match)
        self._check_declaration(profile, context)
        fetched = await self._present(profile, on_progress=on_progress)
        return EnvironmentProfile(match=match, fetched=fetched)

    def _concrete_packages(self, environment: Any) -> dict[str, PackageMember]:
        """The packages **this host** needs, out of what the context pins.

        A context pins the tools package by its *family* — that is what
        lets one context build the same firmware on hosts of two
        architectures — while an image contains one platform's package
        and declares it by its concrete name. The resolution is the
        workbench's own (:func:`~mcuhome.workbench.resolve_pins.concrete_package`,
        the same call a local build provisions from, which also checks
        the pinned hash against the family's entry), asked here rather
        than inside the image lookup so that a package this host cannot
        resolve is answered as a package and not as a missing image.

        The operator's own directories are searched first and MCUHome's
        package registry behind them, exactly as the SDK is acquired: a
        host that mirrors what its sessions pin resolves the set without
        a network.
        """
        wanted: dict[str, PackageMember] = {}
        for package, source in (
            (environment.workspace, resolve_pins.BUILD_WORKSPACE_SOURCE),
            (environment.tools, resolve_pins.BUILD_TOOLS_SOURCE),
        ):
            found = resolve_pins.concrete_package(
                package,
                source=source,
                sources=tuple(self.config.sdk_sources),
                registry=self._package_registry(),
            )
            wanted[found.name] = PackageMember(
                name=found.name, version=found.version, sha256=found.sha256
            )
        return wanted

    def _check_declaration(self, profile: EnvironmentProfile, context: Path) -> None:
        """What the image declares, against what this context needs.

        The package set is not among the questions and does not need to
        be: the image is a candidate at all because its ``packages.``
        labels *are* the set the context pinned. What is left is the
        specification generation and the generator constraint (§9.1),
        both of which the workbench checks for a local build with the
        same call.
        """
        try:
            containerbuild.check_image(
                profile.declaration,
                reference=profile.reference,
                generator=_generator_chain(context),
            )
        except workbench.MCUHomeError as refusal:
            raise _materialization_refusal(refusal) from refusal

    async def _present(self, profile: EnvironmentProfile, *, on_progress: LineSink | None) -> bool:
        """Get those exact bytes onto this host, or refuse. Answers whether it fetched.

        The image is addressed by the digest of the manifest whose labels
        were just read, so what is fetched is what was checked and never
        a tag that has moved since.
        """
        reference = profile.match.reference
        if await asyncio.to_thread(self.runtime.present, profile.runnable):
            return False
        if not self.config.auto_pull:
            raise SessionError(
                "version.builder-unsatisfiable",
                f"The build environment {profile.reference} is not on this host and this "
                "server does not fetch build environments. Its operator places the images "
                "it serves deliberately.",
                environment=profile.reference,
                digest=profile.digest,
            )
        logger.info("fetching build environment %s", profile.reference)
        relay = on_progress if on_progress is not None else (lambda _line: None)
        try:
            fetched = await asyncio.to_thread(
                containerbuild.ensure_image, self.runtime, reference, on_line=relay
            )
        except workbench.MCUHomeError as failed:
            # No network, a registry that wants a login, a digest nothing
            # answers to. All of them come back, which is what
            # `retryable` promises — and the reason itself was already on
            # the client's screen, because the pull's own output was
            # relayed while it happened.
            raise SessionError(
                "version.builder-unfetchable",
                f"This server could not fetch the build environment {profile.reference}.",
                environment=profile.reference,
                digest=profile.digest,
                problem=str(failed),
            ) from failed
        return bool(fetched)

    def _require_runtime(self) -> None:
        """A container runtime, or the two refusals that tell them apart."""
        try:
            containerbuild.preflight(self.runtime, env={})
        except workbench.MCUHomeError as refusal:
            raise SessionError(
                "builder.runtime-unavailable",
                str(refusal.message),
                problem=str(refusal),
            ) from refusal

    def _package_registry(self) -> Any:
        """The registry a session's packages come from — one for this process.

        MCUHome's own, checked against the trust anchor this workbench
        ships, and nothing else. There is deliberately no flag and no
        configuration file for it: a build server is an operator's
        machine and not a project, it has no ``secrets/trust-anchor/`` to
        read, and an anchor an operator could point somewhere else would
        be a trust decision made in a place nobody looks. Local package
        directories stay what they are — the operator's own mirror,
        searched first.

        Deferred, like every other caller's
        (:func:`~mcuhome.workbench.packageregistry.registry_factory`): a
        session whose packages are all in the operator's directories
        never opens a socket.
        """
        if self._registry is not None:
            return self._registry
        domain = packageregistry.OFFICIAL_BASE_DOMAIN
        anchor = packageregistry.BUNDLED_ANCHOR_DIR / f"{domain}.json"
        self._registry = packageregistry.registry_factory(
            domain,
            # Never read: the anchor below replaces the project's own
            # file entirely, and this server has no project.
            project_root=self.config.context_root,
            settings=(packageregistry.RegistrySettings(base_domain=domain, anchor=anchor),),
            # Under the context root and **outside every session**: the
            # documents a registry serves are verified once and are the
            # *server's*, not any one session's — a cache thrown away
            # with a session would be re-fetched by the next one. The
            # context root is the directory this server was given to own,
            # which makes it the one place an operator has to know about.
            into=self.config.context_root / REGISTRY_CACHE_DIR,
            on_warning=lambda line: logger.warning("registry: %s", line),
        )
        return self._registry

    # ----------------------------------------------------------------
    # The session's build environment
    # ----------------------------------------------------------------

    async def _session_environment(self, session: Any) -> EnvironmentProfile:
        """The image this session was answered with, still on this host.

        The whole of "one session, one build environment": the profile is
        the one :meth:`resolve_image` produced at ``send-context``, held
        on the session and taken off it rather than chosen again. What is
        checked here is only that it is still present, because a build
        that started against an image removed in between would fail
        somewhere unhelpful.

        **The frozen manifest does not record it, and cannot.** A context
        pins the environment's *packages* and its identity is computed
        over them; an image is one delivery of that set, and writing the
        delivery into the document that defines the identity would make
        two builds of one context on two hosts two different contexts.
        Which delivery ran is answered where it belongs — at
        ``send-context``, and in the verdict a client keeps — rather than
        in the record of what was built.
        """
        profile = session.image
        assert isinstance(profile, EnvironmentProfile)  # noqa: S101 - resolve_image's own type
        await asyncio.to_thread(self._require_runtime)
        if await asyncio.to_thread(self.runtime.present, profile.runnable):
            return profile
        raise SessionError(
            "version.builder-unavailable",
            f"The build environment {profile.reference} is no longer on this host. This "
            "session was opened against it, so another image of the same line is not a "
            "substitute: the firmware would be attributed to a context that does not "
            "describe it.",
            environment=profile.reference,
            digest=profile.digest,
        )

    async def ensure_runtime(
        self, session: Any, pins: ContextPins, *, context_id: str
    ) -> SessionRuntime:
        """The session's build environment, materialized once and reused.

        Two things happen here and nothing else: the SDK the context
        pinned is acquired and unpacked, and a builder session is created
        against the image this session was answered with. Everything
        after it — the tree of §4, the request document, the liveness
        ladder, the judgement — belongs to the workbench's session object
        and is the same code a local container build runs.

        Materialization stays **lazy**: the first command that needs an
        environment is ``build``, and a session that never builds should
        not pay for an SDK fetch.

        Off the event loop, because underneath it hashes a
        multi-gigabyte package, streams a zstd decompression to disk and
        untars it. On the loop that would stall every other session,
        every other connection and the WebSocket heartbeat, which drops
        unrelated clients after thirty seconds.
        """
        existing = self._runtimes.get(session.id)
        if existing is not None:
            return existing
        paths: SessionPaths = session.paths
        profile = await self._session_environment(session)
        paths.prepare_backend()
        limits = session_limits(self.config)
        started: list[str] = []
        try:
            builder = await asyncio.to_thread(
                self._materialize,
                paths,
                pins,
                profile,
                context_id=context_id,
                session_id=session.id,
                limits=limits,
                started=started,
            )
        except workbench.MCUHomeError as refusal:
            raise _materialization_refusal(refusal) from refusal
        runtime = SessionRuntime(
            session_id=session.id,
            image=profile,
            paths=paths,
            builder=builder,
            runtime=self.runtime,
            started=started,
        )
        self._runtimes[session.id] = runtime
        logger.info(
            "session %s: build environment %s (context %s, %s)",
            session.id,
            profile.reference,
            context_id,
            _described(limits),
        )
        return runtime

    def _materialize(
        self,
        paths: SessionPaths,
        pins: ContextPins,
        profile: EnvironmentProfile,
        *,
        context_id: str,
        session_id: str,
        limits: BuildLimits,
        started: list[str],
    ) -> Any:
        """The blocking half of :meth:`ensure_runtime`, in a worker thread.

        The SDK comes from the operator's directories first and from
        MCUHome's package registry after them, and it is verified against
        the hash the context pins either way — a package that hashes to
        something else is not the pinned SDK, wherever it was found.
        """
        sdk = packagefetch.acquire_sdk(
            version=pins.sdk.version,
            sha256=pins.sdk.sha256,
            sources=tuple(self.config.sdk_sources),
            into=paths.sdk,
            registry=self._package_registry(),
        )
        return buildenvsession.BuilderSession(
            root=paths.work,
            context_dir=paths.context,
            sdk_tree=sdk.tree,
            # The image carries its own entry point at the path §4 fixes,
            # and linking over it would replace the environment's content
            # with this side's idea of it.
            entry_point=None,
            launcher=containerbuild.launcher(
                profile.runnable,
                runtime=self.runtime,
                user=current_user(),
                limits=containerbuild.ResourceLimits.of(
                    limits, pids=self.config.container_pids or containerbuild.DEFAULT_PIDS
                ),
                started=started,
            ),
            context_id=context_id,
            session_id=session_id,
            tiers=buildenvsession.cache_tiers(shared_ccache_dir=self.config.ccache_dir),
            limits=limits,
            deadline_seconds=self.config.build_deadline_seconds,
            cancel_grace_seconds=self.config.cancel_grace_seconds,
        )

    def _prepare_invocation(
        self,
        session: Any,
        runtime: SessionRuntime,
        *,
        action: str,
        context_id: str,
    ) -> InvocationRecord:
        """The workbench prepares the step; this server numbers it and remembers it.

        The split is the one the specification draws. The step's tree,
        its request document and its stop sentinel are the orchestrating
        side's and belong to the builder session. The invocation **id**,
        the session's record of it, the events file this server writes
        and the audience watching it are session-protocol duties and
        belong here.
        """
        step = runtime.builder.prepare(action) if action == ACTION_BUILD else None
        session.invocation_counter += 1
        record = InvocationRecord(
            id=f"inv-{session.invocation_counter}",
            session_id=session.id,
            action=action,
            directory=runtime.paths.invocation(f"inv-{session.invocation_counter}"),
            context_id=context_id,
            out=runtime.builder.out,
            step=step,
        )
        record.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        session.invocations[record.id] = _RUNNING
        self._records[(session.id, record.id)] = record
        return record

    async def _supervise(self, runtime: SessionRuntime, record: InvocationRecord) -> LocalOutcome:
        """Run the step through the workbench, relaying its log as it goes.

        The ladder is the builder session's — the stop sentinel first,
        SIGTERM after the grace period, SIGKILL after that, and the
        deadline entering at the top by raising the same sentinel. What
        stays here is the wire: every log line is numbered and offered to
        the session's audience.

        Off the event loop for the whole step, which is where a build
        spends its minutes. The relay is called from that thread and
        reaches the loop through
        :meth:`~asyncio.AbstractEventLoop.call_soon_threadsafe`, because
        an outbox is not thread-safe and a build log is the one thing
        written fast enough for that to matter.
        """
        del runtime
        loop = asyncio.get_running_loop()

        def on_line(line: str) -> None:
            loop.call_soon_threadsafe(self._log, record, line)

        return await asyncio.to_thread(record.step.run, on_line=on_line)

    async def _collect(self, record: InvocationRecord, outcome: LocalOutcome) -> LocalOutcome:
        """What the workbench judged, plus this server's own egress note.

        Nothing is judged twice. The result document, the exit code and
        every declared artifact — re-hashed where it actually is — were
        settled inside the builder session, which is where they are
        settled for a local build too. What is added here is a log line
        about files a step left in ``out`` without declaring them: they
        are diagnostic material, they are neither served nor deleted, and
        saying so is the only way anybody finds out they exist.
        """
        declared = tuple(outcome.artifacts)
        leftovers = [
            name
            for name in await asyncio.to_thread(artifacts.undeclared, record.out, declared)
            # The result documents are not leftovers: §6.2 puts them in
            # `out` and they are this side's to read, not artifacts a
            # step forgot to declare. Reporting them would make every
            # successful build look like one that lost something.
            if not (
                name.startswith(buildenvsession.RESULT_PREFIX)
                and name.endswith(buildenvsession.RESULT_SUFFIX)
            )
        ]
        if leftovers:
            logger.info(
                "invocation %s: %d undeclared file(s) left in out", record.id, len(leftovers)
            )
        return outcome

    async def _release_runtime(self, runtime: SessionRuntime) -> None:
        """Reap this session's containers. That, and not a signal, is what stops a build.

        ``--rm`` already removed every container whose step finished; the
        sweep is for a step that was stopped, and it is best effort
        because a failed teardown must not replace the build's own
        verdict. The builder session itself owns no process — a container
        profile's step *is* its container — so closing it is bookkeeping.
        """
        for name in list(runtime.started):
            with contextlib.suppress(Exception):
                await asyncio.to_thread(runtime.runtime.remove, name)
        runtime.started.clear()
        if runtime.builder is not None:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(runtime.builder.close)

    # ----------------------------------------------------------------
    # Invocations
    # ----------------------------------------------------------------

    def attach(
        self, session_id: str, connection: Any, *, boundary: tuple[str, int] | None = None
    ) -> None:
        """Add *connection* to a session's live stream, from *boundary* on.

        *boundary* is ``(invocation id, seq)`` and is what
        ``attach-session`` sets after it has replayed that invocation's
        events out of the file: every event of that invocation up to and
        including that ``seq`` has already been delivered as history, so
        relaying it live as well would hand the client the same event
        twice across the boundary it was told to trust. A connection
        that replayed nothing passes ``None`` and sees everything.
        """
        self._audience.setdefault(session_id, {})[connection] = boundary

    def detach(self, connection: Any) -> None:
        """Drop a closed connection from every session's stream."""
        for audience in self._audience.values():
            audience.pop(connection, None)

    def record(self, session_id: str, invocation_id: str) -> InvocationRecord | None:
        return self._records.get((session_id, invocation_id))

    async def invoke(
        self,
        session: Any,
        connection: Any,
        *,
        action: str,
        pins: ContextPins,
        context_id: str,
    ) -> InvocationRecord:
        """Start one working invocation and answer immediately (E46).

        The verb's answer is ``{invocation_id}`` and nothing else: the
        completion travels as a typed ``invocation.verdict`` event
        carrying the status and the artifact list, because a build is
        minutes to hours long and a command frame that waited for it
        would make every client's socket a build timer.

        The ``build`` verb's ``mode`` does not reach here at all: every
        step of this profile runs in a **fresh container**, which is what
        makes the specification's pristine-tree guarantee free, and a
        container that starts empty has nothing to build incrementally
        on. ``verify`` starts nothing at all — it is answered from this
        server's own measurement of the locked context, which the caller
        has already made.
        """
        if action == ACTION_VERIFY:
            return self._verify(session, connection, context_id=context_id)
        runtime = await self.ensure_runtime(session, pins, context_id=context_id)
        if runtime.busy:
            # Steps of a session run strictly one after another (§3).
            # Pre-registry, for the reason `_context_work` gives about
            # its own guard: no registered code means "this session is
            # already doing work", and inventing one is a protocol
            # decision rather than an implementation choice.
            raise protocol.ProtocolError(
                f'Session "{session.id}" is already running an invocation. One invocation '
                "at a time per session: steps of a session run one after another, and two "
                "of them at once would build against each other. Cancel it or wait for "
                "its invocation.verdict event."
            )

        record = self._prepare_invocation(session, runtime, action=action, context_id=context_id)
        runtime.busy = True
        self.attach(session.id, connection)
        self._emit(record, "invocation.started", action=action, context=context_id)
        task = asyncio.create_task(
            self._drive(session, runtime, record), name=f"mcuhome-invocation-{record.id}"
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        # Kept on the record and not only in `_tasks`, because release
        # has to wait for *this session's* invocations and no others.
        record.drive = task
        return record

    def _verify(self, session: Any, connection: Any, *, context_id: str) -> InvocationRecord:
        """``verify`` — answered here, because only this side can answer it.

        The build actions document is explicit that verifying a context
        is not an action: "the orchestrator creates the context, hashes
        it, and delivers it; the environment is forbidden to modify it.
        There is nothing an environment could confirm that the
        orchestrator does not already know from its own bytes." This
        server measures the locked context against its manifest before
        every working invocation — the caller did it a moment ago — so
        the verdict is already in hand and starting a container to hear
        it again would cost minutes and add nothing.

        It is still an *invocation*: it gets an id, an events file and a
        verdict frame, because that is what a client waits on and the
        answer to "is this context what its lock says it is" is worth
        exactly the same shape as the answer to "did it build".
        """
        runtime = self._runtimes.get(session.id)
        session.invocation_counter += 1
        invocation_id = f"inv-{session.invocation_counter}"
        paths: SessionPaths = session.paths
        record = InvocationRecord(
            id=invocation_id,
            session_id=session.id,
            action=ACTION_VERIFY,
            directory=paths.invocation(invocation_id),
            context_id=context_id,
            out=runtime.builder.out if runtime is not None else paths.work / "out",
        )
        record.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        session.invocations[record.id] = _RUNNING
        self._records[(session.id, record.id)] = record
        self.attach(session.id, connection)
        outcome = LocalOutcome(
            action=ACTION_VERIFY,
            context_id=context_id,
            exit_code=0,
            status=STATUS_SUCCESS,
            successful=True,
        )
        record.outcome = outcome
        session.invocations[record.id] = _FINISHED
        session.touch()
        # **After the verb's own answer, and that is the whole reason
        # this is deferred.** The frames of one connection go out in the
        # order they were queued, and this invocation is over before the
        # handler returns — so queueing them here would put the verdict
        # of an invocation on the wire in front of the frame that first
        # names its id. The callback runs on the next turn of the loop,
        # by which time the result frame is queued.
        asyncio.get_running_loop().call_soon(self._answer_verify, record, outcome, context_id)
        return record

    def _answer_verify(
        self, record: InvocationRecord, outcome: LocalOutcome, context_id: str
    ) -> None:
        """The two frames a verify produces, once its own answer has gone out."""
        self._emit(record, "invocation.started", action=ACTION_VERIFY, context=context_id)
        self._emit_verdict(record, outcome)

    async def _drive(self, session: Any, runtime: SessionRuntime, record: InvocationRecord) -> None:
        """Run the invocation to its end, whatever its end turns out to be.

        Owned by this backend and **not** by the connection that started
        it, which is the mechanical half of "connection loss is not
        abandonment": a client may drop its socket, and the build keeps
        going, keeps writing into a record a reattaching client can still
        read.
        """
        outcome: LocalOutcome | None = None
        try:
            outcome = await self._supervise(runtime, record)
        except Exception:
            logger.exception("invocation %s failed to run", record.id)
        finally:
            runtime.busy = False
        if outcome is None:
            outcome = LocalOutcome(
                action=record.action,
                context_id=record.context_id,
                exit_code=None,
                problems=("the invocation did not run",),
            )
        else:
            outcome = await self._collect(record, outcome)
        record.outcome = outcome
        record.artifacts = tuple(outcome.artifacts)
        session.invocations[record.id] = _FINISHED
        # The idle clock counts absent commands, and the command that
        # started this invocation was sent before it ran: a fifteen-minute
        # build would end into a session already minutes past its idle
        # timeout, and the next verb — `get-artifact`, the one that
        # collects what the build produced — would be refused
        # `session.expired`. Observed exactly so, on a build that had
        # just finished linking. Finishing work is activity.
        session.touch()
        self._emit_verdict(record, outcome)

    def _emit_verdict(self, record: InvocationRecord, outcome: LocalOutcome) -> None:
        """The one frame a client is waiting for, live and on disk.

        It is written into the events file as well as sent, because that
        file is what ``attach-session`` replays: a client whose socket
        died during the build reconnects, asks for this invocation's
        events, and finds the verdict it missed. It is the only frame
        that is never dropped when an outbox is full — this server's own
        judgement exists in no other place.
        """
        self._emit(
            record,
            "invocation.verdict",
            drop_when_full=False,
            **self._verdict(outcome, record),
        )

    def _verdict(self, outcome: LocalOutcome, record: InvocationRecord) -> dict[str, Any]:
        """The payload of the ``invocation.verdict`` frame (E46, E58).

        It carries the status and the artifact list, plus the two things
        a client cannot get anywhere else: the context id **this server**
        computed — attribution always uses that one — and, on a failure,
        the session protocol's own error envelope.

        ``status`` is the pessimistic reading. A result document that
        says ``success`` after a non-zero exit, or a zero exit after
        anything else, is §6.3's contradiction and fails the step either
        way; the verdict says so and carries the violation beside it, so
        that a client can tell a misbehaving *environment* from a failed
        build.
        """
        status = _wire_status(outcome, record)
        payload: dict[str, Any] = {
            "session_id": record.session_id,
            "invocation_id": record.id,
            "action": record.action,
            "status": status,
            "context": record.context_id,
            "artifacts": [entry.to_dict() for entry in outcome.artifacts],
        }
        if outcome.violation is not None:
            payload["environment_violation"] = outcome.violation
        # A cancelled invocation carries no envelope, exactly as a
        # successful one does: the status already says everything there
        # is to say, and an envelope beside it would be a second
        # spelling of it.
        if status in (STATUS_SUCCESS, STATUS_CANCELLED):
            payload["error"] = None
            return payload
        payload["error"] = self._envelope(outcome, record, status=status)
        return payload

    def _envelope(
        self, outcome: LocalOutcome, record: InvocationRecord, *, status: str
    ) -> dict[str, Any]:
        """One failed invocation as the session protocol's error envelope.

        Three cases, and each is a different thing to do about it.
        ``unsupported`` is the environment saying that no environment of its kind can do
        this (§6.2), which is a statement about the *environment* and
        sends a client looking for another one. No result document at all
        is an infrastructure failure — "a step that produced no readable
        result document failed, whatever it exited with" — and is the one
        code here that is retryable. Everything else is a failed build.

        The environment's own message is carried in the details, bounded
        and stripped, under a name that says whose sentence it is.
        """
        if status == STATUS_UNSUPPORTED:
            return errors.envelope(
                "version.builder-unsatisfiable",
                "The build environment serving this session answered that no environment "
                "of its kind can do this. Its own message is in the details.",
                session_id=record.session_id,
                invocation_id=record.id,
                exit_code=outcome.exit_code,
                environment_message=_message_of(outcome),
                problems=list(outcome.problems),
            )
        if outcome.result is None:
            return errors.envelope(
                "builder.crashed",
                "The build environment ended without writing a result document. That is "
                "an infrastructure failure rather than a verdict on the context: a step "
                "that produced no readable result document failed whatever it exited "
                "with, and the same invocation may succeed on a retry.",
                session_id=record.session_id,
                invocation_id=record.id,
                exit_code=outcome.exit_code,
                problems=list(outcome.problems),
            )
        return errors.envelope(
            "builder.failed",
            f"The {record.action} in this session's build environment did not succeed. "
            "The environment's own message is in the details; the raw log stream of this "
            "invocation carries what it printed.",
            session_id=record.session_id,
            invocation_id=record.id,
            status=outcome.status,
            exit_code=outcome.exit_code,
            environment_message=_message_of(outcome),
            environment_violation=outcome.violation,
            problems=list(outcome.problems),
        )

    def signal_cancellation(self, session_id: str, invocation_id: str) -> None:
        """Raise the stop sentinel of one invocation. Never raises for asking twice.

        The sentinel is the builder session's own file and is never named
        in a request document: generation 3 defines no cooperative
        cancellation, so what stops a step is a signal, and this is only
        how the decision to send one reaches the supervising loop.

        An invocation this server answers itself has no step and nothing
        to stop; the record is marked all the same, so the verdict that
        follows says ``cancelled`` rather than pretending nothing was
        asked.
        """
        record = self._records.get((session_id, invocation_id))
        if record is None:
            return
        record.cancelled = True
        if record.step is not None:
            record.step.stop()

    def _log(self, record: InvocationRecord, line: str) -> None:
        """One line of the raw log, with the counter that makes drops visible."""
        record.log_seq += 1
        self._publish(
            record,
            protocol.log_frame(
                {
                    "session_id": record.session_id,
                    "invocation_id": record.id,
                    "seq": record.log_seq,
                    "line": line,
                }
            ),
            drop_when_full=True,
        )

    def _emit(
        self, record: InvocationRecord, name: str, *, drop_when_full: bool = True, **fields: Any
    ) -> None:
        """One event of this invocation: numbered, written down, and sent.

        **The events are this server's own.** The build environment has
        no event channel — the specification gives it a request document,
        a result document and a log stream, and nothing else — so what a
        client follows is what this server did: the invocation started,
        and the verdict it reached. Numbering them is what makes the file
        replayable, because ``attach-session`` resumes at a ``seq``.

        Written before it is sent, so that a frame a full outbox drops is
        still in the file the reconnecting client reads.
        """
        record.event_seq += 1
        payload = {
            "event": name,
            "seq": record.event_seq,
            "session_id": record.session_id,
            "invocation_id": record.id,
            **fields,
        }
        with contextlib.suppress(OSError), record.events.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self._publish(record, protocol.event_frame(name, payload), drop_when_full=drop_when_full)

    def _publish(
        self, record: InvocationRecord, frame: dict[str, Any], *, drop_when_full: bool = False
    ) -> None:
        """Put one frame on every connection watching this session.

        *drop_when_full* is the difference between the two streams and
        it is E46's shape read against the transport's. Program events
        and log lines are offered — dropping the oldest rather than
        applying backpressure through the log reader and from there into
        the compiler — and both survive it: the log carries a counter
        that makes a gap visible, and the events file on disk **is** the
        replay buffer, so ``attach-session`` can fetch the gap. The
        ``invocation.verdict`` frame is sent instead, because it is the
        one frame a client is waiting on and there is no second way to
        learn it: it is this server's own judgement and is in no events
        file, so a drop would lose it for good.

        A connection that joined through ``attach-session`` carries a
        replay boundary, and a frame this server already delivered to it
        as history is not delivered again as news.
        """
        for connection, boundary in tuple(self._audience.get(record.session_id, {}).items()):
            if _already_replayed(frame, record, boundary):
                continue
            if drop_when_full:
                connection.offer(frame)
            else:
                # Tracked rather than fired and forgotten: an untracked
                # task that is still pending when the loop closes is a
                # warning nobody can act on, and this one is the frame a
                # client is waiting for.
                task = asyncio.ensure_future(connection.send(frame))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)

    # ----------------------------------------------------------------
    # Teardown
    # ----------------------------------------------------------------

    async def release(
        self, session_id: str, *, reaped: str | None = None, wait: float | None = None
    ) -> bool:
        """Reap the session's build environment and wait for its invocation.

        Never raises. Answers whether the session is **released**: the
        container is gone and no invocation of it is running any more.
        ``False`` is the one case a caller has to act on — the supervisor
        did not come back inside the ladder — and it means the session's
        directory must stay where it is.

        *reaped* is why the session was taken away, and it is set for a
        session this server took rather than one a client closed: such a
        session owes its audience an explanation, while ``close-session``
        is the client's own act and process shutdown reaches nobody
        anyway.

        **Every caller comes through**
        :func:`~mcuhome.buildserver.sessions.release_session`, which is
        the session layer's half of the same teardown: it raises the
        cancel sentinel before this runs and deletes the session's
        directory after it. The two halves are one thing done in one
        order, because the environment and the directory are one thing:
        in the ``container`` profile the directory *is* the container's
        mounts, and in the ``subprocess`` profile it is the working area
        of a child of this process. Either way, something still running
        against a deleted tree is the one state neither half can recover
        from.

        **The order is the guarantee**, and the wait is the rung that was
        missing from it. The container is removed first, because that —
        and not a signal — is what stops a build; then this waits for the
        invocation's own task, which is what holds the worker thread the
        supervisor runs in; only then is the session forgotten and its
        directory the caller's to delete. Removing the container ends the
        step it supervises, so the wait is normally one poll long;
        it is bounded by :func:`_ladder_seconds` for the case where it is
        not.

        A session that did not release keeps its runtime and its records:
        nothing here has been forgotten, so the same call can be made
        again — by the sweep, which retries every session on its release
        list, or by process shutdown — and it walks the same three steps
        against the same state.

        *wait* overrides the ladder for a caller that has a deadline of
        its own. Process shutdown is the one that does: it releases every
        session in turn under **one** total budget, because a server
        that stopped is expected to be gone rather than to spend the
        ladder once per session.
        """
        runtime = self._runtimes.get(session_id)
        if reaped is not None:
            self._announce_reaping(session_id, reaped)
        # Before the wait, so that the verdict this invocation is about
        # to publish reaches nobody: the audience was told why the
        # session went, and a second verdict frame would contradict the
        # first.
        self._audience.pop(session_id, None)
        if runtime is not None:
            await self._release_runtime(runtime)
        if not await self._join_invocations(session_id, wait):
            return False
        self._runtimes.pop(session_id, None)
        for key in [key for key in self._records if key[0] == session_id]:
            self._records.pop(key, None)
        return True

    async def _join_invocations(self, session_id: str, wait: float | None = None) -> bool:
        """Wait for every running invocation of *session_id*. Never raises.

        The task is not cancelled when the wait runs out, and that is
        deliberate: it is blocked in :func:`asyncio.to_thread`, where
        cancelling the task abandons the worker thread instead of
        stopping it — which is precisely the state this method exists to
        rule out. So a wait that ran out answers ``False`` and leaves the
        thread the only thing that can end it: the ladder, whose own last
        rung gives up on a process that survived SIGKILL.
        """
        tasks = {
            record.drive
            for (owner, _), record in self._records.items()
            if owner == session_id and record.drive is not None and not record.drive.done()
        }
        if not tasks:
            return True
        seconds = _ladder_seconds(self.config) if wait is None else wait
        _, pending = await asyncio.wait(tasks, timeout=seconds)
        if pending:
            logger.error(
                "session %s: %d invocation(s) still running after %.1fs; the session's "
                "directory is kept",
                session_id,
                len(pending),
                seconds,
            )
            return False
        return True

    def _announce_reaping(self, session_id: str, reaped: str) -> None:
        """Tell whoever is still listening that this session was taken away.

        A client waits for one frame and one frame only — the
        ``invocation.verdict`` of the invocation it started — and this
        server used to drop the audience without sending anything, so a
        session reaped under a running build left the client waiting on a
        verdict that could never arrive. The socket stays open, so not
        even a connection loss ends the wait: measured at 56 minutes
        before it was killed by hand.

        So the verdict is sent, as a failure carrying the session layer's
        own ``session.expired`` — the code whose summary has always been
        "the session's lease or hard TTL ran out and it was reaped".
        Only for invocations this server never judged: one that already
        has an outcome has already had its verdict.
        """
        for (owner, _), record in list(self._records.items()):
            if owner != session_id or record.outcome is not None:
                continue
            self._publish(
                record,
                protocol.event_frame(
                    "invocation.verdict",
                    {
                        "session_id": record.session_id,
                        "invocation_id": record.id,
                        "action": record.action,
                        "status": STATUS_FAILURE,
                        "context": record.context_id,
                        "artifacts": [],
                        "error": errors.envelope(
                            "session.expired",
                            f"This session was reaped ({reaped}) while its invocation was "
                            f"still running, so the build was stopped and its directory "
                            f"deleted. Nothing was delivered.",
                            session_id=session_id,
                            invocation_id=record.id,
                        ),
                    },
                ),
            )

    async def release_all(self, *, deadline: float) -> None:
        """Every build environment still held, after shutdown released them.

        The last pass of
        :func:`~mcuhome.buildserver.sessions.release_every_session`,
        which releases every session this process has and therefore
        every runtime one of them named. What is still here afterwards
        is one of two things: the runtime of a session whose release
        just ran out of the shutdown budget, or — if the two halves ever
        disagree about what exists — a runtime nothing else would have
        reached. Both get one more attempt and, failing that, a log
        line: a container that outlives this process is one an operator
        has to find by its label, and the id in the log is where that
        search starts.

        *deadline* is a :func:`time.monotonic` value: the caller's
        remaining budget, shared by whatever is left here, and usually
        already spent by the time this runs.
        """
        for session_id in list(self._runtimes):
            if not await self.release(session_id, wait=max(0.0, deadline - time.monotonic())):
                logger.error("session %s was not released before shutdown", session_id)


# --------------------------------------------------------------------------
# Refusals, and what a verdict is made of
# --------------------------------------------------------------------------


def _materialization_refusal(refusal: Exception) -> SessionError:
    """One of the workbench's typed refusals, as this protocol says it.

    The workbench refuses in words, because its first caller is a person
    at a terminal; the session protocol refuses in codes, because its
    caller is a program deciding whether to try another server. The
    translation is a table of **types** and not of messages — matching on
    wording is how a rephrased sentence becomes a wrong error code — and
    the words are carried into the details, where they are the most
    useful thing in the frame.

    Anything unrecognized stays ``error.internal`` by not being caught
    here: a workbench failure this server has no code for is a defect on
    this side, and dressing it as a client-facing refusal would send a
    client looking for a mistake it did not make.
    """
    if isinstance(refusal, workbench.SdkUnavailable):
        # The pin, and **not** the directories that were searched: those
        # are this operator's filesystem, and a client that pinned a
        # package this server does not have has no use for the paths it
        # is not in. The workbench carries them because a person at a
        # terminal is looking at their own machine; here they stop.
        return SessionError(
            "sdk.unavailable",
            f"This server has no {SDK_PACKAGE_NAME} {refusal.version} whose bytes hash to "
            f"{refusal.sha256}. Its SDK packages come from the directories its operator "
            "configured and from MCUHome's own package registry, and the url in a context "
            "is a hint that is never fetched.",
            version=refusal.version,
            sha256=refusal.sha256,
        )
    if isinstance(refusal, packageregistry.PackageRegistryError):
        # A package this server could not get: the operator's own
        # directories do not hold it and MCUHome's registry did not
        # answer for it — because it publishes no such package, or
        # because it could not be read at all. Both are "this server has
        # no such package", which is what `sdk.unavailable` says; the
        # registry's own sentence travels in the details, where it is
        # the difference between the two.
        return SessionError(
            "sdk.unavailable",
            "This server could not get a package this context pins. Its packages come "
            "from the directories its operator configured and from MCUHome's own package "
            "registry behind them.",
            problem=str(refusal),
        )
    if isinstance(refusal, workbench.EnvironmentUnavailable):
        code = "version.builder-unsatisfiable"
    elif isinstance(refusal, workbench.EnvironmentUnusable):
        code = "version.builder-unavailable"
    else:
        raise refusal
    return SessionError(code, str(refusal.message), problem=str(refusal))


def _unresolvable_packages(refusal: Exception) -> SessionError:
    """A package this server could not resolve, whatever went wrong with it.

    Three things can: the sources do not carry the version, one of them
    carries it under *other bytes* — which is never shopped around for —
    or the registry behind them could not be read. All three are
    ``sdk.unavailable``: this server has no such package, and the
    workbench's own sentence in the details is what says which of the
    three it was.

    The typed refusals that carry their own detail shape keep it
    (:func:`_materialization_refusal`); everything else is a package
    refusal in words, and a refusal in words is still a refusal about a
    package rather than a defect on this side.
    """
    try:
        return _materialization_refusal(refusal)
    except Exception:  # noqa: BLE001 - a refusal this table does not know by type
        return SessionError(
            "sdk.unavailable",
            "This server could not resolve a package this context pins. Its packages "
            "come from the directories its operator configured and from MCUHome's own "
            "package registry behind them.",
            problem=str(refusal),
        )


def _no_image_for_a_package_set(
    pins: ContextPins, refusal: Exception, *, allowed: Sequence[str]
) -> SessionError:
    """No allowed image declares the package set this context pins.

    The workbench's own refusal already names every candidate that was
    tried and why each was rejected — an image built from the same
    versions but other bytes reads identically to one that was never
    published in a one-line message, and the difference is the whole
    point — so it is carried into the details verbatim rather than
    summarized away. What this adds is the operator's side of it: which
    repositories this server is allowed to look in at all.
    """
    described = pins.build_environment.described()
    return SessionError(
        "version.builder-unsatisfiable",
        f"No image declares the pinned package set. This context asks for {described}, "
        "and no image in the repositories this server may serve is assembled from exactly "
        "those packages.",
        required=described,
        allowed=list(dict.fromkeys(allowed)),
        problem=str(refusal),
    )


def _message_of(outcome: LocalOutcome) -> str:
    """The environment's own message (§6.2), bounded and stripped.

    Free text written by the environment for a human, so it is the one
    untrusted string in the document: control characters go, and the
    length is capped, because it ends up in an error frame this server
    signs its name under.
    """
    document = outcome.result or {}
    found = document.get("message")
    if not isinstance(found, str):
        return ""
    cleaned = "".join(character for character in found if character >= " " or character == "\n")
    return cleaned[:_MAX_MESSAGE]


#: How much of the environment's untrusted ``message`` this server
#: carries into an envelope. Not a number any document fixes.
_MAX_MESSAGE = 2000


#: Mirrors of :mod:`mcuhome.buildserver.sessions`' invocation states.
#: Spelled here rather than imported to keep the import edge one-way:
#: the verbs call the backend, the backend never calls the verbs.
_RUNNING = "running"
_FINISHED = "finished"


def _already_replayed(
    frame: dict[str, Any], record: InvocationRecord, boundary: tuple[str, int] | None
) -> bool:
    """Whether *frame* is inside a connection's own replayed history.

    A replay boundary is a position in this server's numbered event
    stream, so the ``seq`` test is the load-bearing one: the log is not
    replayed at all and carries a counter of its own, and a frame without
    a number has no position in the stream a boundary is stated against.
    """
    if boundary is None:
        return False
    invocation_id, seq = boundary
    if record.id != invocation_id or frame.get("type") != protocol.TYPE_EVENT:
        return False
    found = frame.get("payload", {}).get("seq")
    if isinstance(found, bool) or not isinstance(found, int):
        return False
    return found <= seq


def _wire_status(outcome: LocalOutcome, record: InvocationRecord) -> str:
    """The status a client is told, which is the pessimistic one.

    ``cancelled`` first, because it is the only one this server knows
    something about that the document cannot: a stopped step writes no
    result document, and reporting that as a plain failure would hide the
    fact that the failure was asked for. Otherwise the workbench's own
    verdict decides — success only when every condition held, and the
    document's own status where it says something other than success.
    """
    if record.cancelled and not outcome.successful:
        return STATUS_CANCELLED
    if outcome.successful:
        return STATUS_SUCCESS
    if outcome.status and outcome.status != STATUS_SUCCESS:
        return outcome.status
    return STATUS_FAILURE


def _generator_chain(context: Path) -> str:
    """The generator chain of the context at *context*, or a refusal.

    Read with the workbench's own reader, so that the one place that
    knows what a chain looks like is the one place that parses it.

    **A context without one is refused here**, and that is the
    specification's own rule rather than this server's strictness: §9
    makes ``build-context.json`` and a readable ``generator`` in it part
    of what a build context *is*, and says the orchestrator refuses a
    context that has neither "before your environment is started". It has
    to be this side, too, because the chain is what §9.1's constraint
    check is made against: a missing chain read as an empty one would
    turn "this environment accepts nothing of yours" into a check that
    silently passed.
    """
    try:
        return format_generator_chain(read_generator_chain(context / BUILD_CONTEXT_FILE))
    except MCUHomeError as unreadable:
        raise SessionError(
            "context.missing",
            f"This build context carries no readable {BUILD_CONTEXT_FILE}. It is what "
            "says which tool wrote the context, and a build environment declares which "
            "tools' contexts it accepts — without it there is nothing to hold that "
            "declaration against, so no environment may be started for it.",
            problem=str(unreadable),
        ) from unreadable


def _described(limits: BuildLimits) -> str:
    """The budget one step of this session is given, for the log."""
    cpus = "the machine" if limits.cpus is None else f"{limits.cpus:g} cpus"
    memory = "no memory bound" if limits.memory_bytes is None else f"{limits.memory_bytes} bytes"
    return f"{cpus}, {memory}"


def session_limits(config: Config) -> BuildLimits:
    """What one step of this server's sessions is given, and held to.

    Both halves of it, from one place. The numbers are written into every
    request document as the recommendation an environment sizes itself
    from (§6.1), and set on every container as the hard limits the
    runtime holds it to — the orchestrating side cannot trust an
    environment to stay inside a recommendation, so the guard is outside
    it, and §11 tells the environment plainly that whatever budget was
    set may be enforced hard.

    The defaults are this server's own: all of the host's CPUs, and the
    memory ceiling ``--container-memory`` states. An operator moves
    either with the flags that already exist; ``--container-memory ""``
    is the operator saying the host is not to be bounded by memory, and
    it is honoured as stated rather than replaced by a measurement.
    """
    machine = buildenvsession.host_limits()
    cpus = machine.cpus
    if config.container_cpus:
        try:
            cpus = float(config.container_cpus)
        except ValueError as broken:
            raise BuildError(
                f'"{config.container_cpus}" is not a number of CPUs.',
                hint="--container-cpus takes a number of cores, fractions allowed — 2, 1.5",
            ) from broken
    return BuildLimits(
        cpus=cpus if cpus > 0 else None,
        memory_bytes=buildenvsession.memory_bytes(
            config.container_memory, option="--container-memory"
        ),
    )
