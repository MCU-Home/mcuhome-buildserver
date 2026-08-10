# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The container backend: one session, one container, and what runs in it.

This is the part of the build server that build-container contract §1.2
calls a backend in the ``container`` profile: "the backend materializes
one container per session and invokes the program inside it", with every
isolation guarantee of ADR 0019 §8 — one session = one container
instance = the trust boundary, no network, per-session limits.

**It is a backend and never a build environment.** Nothing here compiles
anything; it starts a container, writes a request document, execs a
program and reads what came back. The build environment is the image's,
and the one piece of MCUHome code that runs inside it arrives with the
SDK mount rather than from this repository.

The layering, from the outside in:

* :mod:`mcuhome_buildserver.sessions` owns the verbs and the state
  machine and calls into this module through ``state.backend``;
* this module owns the *lifecycle* — image discovery, the session's
  container, the per-invocation directories, liveness, the event and log
  relay, and what an invocation is worth at the end of it;
* :mod:`mcuhome_buildserver.container` owns docker,
  :mod:`mcuhome_buildserver.abi` owns the two documents,
  :mod:`mcuhome_buildserver.events` owns the NDJSON stream,
  :mod:`mcuhome_buildserver.artifacts` owns egress, and
  :mod:`mcuhome_buildserver.sdkstore` owns the one external input.

**Three things this backend deliberately does not do**, each because a
decision took the premise away.

*No host-side overlay* (E47). Contract §6.2's writable view of a patched
layer costs nothing in this profile: the image's trees are writable
inside the container by construction, one session is one container, and
the container is discarded when the session closes — so a patched
``zephyr`` cannot outlive the session that patched it. This server
therefore asserts ``writable: true`` for an in-image tree at the path
``describe`` reported, and the assertion is truthful because the
container's own copy-on-write layer makes it so. No ``docker cp``, no
volume, no overlayfs.

*No pull.* The digest pin is resolved against the **local** image
inventory (product-owner decision). ADR 0019 §8 permits pulling from
configured registries; contract v1 of this server has no registry
configuration, so an image that is not on this host is
``version.builder-unavailable`` — a final answer rather than a fetch
this server quietly declined to make.

*No signing, and no key.* The program is forbidden to sign, this server
holds no private key, and ``keys/signing.pub`` is the client's to put in
the context. A ``build`` against a context without it fails typed inside
the container (``error.context.incomplete``) and this backend relays the
refusal instead of retrying it.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcuhome_buildserver import abi, artifacts, container, errors, events, protocol, sdkstore
from mcuhome_buildserver.abi import Artifact, TreeEntry
from mcuhome_buildserver.config import Config
from mcuhome_buildserver.contextstore import ContextPins, SessionPaths, derive_patch_layers
from mcuhome_buildserver.errors import SessionError
from mcuhome_buildserver.ingress import IngressCaps

__all__ = [
    "ACTION_BUILD",
    "ACTION_DESCRIBE",
    "ACTION_VERIFY",
    "ContainerBackend",
    "ImageProfile",
    "InvocationRecord",
    "SessionRuntime",
]

logger = logging.getLogger(__name__)

ACTION_DESCRIBE = "describe"
ACTION_VERIFY = "verify"
ACTION_BUILD = "build"

#: The contract version this server implements. §7.1.1: "A backend that
#: does not implement the value it finds here MUST NOT invoke a working
#: action on this program — everything else in the result document is
#: described by a specification the backend does not have."
CONTRACT_VERSION = 1

#: How often the event file is polled while an invocation runs. Fast
#: enough that a client sees phases as they happen, slow enough that a
#: two-hour build costs a bounded number of stats. It is not a contract
#: number — §11 leaves liveness and timeout policy explicitly free.
_POLL_SECONDS = 0.2

#: How long SIGTERM has before SIGKILL. The last rung of the liveness
#: ladder and the shortest, because by the time it is reached the
#: program has already ignored a sentinel it agreed to poll and a signal
#: it agreed to handle.
_KILL_AFTER_SECONDS = 10.0

#: A ``program.id`` that can be a directory name in the shared ccache
#: store. §7.1.1 makes the id opaque — "a backend compares it for
#: equality and does nothing else with it" — so anything that is not
#: already a safe path segment simply gets no cache rather than a
#: sanitized name it never claimed.
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


# --------------------------------------------------------------------------
# What an image is, and what a session runs on
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ImageProfile:
    """One image, as ``describe`` and its labels jointly answer for it.

    Cached per image digest for the life of the server process: the
    answer is a property of the image, an image is identified by its
    digest, and a digest names bytes that do not change. A session pays
    for it once for the whole host rather than once per session, which
    is what makes container materialization stay lazy — a session that
    never builds never starts a container of its own.
    """

    facts: container.ImageFacts
    #: ``describe``'s ``program`` block, verbatim. Authoritative about
    #: what the program can do; the labels are the pre-start hint.
    program: dict[str, Any]

    @property
    def identity(self) -> str:
        found = self.program.get("id")
        return found if isinstance(found, str) else "unknown"

    @property
    def actions(self) -> tuple[str, ...]:
        found = self.program.get("actions")
        return tuple(str(name) for name in found) if isinstance(found, list) else ()

    def tree_path(self, layer: str) -> Path | None:
        """Where the image keeps *layer*, or ``None`` if it carries none.

        §7.1.1: "``null`` asks, a path requires." A concrete path is
        where the image keeps that tree **and**, for a tree the backend
        supplies, the path the backend MUST supply it at; ``null`` means
        "put it wherever you like and name it in ``trees``".
        """
        trees = self.program.get("trees")
        entry = trees.get(layer) if isinstance(trees, dict) else None
        path = entry.get("path") if isinstance(entry, dict) else None
        return Path(path) if isinstance(path, str) and path.startswith("/") else None

    def to_wire(self) -> dict[str, Any]:
        """What ``send-context`` answers about the serving container."""
        return {
            "digest": self.facts.digest,
            "contract": self.program.get("contract"),
            "program": self.identity,
            "version": self.program.get("version"),
            "actions": list(self.actions),
        }


@dataclass
class SessionRuntime:
    """The container one session builds in, and everything mounted in it."""

    session_id: str
    image: ImageProfile
    container_id: str
    paths: SessionPaths
    #: The ``trees`` block every invocation of this session writes. Fixed
    #: for the session because the patch set of a locked context cannot
    #: change (§6.2) and because mounts cannot be added to a running
    #: container.
    trees: dict[str, TreeEntry]
    patched_layers: tuple[str, ...]
    ccache: TreeEntry | None = None
    #: One invocation at a time per ``work`` (§9.1). The program cannot
    #: check it, so it is a backend duty; this flag is the whole of it.
    busy: bool = False


@dataclass
class InvocationRecord:
    """One invocation, from the id this server assigned to what it produced."""

    id: str
    session_id: str
    action: str
    directory: Path
    context_id: str
    #: The layers the context carries patches for, derived once per
    #: session and carried here because §5.4's ``layers`` row is stated
    #: against it: "MUST, on success, **for every patched layer**", and
    #: "the backend compares the block against what it expects to have
    #: been applied".
    patched_layers: tuple[str, ...] = ()
    started_at: float = field(default_factory=time.monotonic)
    #: Filled when the invocation ends. Until then the artifact list is
    #: empty, which is the truthful answer to ``get-artifact``: nothing
    #: has been declared, so nothing has been verified.
    outcome: abi.InvocationOutcome | None = None
    artifacts: tuple[Artifact, ...] = ()
    log_seq: int = 0

    @property
    def out(self) -> Path:
        return self.directory / "out"

    @property
    def result(self) -> Path:
        return self.directory / "result.json"

    @property
    def request(self) -> Path:
        return self.directory / "request.json"

    @property
    def events(self) -> Path:
        return self.directory / "events.ndjson"

    @property
    def cancel(self) -> Path:
        return self.directory / "cancel"


# --------------------------------------------------------------------------
# The backend
# --------------------------------------------------------------------------


class ContainerBackend:
    """Everything one build-server process knows about containers.

    One instance per :class:`~mcuhome_buildserver.app.ServerState`. It
    holds no session state of its own beyond what a container needs —
    the session record stays in
    :class:`~mcuhome_buildserver.sessions.Session` — because the two
    have different lifetimes: a session exists from ``open-session``,
    and its container exists from the first command that needs one.
    """

    #: The backend profile this server declares at ``open-session``
    #: (contract §1.2). ``container``, and never ``subprocess``: this
    #: process is an orchestrator, and a subprocess-profile backend
    #: would be the build environment itself.
    profile = "container"

    def __init__(self, config: Config, *, docker: container.Docker | None = None) -> None:
        self.config = config
        self.docker = container.Docker(config.docker) if docker is None else docker
        self._images: dict[str, ImageProfile] = {}
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
        """The build-container images this host can serve, for ``capabilities``.

        ADR 0019 §2 wants "available builder images (tag + digest +
        contract labels)" from a verb that is "pre-session, cheap,
        unmetered", and that is exactly what a label-filtered
        ``docker image ls`` plus one ``inspect`` costs. No ``describe``
        is run here: ``describe`` costs a container start, and a client
        asking what this server has is not yet asking any image to prove
        it.

        A runtime that cannot be reached answers an empty list rather
        than a refusal. The question is "which images can this server
        serve", the answer when there is no runtime is "none", and that
        is a fact rather than an error — the refusal belongs to the verb
        that actually needs a container, where it can be acted on.
        """
        try:
            found = await self.docker.inventory()
        except SessionError:
            return []
        return [facts.to_wire() for facts in found]

    async def resolve_image(self, pins: ContextPins) -> ImageProfile:
        """The image a context pins, described and cross-checked.

        Called from ``send-context``, which is where ADR 0019's
        amendment puts container discovery: "``send-context`` answers
        what the context determines — the serving build container's
        contract version and its command set", because only with the
        pins in hand does the backend know *which* container serves the
        session.

        Four gates, in the order that makes each one's refusal legible:
        the runtime is there; the image is on this host; ``describe``
        answers and answers conformingly; and what ``describe`` said is
        something this server can actually drive.
        """
        digest = pins.container.digest
        cached = self._images.get(digest)
        if cached is not None:
            return cached
        await self.docker.require_runtime()
        reference = f"{pins.container.image}@{digest}"
        facts = await self.docker.image(reference)
        if facts is None:
            raise SessionError(
                "version.builder-unavailable",
                f"No build container on this host answers to {reference}. This server "
                "resolves the container digest against its local image inventory and "
                "pulls nothing, so the image has to be present before a session that "
                "pins it can build.",
                digest=digest,
                image=pins.container.image,
            )
        profile = await self._describe(facts)
        self._images[digest] = profile
        return profile

    async def _describe(self, facts: container.ImageFacts) -> ImageProfile:
        """Ask the image what it is, and check the labels against it.

        ``describe`` "is **authoritative** about what the program can do.
        The image labels are a pre-start hint; a backend MUST verify
        them against ``describe`` and MUST NOT rely on a label
        ``describe`` contradicts." It also "doubles as the first
        conformance test: a program that cannot answer ``describe``
        cannot be trusted with a build" — which is why every failure
        below is the same refusal, ``version.builder-unavailable``, and
        why none of them is retryable: nothing about this image will be
        different in a second.

        **The probe directory is per call and not per image.** It is the
        same rule §5.1 step 1 states for an invocation — a
        backend-owned per-invocation directory, which "removes the data
        race the fixed path ``/ctx/.mcuhome/command.json`` had, where two
        concurrent ``docker exec`` invocations overwrote each other's
        document" — and ``describe`` is an invocation. Nothing
        serializes two of them: the memo in ``self._images`` is written
        only after this returns, and ``send-context`` runs under a
        per-session guard, so two sessions pinning the same image
        describe it concurrently. Sharing one directory would have the
        second call's ``result.unlink`` delete the first call's answer,
        which reads back as "no result document was written" and
        disqualifies a perfectly good image.
        """
        probe = self.config.context_root / ".probe" / f"describe-{uuid.uuid4().hex}"
        probe.mkdir(mode=0o700, parents=True, exist_ok=False)
        request = probe / "request.json"
        result = probe / "result.json"
        result.unlink(missing_ok=True)
        try:
            # The preamble alone: `describe` "needs only `request` and
            # `result`, never touches the context, writes nothing but the
            # result document". A backend that sent more would be
            # inviting a program to echo a field it was never promised.
            abi.write_request({"request": abi.REQUEST_VERSION, "result": str(result)}, request)
            completed = await self.docker.describe(
                image=facts.reference,
                mounts=[container.Mount(source=probe, target=probe)],
                request=request,
                user=container.current_user(),
            )
            outcome = abi.read_result(
                path=result,
                action=ACTION_DESCRIBE,
                exit_code=completed.status,
                # `describe` gets no session, so the echo rule says it
                # must not answer one — and passing `None` here is how
                # that expectation is stated rather than assumed.
                session=None,
                context_id=None,
            )
        finally:
            with contextlib.suppress(OSError):
                request.unlink(missing_ok=True)
                result.unlink(missing_ok=True)
                probe.rmdir()
        if not outcome.successful or outcome.result is None:
            raise _not_conforming(facts, "; ".join(outcome.problems) or "describe failed")
        program = outcome.result.program
        problem = _program_problem(program, facts)
        if problem is not None:
            raise _not_conforming(facts, problem)
        return ImageProfile(facts=facts, program=program)

    # ----------------------------------------------------------------
    # The session's container
    # ----------------------------------------------------------------

    async def ensure_runtime(
        self, session: Any, pins: ContextPins, *, context_id: str
    ) -> SessionRuntime:
        """The session's container, started on first use.

        "Container materialization is **lazy** — the backend may defer
        creating the container until the first command that needs one"
        (ADR 0019 §2). The first such command is ``verify`` or
        ``build``, so everything expensive happens here: the SDK is
        fetched and hash-verified, the trees are resolved against what
        ``describe`` reported, the mounts are composed and the container
        is started.

        The pins are cross-checked one last time on the way (§9.1): the
        image really carries the digest the context names, and the SDK
        package really hashes to ``mcuhome.package.sha256``. The third
        pin, ``target.board``, is compared against the pins the session
        was admitted on by
        :func:`~mcuhome_buildserver.contextstore.recheck_locked_context`
        before every invocation, which is the only place a board can be
        compared to anything on this side.
        """
        existing = self._runtimes.get(session.id)
        if existing is not None:
            return existing
        paths: SessionPaths = session.paths
        profile = await self.resolve_image(pins)
        if profile.facts.digest not in (None, pins.container.digest):  # pragma: no cover
            raise SessionError(
                "version.builder-unavailable",
                "The image this host resolved for the context's digest reports a different "
                "digest of its own. The pin names bytes, and this one does not name these.",
                digest=pins.container.digest,
                resolved=profile.facts.digest,
            )
        paths.prepare_backend()
        patched = derive_patch_layers(paths.context)
        # Off the event loop: this hashes a multi-gigabyte package,
        # streams a full zstd decompression to disk and untars it, and
        # it happens in the path of the first `verify` or `build` — the
        # commands that promise to "answer immediately" (E46). On the
        # loop it would stall every other session, every other
        # connection and the WebSocket heartbeat, which drops unrelated
        # clients after thirty seconds.
        package = await asyncio.to_thread(
            sdkstore.acquire_sdk,
            version=pins.sdk.version,
            sha256=pins.sdk.sha256,
            sources=self.config.sdk_sources,
            into=paths.sdk,
            caps=IngressCaps.from_config(self.config),
            max_bytes=self.config.max_decompressed_bytes,
        )
        trees, mounts = self._arrange_trees(profile, paths, package, patched)
        ccache, cache_mount = self._arrange_ccache(profile)
        if cache_mount is not None:
            mounts.append(cache_mount)
        container_id = await self.docker.start(
            image=profile.facts.reference,
            mounts=container.mounts_for(mounts),
            session_id=session.id,
            user=container.current_user(),
            limits=container.ResourceLimits(
                memory=self.config.container_memory,
                cpus=self.config.container_cpus,
                pids=self.config.container_pids,
            ),
        )
        runtime = SessionRuntime(
            session_id=session.id,
            image=profile,
            container_id=container_id,
            paths=paths,
            trees=trees,
            patched_layers=patched,
            ccache=ccache,
        )
        self._runtimes[session.id] = runtime
        logger.info(
            "session %s: container %s from %s (context %s)",
            session.id,
            container_id[:12],
            profile.facts.reference,
            context_id,
        )
        return runtime

    def _arrange_trees(
        self,
        profile: ImageProfile,
        paths: SessionPaths,
        package: sdkstore.SdkPackage,
        patched: tuple[str, ...],
    ) -> tuple[dict[str, TreeEntry], list[container.Mount]]:
        """Decide every ``trees`` entry and the mounts behind them (§4.1).

        **The session tree is mounted piece by piece and never
        wholesale.** One bind mount of the session root would be shorter
        and it is wrong, for a reason that only shows up when a tree has
        two paths: the SDK is unpacked into ``<root>/sdk`` and mounted
        read-only at the path ``describe`` asked for, so a root mount
        exposes the very same directory writable at ``<root>/sdk`` —
        and §4.1's ``writable: false`` is "asserted by the backend,
        never probed by the program", which makes it a claim this server
        would be making falsely. §9.1 asks for the strongest write
        protection the profile has, and in this profile that is a
        read-only bind mount with nothing shadowing it.

        So the container sees exactly what the request document names,
        each at its own host path: ``context`` read-only, ``work``
        writable, the per-invocation directories writable (mounted as
        their parent, because bind mounts are fixed when the container
        is created and an invocation directory does not exist yet — the
        parent is a mount, so every ``out``, ``tmp``, request and result
        created in it later is inside it), the SDK at its target, and
        the shared cache read-only when there is one. What is *not*
        visible any more is everything else the session directory holds:
        the upload spool, ``staging`` and — worth naming — ``downloads``,
        where ``get-artifact`` builds the archive it is about to stream.

        Three rules and one non-rule.

        **``sdk`` is always supplied**, at the path ``describe``
        declared for it or at one of this server's choosing when it
        declared ``null``. It is mounted read-only unless the ``sdk``
        layer carries patches, in which case the per-session unpacked
        tree *is* the writable view §6.2 asks for — it dies with the
        session, so no overlay and no copy is needed to keep it from
        outliving one.

        **Every patched in-image layer is supplied writable at the path
        the image reported** (E47). The container's own copy-on-write
        layer is the view; asserting ``writable: true`` for it is
        truthful rather than optimistic, because the layer makes it so
        and the container is discarded at ``close-session``. No mount is
        involved at all — the tree is already in the image.

        **An unpatched in-image tree is omitted**, which §4.1 explicitly
        permits: "the program then uses its own".

        And the non-rule: a patched layer the image reports **no** path
        for gets no entry, because there is nothing to name one at. That
        is not this backend giving up on §4.1's duty — it is the only
        honest move, and the contract has an answer for exactly it: a
        program that finds ``patches/<layer>/`` with no ``trees`` entry
        "MUST NOT proceed: ``status: "failure"``, ``reason:
        "error.layer.unknown"``". The pointer goes into ``required``
        anyway (:meth:`_document`), so a conforming program refuses
        legibly before it does any work.
        """
        mounts = [
            # §9.1: write-protected "with the strongest means its
            # profile has", which in this profile is the kernel rather
            # than a promise — and nothing else is mounted over it.
            container.Mount(source=paths.context, target=paths.context, read_only=True),
            container.Mount(source=paths.work, target=paths.work),
            container.Mount(source=paths.invocations, target=paths.invocations),
        ]
        sdk_writable = "sdk" in patched
        sdk_target = profile.tree_path("sdk") or package.tree
        mounts.append(
            container.Mount(source=package.tree, target=sdk_target, read_only=not sdk_writable)
        )
        trees: dict[str, TreeEntry] = {"sdk": TreeEntry(path=sdk_target, writable=sdk_writable)}
        for layer in patched:
            if layer == "sdk":
                continue
            declared = profile.tree_path(layer)
            if declared is None:
                continue
            trees[layer] = TreeEntry(path=declared, writable=True)
        return trees, mounts

    def _arrange_ccache(
        self, profile: ImageProfile
    ) -> tuple[TreeEntry | None, container.Mount | None]:
        """The shared cache, offered read-only or not at all (§10).

        "Shared backends MUST offer a shared cache read-only for
        untrusted work; cache warming is a deliberate operator
        invocation with a writable cache and trusted contexts only." A
        build server serves untrusted contexts by definition and has no
        warming verb, so the cache is read-only here with no option to
        change it, and the program keeps its own primary cache in
        ``work`` or ``tmp``.

        The store is laid out one subdirectory per implementation, named
        from ``describe``'s ``program.id`` — §10's own recommendation,
        "so that two foreign images cannot corrupt each other's store".
        An identity that is not a usable path segment simply gets no
        cache: a third-party program is free to call itself anything,
        and a backend that sanitized the name would be inventing an
        identity the program did not claim.
        """
        root = self.config.ccache_dir
        if root is None:
            return None, None
        identity = profile.identity
        if not _PATH_SEGMENT.fullmatch(identity):
            logger.warning("no shared cache for program id %r: not a path segment", identity)
            return None, None
        store = root / identity
        try:
            store.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:  # pragma: no cover - an operator's directory
            logger.warning("no shared cache at %s: %s", store, exc)
            return None, None
        return (
            TreeEntry(path=store, writable=False),
            container.Mount(source=store, target=store, read_only=True),
        )

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
        mode: str | None = None,
    ) -> InvocationRecord:
        """Start one working invocation and answer immediately (E46).

        The verb's answer is ``{invocation_id}`` and nothing else: the
        completion travels as a typed ``invocation.finished`` event
        carrying the status and the artifact list, because a build is
        minutes to hours long and a command frame that waited for it
        would make every client's socket a build timer.

        Everything §9.1 requires **before** an invocation happens here,
        in one place so that the list can be read against the contract:
        the per-invocation directory, an empty ``out``, an empty
        ``tmp``, the session's ``work``, the ``events`` file, the
        request document written atomically, and write protection of
        ``context`` and of every non-writable tree — the last of which
        was arranged when the container started, because a mount cannot
        be added to a running one.
        """
        runtime = await self.ensure_runtime(session, pins, context_id=context_id)
        if action not in runtime.image.actions:
            # §7.1.1: "A backend MUST NOT invoke an action absent from
            # the list." The image would answer `unsupported.action`
            # legibly, which is precisely why there is no reason to make
            # it: the refusal is already knowable.
            raise SessionError(
                "version.builder-unavailable",
                f'The build container serving this session does not implement "{action}". '
                f"It announced {sorted(runtime.image.actions)}, and describe is the only "
                "declaration of an action set there is.",
                action=action,
                actions=sorted(runtime.image.actions),
                digest=runtime.image.facts.digest,
            )
        if runtime.busy:
            # One invocation at a time per `work` (§9.1). Pre-registry,
            # for the reason `_context_work` gives about its own guard:
            # no registered code means "this session is already doing
            # work", and inventing one is a protocol decision rather
            # than an implementation choice.
            raise protocol.ProtocolError(
                f'Session "{session.id}" is already running an invocation. One invocation '
                "at a time per session: they share one work directory, and two of them in "
                "it would build against each other's tree. Cancel it or wait for its "
                "invocation.finished event."
            )

        record = self._prepare(session, runtime, action=action, context_id=context_id)
        document = self._document(runtime, record, mode=mode)
        abi.write_request(document, record.request)
        runtime.busy = True
        self.attach(session.id, connection)
        task = asyncio.create_task(
            self._drive(session, runtime, record), name=f"mcuhome-invocation-{record.id}"
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return record

    def _prepare(
        self, session: Any, runtime: SessionRuntime, *, action: str, context_id: str
    ) -> InvocationRecord:
        """Everything on disk one invocation needs, before it is started."""
        session.invocation_counter += 1
        invocation_id = f"inv-{session.invocation_counter}"
        directory = runtime.paths.invocation(invocation_id)
        record = InvocationRecord(
            id=invocation_id,
            session_id=session.id,
            action=action,
            directory=directory,
            context_id=context_id,
            patched_layers=runtime.patched_layers,
        )
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        record.out.mkdir(mode=0o700)
        (directory / "tmp").mkdir(mode=0o700)
        # The events file is created empty by the backend, because §9.1
        # says so and because a reader that had to tell "not created
        # yet" from "no events yet" would be guessing at exactly the
        # moment a client is watching.
        record.events.touch(mode=0o600)
        session.invocations[invocation_id] = _RUNNING
        self._records[(session.id, invocation_id)] = record
        return record

    def _document(
        self, runtime: SessionRuntime, record: InvocationRecord, *, mode: str | None
    ) -> dict[str, Any]:
        """The request document for one invocation (§5.2).

        ``required`` is where this server states what it will not have
        silently ignored. Two kinds of pointer go in it, and only for
        ``build``:

        * ``/params/mode`` — because the value decides whether a warm
          workspace was reused, and §5.2 makes the *value* count and not
          only the pointer: "a program that knows ``/params/mode`` but
          not the value ``reproducible`` MUST refuse with
          ``unsupported.required`` rather than accept the job and
          quietly deliver something else."
        * ``/trees/<layer>`` for every layer whose patches the context
          carries — because a build that ignored one would produce an
          image attributed to a context whose patches never reached a
          tree, which is the one wrong artifact that looks right.

        ``verify`` demands neither, and that is not an oversight: it
        "applies no patches and touches no source tree", so demanding
        that it honour a tree pointer would ask a conforming program to
        refuse for not using something it is forbidden to use. The tree
        entries themselves are still supplied — §7.3 says exactly that —
        because "a view it never writes to is indistinguishable from one
        it was not given".
        """
        params: dict[str, Any] | None = None
        required: list[str] = []
        if record.action == ACTION_BUILD:
            params = {"mode": mode or "clean"}
            required.append("/params/mode")
            required += [f"/trees/{layer}" for layer in runtime.patched_layers]
        return abi.request_document(
            result=record.result,
            session=record.session_id,
            out=record.out,
            work=runtime.paths.work,
            tmp=record.directory / "tmp",
            context=runtime.paths.context,
            trees=runtime.trees,
            jobs=self.config.build_jobs,
            deadline_seconds=self.config.build_deadline_seconds,
            cancel_grace_seconds=self.config.cancel_grace_seconds,
            events=record.events,
            cancel=record.cancel,
            params=params,
            required=tuple(required),
            ccache=runtime.ccache,
        )

    async def _drive(self, session: Any, runtime: SessionRuntime, record: InvocationRecord) -> None:
        """Run the invocation to its end, whatever its end turns out to be.

        Owned by this backend and **not** by the connection that started
        it, which is the mechanical half of "connection loss is not
        abandonment": a client may drop its socket, and the build keeps
        going, keeps writing its events file, and finishes into a record
        a reattaching client can still read.
        """
        exit_code: int | None = None
        try:
            exit_code = await self._supervise(record)
        except Exception:
            logger.exception("invocation %s failed to run", record.id)
        finally:
            runtime.busy = False
        outcome = await self._collect(record, exit_code=exit_code)
        record.outcome = outcome
        record.artifacts = outcome.artifacts
        session.invocations[record.id] = _FINISHED
        if outcome.reason in _POISONING:
            # §6.2 and §6.3: both are terminal for the session, and both
            # say so in the same words — "the backend MUST refuse every
            # further working action in that session". `session.poisoned`
            # is that refusal, and the remedy for either is a new session
            # with pristine trees and a `work` this server owns.
            session.poison()
        self._publish(
            record,
            protocol.event_frame("invocation.finished", self._finished(outcome, record)),
        )

    async def _supervise(self, record: InvocationRecord) -> int | None:
        """Exec the program, relay what it says, and enforce liveness.

        The ladder, in order and with the reason for each rung:

        1. **The cancel sentinel.** Its *existence* means stop. It is
           first because it is the only rung that lets the program write
           a result document — ``status: "cancelled"``, with ``reason``
           and ``error`` both null, because nothing was diagnosed.
        2. **SIGTERM at ``cancel_grace_seconds``**, to the ``docker
           exec`` client. It is worth saying plainly that this does *not*
           reach the process inside the container — killing a ``docker
           exec`` client never has, which is exactly why the contract
           has a sentinel at all — so what this rung buys is the
           server's own file descriptors back.
        3. **SIGKILL**, and then the container itself at
           ``close-session``, which is the only thing that actually
           reaps a program that ignored both. One session is one
           container, so there is always that hammer.

        The deadline enters the same ladder at the top rather than
        beside it: ``limits.deadline_seconds`` is advisory to the
        program and enforced here, and a program that honours it stops
        itself and says ``error.deadline.exceeded``.
        """
        reader = events.EventReader(path=record.events)
        process = await self.docker.invoke(
            container=self._container_of(record),
            action=record.action,
            request=record.request,
            on_line=lambda line: self._log(record, line),
            user=container.current_user(),
        )
        waiter = asyncio.ensure_future(process.wait())
        stopping_at: float | None = None
        terminated_at: float | None = None
        deadline = record.started_at + self.config.build_deadline_seconds
        while not waiter.done():
            await asyncio.wait({waiter}, timeout=_POLL_SECONDS)
            self._relay(record, reader)
            now = time.monotonic()
            if stopping_at is None and record.cancel.exists():
                stopping_at = now
            if stopping_at is None and now >= deadline:
                logger.warning("invocation %s passed its deadline", record.id)
                # Suppressed because the directory may already be gone:
                # `close-session` deletes the session's tree while an
                # invocation is still running, and a deadline that fired
                # into that race must not become an exception in the
                # supervisor — the ladder's next rung reaches the
                # process either way.
                with contextlib.suppress(OSError):
                    record.cancel.touch()
                stopping_at = now
            if (
                terminated_at is None
                and stopping_at is not None
                and now >= stopping_at + self.config.cancel_grace_seconds
            ):
                process.terminate()
                terminated_at = now
            if terminated_at is not None and now >= terminated_at + _KILL_AFTER_SECONDS:
                process.kill()
        # One last read, because the program's own `invocation.finished`
        # is written immediately before the result document and can land
        # between the last poll and the exit.
        self._relay(record, reader)
        if reader.dropped:
            logger.warning("invocation %s: discarded %d event line(s)", record.id, reader.dropped)
        return waiter.result()

    def _container_of(self, record: InvocationRecord) -> str:
        runtime = self._runtimes[record.session_id]
        return runtime.container_id

    async def _collect(
        self, record: InvocationRecord, *, exit_code: int | None
    ) -> abi.InvocationOutcome:
        """Read the result, harden egress, and decide what it was worth.

        §5.3's seventh condition and §9.3's five duties meet here: the
        document is judged by :func:`~mcuhome_buildserver.abi.read_result`
        and the artifacts by
        :func:`~mcuhome_buildserver.artifacts.harden`, and an invocation
        is successful only if both had nothing to say. That ordering is
        the contract's — "every declared artifact exists as a regular
        file under its declared ``root`` and re-hashes to its declared
        value" is one of the seven conditions, not a step after them.

        Three sources of problem, all of them §5.3's sixth condition
        read whole: an entry the program declared and got *wrong* (a
        misrendered hash, a path outside §9.2's charset), an entry whose
        bytes do not survive ``harden``, and §7.2's delivery rule about
        what a successful build has to contain. The first of the three
        is why :func:`~mcuhome_buildserver.abi.declared_artifacts`
        answers problems at all: an entry it merely dropped would leave
        a build reported ``success`` with an artifact silently missing.

        The hashing runs off the event loop. ``harden`` re-reads every
        artifact of the build, which for a firmware set is tens of
        megabytes and for a symbols-and-map delivery considerably more.
        """
        outcome = abi.read_result(
            path=record.result,
            action=record.action,
            exit_code=exit_code,
            session=record.session_id,
            context_id=record.context_id,
            patched_layers=record.patched_layers,
        )
        if outcome.result is not None:
            declared, malformed = abi.declared_artifacts(outcome.result)
            verified, problems = await asyncio.to_thread(
                artifacts.harden,
                record.out,
                declared,
                max_bytes=self.config.max_artifact_bytes,
            )
            outcome.artifacts = verified
            problems = malformed + problems + _delivery_problems(record.action, outcome, verified)
            if problems:
                outcome.problems = outcome.problems + problems
                outcome.successful = False
            leftovers = await asyncio.to_thread(artifacts.undeclared, record.out, verified)
            if leftovers:
                # Not served and not deleted: they are diagnostic
                # material (§9.3), and saying so in the log is the only
                # way anybody finds out they exist.
                logger.info(
                    "invocation %s: %d undeclared file(s) left in out", record.id, len(leftovers)
                )
        if outcome.violation is not None:
            logger.warning(
                "contract violation against image for invocation %s: %s",
                record.id,
                outcome.violation,
            )
        return outcome

    def _finished(self, outcome: abi.InvocationOutcome, record: InvocationRecord) -> dict[str, Any]:
        """The payload of the ``invocation.finished`` frame (E46).

        It carries the status and the artifact list, which is what E46
        asks for, plus the two things a client cannot get anywhere else:
        the context id **this server** computed — attribution always
        uses that one, never ``result.context`` — and, on a failure, the
        session protocol's own error envelope, mapped from the
        program's ``reason`` through
        :data:`~mcuhome_buildserver.errors.REASON_CODES`.

        ``status`` is the pessimistic reading. A document that says
        ``success`` while one of §5.3's seven conditions does not hold
        is reported as a failure, because "where exit code and document
        contradict each other, the pessimistic reading wins".

        **The name collides with a registry event, and the collision is
        resolved by ``seq``.** Contract §8 seeds the event registry with
        ``invocation.finished`` — emitted by the *program*, "once,
        immediately before the result document is written" — and E46
        gives the same name to this server's own completion frame, which
        is emitted after that document has been read and judged. Both
        reach the client, because a relayed event is never dropped. What
        tells them apart is structural rather than conventional: §8 makes
        every program event carry a monotonic ``seq``, and this server
        never invents one, so **a frame of this name carrying ``seq`` is
        the program's announcement and one without it is the verdict.**
        Only the verdict carries ``artifacts``, ``context`` and ``error``.
        """
        status = _wire_status(outcome)
        payload: dict[str, Any] = {
            "session_id": record.session_id,
            "invocation_id": record.id,
            "action": record.action,
            "status": status,
            "context": record.context_id,
            "artifacts": [entry.to_wire() for entry in outcome.artifacts],
        }
        if outcome.violation is not None:
            payload["contract_violation"] = outcome.violation
        # A cancelled result carries `reason: null` and `error: null`
        # exactly as a successful one does (§5.4): status cancelled
        # already says everything there is to say, and an envelope beside
        # it would be a second spelling of the status.
        if status in (abi.STATUS_SUCCESS, abi.STATUS_CANCELLED):
            payload["error"] = None
            return payload
        payload["error"] = self._envelope(outcome, record)
        return payload

    def _envelope(self, outcome: abi.InvocationOutcome, record: InvocationRecord) -> dict[str, Any]:
        """One failed invocation as the session protocol's error envelope.

        ``builder.crashed`` when there is no result document at all —
        "an infrastructure failure, not a verdict on the context", and
        the one code here that is retryable. Otherwise the reason
        decides, through this server's own table.

        The program's own ``error.retryable`` is carried in the details
        under a name that says whose promise it is, and it is never the
        envelope's ``retryable``: that value is the server's, "derived
        from the server's own registry precisely so the promise cannot
        be forged".
        """
        result = outcome.result
        if result is None:
            return errors.envelope(
                "builder.crashed",
                "The build container ended without writing a result document. That is an "
                "infrastructure failure rather than a verdict on the context: an out "
                "directory with no result at the path the request named is a failed "
                "invocation by definition, and the same invocation may succeed on a retry.",
                session_id=record.session_id,
                invocation_id=record.id,
                exit_code=outcome.exit_code,
                problems=list(outcome.problems),
            )
        code = errors.from_reason(result.reason)
        return errors.envelope(
            code,
            f"The {record.action} in this session's build container did not succeed. "
            "The container's own classification and its message are in the details; the "
            "raw log stream of this invocation carries what it printed.",
            session_id=record.session_id,
            invocation_id=record.id,
            # Verbatim, whatever it is: "unknown values are handled as
            # their status class and passed through verbatim".
            reason=result.reason,
            status=result.declared_status,
            exit_code=outcome.exit_code,
            # The one untrusted-text field in the document, stripped of
            # control characters and bounded by `ResultDocument`.
            container_message=result.error_message,
            container_details=result.error_details,
            # Under a name that says whose promise it is. §5.4.1 forbids
            # relaying it *as* the envelope's `retryable` and says
            # nothing against carrying it, and carrying it is the only
            # way a client sees the program's own opinion of its failure
            # at all.
            container_retryable=result.error_retryable,
            problems=list(outcome.problems),
        )

    # ----------------------------------------------------------------
    # The streams
    # ----------------------------------------------------------------

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

    def _relay(self, record: InvocationRecord, reader: events.EventReader) -> None:
        """Relay every new event of the program, verbatim (§8).

        "Unknown names are relayed opaquely — a backend passes an event
        whose name it does not know through to its client verbatim, with
        its fields intact, and never drops it, never rewrites it and
        never treats it as an error." So the payload **is** the
        program's object, with this server's addressing merged in: a
        program has no invocation id — the request document deliberately
        carries none — so ``invocation_id`` cannot collide with anything
        a program could mean by it.
        """
        for line in reader.read():
            name = events.event_name(line)
            if name is None:  # pragma: no cover - the reader filtered these
                continue
            payload = dict(line)
            payload["session_id"] = record.session_id
            payload["invocation_id"] = record.id
            self._publish(record, protocol.event_frame(name, payload), drop_when_full=True)

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
        ``invocation.finished`` frame is sent instead, because it is the
        one frame a client is waiting on and there is no second way to
        learn it.

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

    async def release(self, session_id: str) -> None:
        """Reap the session's container, if it had one. Never raises.

        Called from ``close-session``, from the reaper's sweep and from
        process shutdown — the same three exits the per-session
        directory has, because the container and the directory are one
        thing: the directory is the container's mounts, and a container
        left running against a deleted mount source is the one state
        neither half can recover from.
        """
        runtime = self._runtimes.pop(session_id, None)
        self._audience.pop(session_id, None)
        for key in [key for key in self._records if key[0] == session_id]:
            self._records.pop(key, None)
        if runtime is None:
            return
        await self.docker.remove(runtime.container_id)

    async def release_all(self) -> None:
        for session_id in list(self._runtimes):
            await self.release(session_id)


#: The ``reason`` values that end a session rather than an invocation.
#: §6.2's interrupted patch application leaves trees no future build may
#: trust; §6.3's foreign ``work`` marker "can only differ if the
#: exclusivity guarantee of §9.1 was broken" and is "a defect on the
#: backend's own side". Both say the same thing about what happens next:
#: every further working action in that session is refused, and the
#: remedy is a new session.
#:
#: **Derived from the reason table rather than written out again.**
#: ``session.poisoned`` is what that table already says about these two,
#: and two independent literals saying the same thing is one literal
#: that can be edited alone — which is exactly what happened: the table
#: had both reasons and this set could lose one with the suite green.
_POISONING = frozenset(
    reason for reason, code in errors.REASON_CODES.items() if code == "session.poisoned"
)

#: Mirrors of :mod:`mcuhome_buildserver.sessions`' invocation states.
#: Spelled here rather than imported to keep the import edge one-way:
#: the verbs call the backend, the backend never calls the verbs.
_RUNNING = "running"
_FINISHED = "finished"


def _already_replayed(
    frame: dict[str, Any], record: InvocationRecord, boundary: tuple[str, int] | None
) -> bool:
    """Whether *frame* is inside a connection's own replayed history.

    Only a program event can be: the log is not replayed at all, and
    this server's own frames carry no ``seq`` — which is the same rule
    that tells the program's ``invocation.finished`` from the backend's
    verdict of the same name.
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


def _delivery_problems(
    action: str, outcome: abi.InvocationOutcome, verified: tuple[Artifact, ...]
) -> tuple[str, ...]:
    """What §7.2 requires of a successful build, measured on what survived.

    "A successful device build MUST declare at least two artifacts: the
    unsigned image with role ``firmware`` … and **exactly one artifact
    with role ``report``**, whose content is the build report of §7.2.1."
    The report is mandatory because "the program is forbidden to sign and
    the client therefore has to: a build whose parameters the client
    cannot read produces an image nobody can sign."

    Measured on the **verified** set rather than on the declaration,
    because that is what the client actually receives: the backend
    serves exactly the intersection of declared and verified (§9.3), so
    a build whose report was declared and could not be verified has
    produced an image nobody can sign just as surely as one that never
    declared it. Checking the declaration would answer success for a
    delivery that is missing the one artifact §7.2 exists to guarantee.
    """
    if action != ACTION_BUILD or outcome.result is None:
        return ()
    if outcome.result.status != abi.STATUS_SUCCESS:
        return ()
    problems: list[str] = []
    if not any(entry.role == "firmware" for entry in verified):
        problems.append("a successful build delivers no artifact with role firmware")
    reports = sum(1 for entry in verified if entry.role == "report")
    if reports != 1:
        problems.append(
            f"a successful build delivers {reports} artifacts with role report, and the "
            "client that signs detached needs exactly one"
        )
    return tuple(problems)


def _wire_status(outcome: abi.InvocationOutcome) -> str:
    """The status a client is told, which is the pessimistic one."""
    if outcome.successful:
        return abi.STATUS_SUCCESS
    if outcome.result is not None and outcome.result.status != abi.STATUS_SUCCESS:
        return outcome.result.status
    return abi.STATUS_FAILURE


def _not_conforming(facts: container.ImageFacts, problem: str) -> SessionError:
    """An image that cannot be trusted with a build, and why.

    ``version.builder-unavailable`` rather than a code of its own: from
    the client's side there is no build container on this server that
    can serve its context, which is exactly what that entry says. The
    detail says which image and what was wrong with it, because the
    party who can act on it is the operator and the client is only the
    messenger.
    """
    return SessionError(
        "version.builder-unavailable",
        f"The image {facts.reference} cannot serve a session on this server: {problem}. "
        "describe is authoritative about what a build container can do and doubles as "
        "the first conformance test, so an image that cannot answer it conformingly is "
        "not one this server will invoke a build on.",
        image=facts.reference,
        digest=facts.digest,
        problem=problem,
    )


def _program_problem(program: dict[str, Any], facts: container.ImageFacts) -> str | None:
    """Everything that has to hold about a ``describe`` before it is used.

    §7.1.1 makes every field of the block mandatory in a ``describe``
    result, ``trees`` included, and the gates that follow are the ones a
    backend has to pass before it may invoke anything: a contract
    version it implements, a request version the program parses, a
    result version it writes, and — §2.1 — labels that do not contradict
    what the block just said.
    """
    missing = [name for name in (*abi.PROGRAM_FIELDS, "trees") if name not in program]
    if missing:
        return f"its describe result has no program.{', program.'.join(missing)}"
    if program.get("contract") != CONTRACT_VERSION:
        return (
            f"it implements contract version {program.get('contract')!r} and this server "
            f"implements {CONTRACT_VERSION}"
        )
    if abi.REQUEST_VERSION not in _versions(program.get("request")):
        return (
            f"it parses request format versions {program.get('request')!r} and this "
            f"server writes {abi.REQUEST_VERSION}"
        )
    if abi.RESULT_VERSION not in _versions(program.get("result")):
        return (
            f"it writes result format versions {program.get('result')!r} and this server "
            f"reads {abi.RESULT_VERSION}"
        )
    return _label_problem(program, facts)


def _label_problem(program: dict[str, Any], facts: container.ImageFacts) -> str | None:
    """The §2.1 cross-check: labels against what ``describe`` answered.

    "A backend MUST verify them against ``describe`` and MUST NOT rely
    on a label ``describe`` contradicts", and §7.1.1 goes further for
    the one label that has a counterpart in the block: ``program.contract``
    "MUST equal the ``org.mcuhome.contract`` label; where the two
    disagree, ``describe`` is authoritative and the disagreement is a
    contract violation against the image".

    The other two labels have no counterpart to be checked against, so
    what is checked about them is that they are **there**: they are the
    coupling labels a compatibility constraint is written over, and
    "a container that does not carry a named label does not qualify —
    absence is never read as compatible" (§2.1.1).
    """
    absent = [
        name
        for name in (container.CONTRACT_LABEL, container.ZEPHYR_LABEL, container.TOOLCHAIN_LABEL)
        if not facts.labels.get(name)
    ]
    if absent:
        return f"it carries no {' and no '.join(absent)} label"
    declared = facts.labels[container.CONTRACT_LABEL]
    if declared != str(program.get("contract")):
        return (
            f"its {container.CONTRACT_LABEL} label says {declared!r} and its describe "
            f"result says {program.get('contract')!r}"
        )
    return None


def _versions(value: Any) -> tuple[int, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(entry for entry in value if isinstance(entry, int) and not isinstance(entry, bool))
