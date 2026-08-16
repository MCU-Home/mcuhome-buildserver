# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The backend seam, and the container backend standing on it.

Two things live here. :class:`SessionBackend` is everything a backend of
build-container contract §9 does **whatever profile it serves** — the
per-invocation directories, the request document, liveness, the event and
log relay, egress and the verdict. :class:`ContainerBackend` is the
``container`` profile of §1.2 on top of it: "the backend materializes one
container per session and invokes the program inside it", with every
isolation guarantee of ADR 0019 §8 — one session = one container
instance = the trust boundary, no network, per-session limits. The other
profile is :class:`~mcuhome_buildserver.subprocessbackend.SubprocessBackend`,
and it is a sibling rather than a special case: §5's ABI is identical in
both, so what differs is only how the program is started and how much of
the environment the kernel keeps apart.

**A backend is never a build environment.** Nothing here compiles
anything; it starts something, writes a request document, invokes a
program and reads what came back. That sentence holds in both profiles —
§1.2 makes it hold — which is precisely why the split above is a base
class and not two implementations of one interface written twice.

The layering, from the outside in:

* :mod:`mcuhome_buildserver.sessions` owns the verbs and the state
  machine and calls into this module through ``state.backend``;
* this module owns the *lifecycle* — build-environment discovery, the
  session's runtime, the per-invocation directories, liveness, the event
  and log relay, and what an invocation is worth at the end of it;
* :mod:`mcuhome_buildserver.container` owns docker,
  :mod:`mcuhome_buildserver.program` owns the child process the other
  profile starts,
  :mod:`mcuhome_buildserver.abi` owns the two documents,
  :mod:`mcuhome_buildserver.events` owns the NDJSON stream,
  :mod:`mcuhome_buildserver.artifacts` owns egress, and
  :mod:`mcuhome_buildserver.sdkstore` owns the one external input.

**Three things the container backend deliberately does not do**, each
because a decision took the premise away.

*No host-side overlay* (E47). Contract §6.2's writable view of a patched
layer costs nothing in this profile: the image's trees are writable
inside the container by construction, one session is one container, and
the container is discarded when the session closes — so a patched
``zephyr`` cannot outlive the session that patched it. This server
therefore asserts ``writable: true`` for an in-image tree at the path
``describe`` reported, and the assertion is truthful because the
container's own copy-on-write layer makes it so. No ``docker cp``, no
volume, no overlayfs.

*No pull.* The context's Zephyr line is answered out of the **local**
image inventory (product-owner decision). ADR 0019 §8 permits pulling
from configured registries; contract v1 of this server has no registry
configuration, so a line no local image carries is
``version.builder-unsatisfiable`` — a final answer rather than a fetch
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
import functools
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from mcuhome.model import containerpaths
from mcuhome.model.context import ContainerResolution
from mcuhome.model.toolchain import line_of, satisfies_line

from mcuhome_buildserver import (
    abi,
    artifacts,
    container,
    errors,
    events,
    processes,
    protocol,
    sdkstore,
)
from mcuhome_buildserver.abi import Artifact, TreeEntry
from mcuhome_buildserver.config import Config
from mcuhome_buildserver.contextstore import ContextPins, SessionPaths, derive_patch_layers
from mcuhome_buildserver.errors import SessionError

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "ACTION_BUILD",
    "ACTION_DESCRIBE",
    "ACTION_VERIFY",
    "CONTRACT_VERSION",
    "ContainerBackend",
    "ImageProfile",
    "InvocationRecord",
    "ProgramProfile",
    "SessionBackend",
    "SessionRuntime",
    "describe_problem",
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
# What a build environment is, and what a session runs on
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ProgramProfile:
    """One build environment, as its ``describe`` answers for it.

    The profile-independent half, because ``describe`` is
    profile-independent: §7.1 makes it "**authoritative** about what the
    program can do" in both, and in the ``subprocess`` profile it is "the
    only discovery channel that exists … where there is no image and
    therefore no labels". Everything a backend has to know before it may
    invoke anything — the contract version, the request and result
    formats, the action set, where the trees are — is in this one block,
    and none of it is a property of a container.

    What the two profiles add on top is only how the environment is
    *named*: :class:`ImageProfile` names it by image reference and repo
    digest, and the subprocess profile names it by the program's own
    identity, because that is all there is to name.
    """

    #: ``describe``'s ``program`` block, verbatim. Authoritative about
    #: what the program can do; an image's labels are the pre-start hint.
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
        """Where the environment keeps *layer*, or ``None`` if it carries none.

        §7.1.1: "``null`` asks, a path requires." A concrete path is
        where the environment keeps that tree **and**, for a tree the
        backend supplies, the path the backend MUST supply it at;
        ``null`` means "put it wherever you like and name it in
        ``trees``".
        """
        found = self._tree(layer, "path")
        return Path(found) if found is not None and found.startswith("/") else None

    def tree_version(self, layer: str) -> str | None:
        """What the environment says the tree at *layer* **is**, or ``None``.

        §7.1.1's optional companion of ``path``: "an image that does not
        carry a tree cannot state its version", so absence is the normal
        answer for a tree the backend supplies and a stated value is the
        environment describing its own filesystem. The value is a
        *revision* rather than a release — MCUHome's own program reports
        what west lists, which is the manifest's tag — so what may be
        concluded from it is whatever the reader can parse out of it, and
        nothing at all where it does not parse. Absence is never read as
        compatible (§2.1.1).
        """
        found = self._tree(layer, "version")
        return found.strip() or None if found is not None else None

    def _tree(self, layer: str, field_name: str) -> str | None:
        """One string field of one ``trees`` entry, or ``None``."""
        trees = self.program.get("trees")
        entry = trees.get(layer) if isinstance(trees, dict) else None
        found = entry.get(field_name) if isinstance(entry, dict) else None
        return found if isinstance(found, str) else None

    @property
    def resolution(self) -> ContainerResolution:
        """This environment as ``manifest.yaml``'s ``container:`` records it.

        The one thing a profile has to answer for itself, because it is
        the one thing ``describe`` does not answer: §3.2 makes the block
        "the record of which build environment answered this context's
        requirement", and what an environment is *called* is exactly what
        the two profiles do not share.
        """
        raise NotImplementedError

    def to_wire(self) -> dict[str, Any]:
        """What ``send-context`` answers about the serving environment.

        Since E61 this is a **resolution and not an echo**: the context
        named no container, so every field here is something this server
        decided. ``image`` and ``tag`` joined for exactly that reason —
        under the digest-pinned format the client already knew them
        because it had sent them, and now it does not. They are the same
        three names ``manifest.yaml`` carries, so what a client reads off
        this answer and what it reads off the manifest it gets back are
        the same fields with the same values.

        ``digest`` may be ``null``, for an image built on this host and
        never pushed — and is ``null`` always in the ``subprocess``
        profile, where there is no image at all. That is a fact about the
        environment rather than a gap: it names no bytes a client could
        fetch, and saying so is the honest half of E60's promise that
        these field names mean something.

        The four fields after the resolution come out of ``describe``,
        which is authoritative, rather than out of an image's labels,
        which are a pre-start hint that is cross-checked against it — so
        they are answered here once, for both profiles.
        """
        resolution = self.resolution
        return {
            "image": resolution.image,
            "tag": resolution.tag,
            "digest": resolution.digest,
            "contract": self.program.get("contract"),
            "program": self.identity,
            "version": self.program.get("version"),
            "actions": list(self.actions),
        }


@dataclass(frozen=True)
class ImageProfile(ProgramProfile):
    """One image, as ``describe`` and its labels jointly answer for it.

    Cached for the life of the server process under a key that names
    bytes: the answer is a property of the image, so the cache is only
    honest as long as the key cannot come to mean a different image. The
    repo digest is that key where there is one; where there is none —
    the locally built, never-pushed image E61 made first-class with
    ``digest: null`` — it is docker's own content-addressed image ID,
    which changes on every rebuild of the same tag. What must *not* be
    the key is the tag, for the reason :func:`_pinned` gives about
    naming: rebuilding ``localhost/build-container:dev`` against a
    long-lived server would otherwise serve the previous build's action
    set, tree paths and program version to every later session.

    A session pays for it once for the whole host rather than once per
    session, which is what makes container materialization stay lazy —
    a session that never builds never starts a container of its own.
    """

    facts: container.ImageFacts

    @property
    def resolution(self) -> ContainerResolution:
        """This image as ``manifest.yaml`` records it (E61).

        The answer this server gave to the context's ``zephyr``
        requirement, in the manifest's own vocabulary — so the freeze
        writes a value it was handed rather than one it assembles from
        docker's spelling.
        """
        return ContainerResolution.from_reference(self.facts.reference, digest=self.facts.digest)


@dataclass
class SessionRuntime:
    """The build environment one session works in, and what it was given.

    One record for both profiles, because everything in it is something
    §4 and §5 make a property of the *session* rather than of a container:
    the trees the request document will name, the patch set of the locked
    context, the shared cache, and the one-invocation-at-a-time flag §9.1
    requires. :attr:`container_id` is the single container-profile field
    and it is ``None`` in the other, where there is no container to
    address and the running child is addressed by its process handle.
    """

    session_id: str
    #: What ``describe`` answered for the environment serving this
    #: session — an :class:`ImageProfile` in the ``container`` profile.
    image: ProgramProfile
    paths: SessionPaths
    #: The ``trees`` block every invocation of this session writes. Fixed
    #: for the session because the patch set of a locked context cannot
    #: change (§6.2) and because mounts cannot be added to a running
    #: container.
    trees: dict[str, TreeEntry]
    patched_layers: tuple[str, ...]
    container_id: str | None = None
    ccache: TreeEntry | None = None
    #: One invocation at a time per ``work`` (§9.1). The program cannot
    #: check it, so it is a backend duty; this flag is the whole of it.
    busy: bool = False
    #: The handle of this session's most recent invocation, where the
    #: profile has to reach it at teardown. The ``container`` profile leaves it
    #: ``None`` and reaps the container instead — removing that is what
    #: actually stops a program there, because killing a ``docker exec``
    #: client never did. The ``subprocess`` profile has no container and
    #: the child *is* the build, so this is its only address for it.
    child: processes.Process | None = None


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
# The backend seam: everything §9 asks of a backend in either profile
# --------------------------------------------------------------------------


class SessionBackend:
    """What a backend does, minus how its build environment is started.

    One instance per :class:`~mcuhome_buildserver.app.ServerState`. It
    holds no session state of its own beyond what a build environment
    needs — the session record stays in
    :class:`~mcuhome_buildserver.sessions.Session` — because the two have
    different lifetimes: a session exists from ``open-session``, and its
    build environment exists from the first command that needs one.

    **Everything here is profile-independent by construction**, and the
    list is contract §9.1's own: the per-invocation directory, an empty
    ``out``, an empty ``tmp``, the session's ``work``, the events file,
    the request document written atomically, one invocation at a time per
    ``work``, the SDK verified against the pin, the result document read
    whenever it exists, egress hardened, the verdict published. §9.1 says
    of exactly this list that "neither shape moves a duty from this list
    onto the program", and the two duties that *are* profile-dependent —
    network isolation and per-session resource limits — are not on it.

    A subclass supplies six things and nothing else: what it can serve
    (:meth:`inventory`), which environment answers a context's
    requirement (:meth:`resolve_image`), how the session's environment is
    materialized (:meth:`_materialize`), how one invocation of the
    program is started (:meth:`_start`), how the environment is reaped
    (:meth:`_release_runtime`), and how the environment spells a path
    this server owns (:meth:`_inside`).
    """

    #: The backend profile this server declares at ``open-session``
    #: (contract §1.2). Set by the subclass, because it is the one thing
    #: about a backend that the wire promises a client.
    profile = ""

    def __init__(self, config: Config) -> None:
        self.config = config
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
    # What a subclass owns
    # ----------------------------------------------------------------

    async def inventory(self) -> list[dict[str, Any]]:
        """The build environments this server can serve, for ``capabilities``."""
        raise NotImplementedError

    async def resolve_image(self, pins: ContextPins) -> ProgramProfile:
        """The environment that serves a context's Zephyr line, or a refusal."""
        raise NotImplementedError

    async def _session_environment(self, session: Any) -> ProgramProfile:
        """The environment this session was answered with, still available."""
        raise NotImplementedError

    async def _materialize(
        self,
        session: Any,
        profile: ProgramProfile,
        paths: SessionPaths,
        package: sdkstore.SdkPackage,
        patched: tuple[str, ...],
    ) -> SessionRuntime:
        """Arrange the trees, start whatever has to be started, and record it."""
        raise NotImplementedError

    async def _start(self, runtime: SessionRuntime, record: InvocationRecord) -> processes.Process:
        """Invoke the program for one invocation (§5.1) and hand back its handle."""
        raise NotImplementedError

    async def _release_runtime(self, runtime: SessionRuntime) -> None:
        """Reap the session's build environment. Never raises."""
        raise NotImplementedError

    def _inside(self, runtime: SessionRuntime, path: Path) -> PurePosixPath | Path:
        """*path*, as the build environment spells it.

        Every path this server puts in a request document goes through
        here, because "the directory this server made" and "the path the
        program is told about" are only the same string in a profile
        where they are. In this one they are: a subprocess shares this
        filesystem, so the answer is the path itself.
        """
        return path

    # ----------------------------------------------------------------
    # The session's build environment
    # ----------------------------------------------------------------

    async def ensure_runtime(
        self, session: Any, pins: ContextPins, *, context_id: str
    ) -> SessionRuntime:
        """The session's build environment, materialized on first use.

        "Container materialization is **lazy** — the backend may defer
        creating the container until the first command that needs one"
        (ADR 0019 §2), and the same laziness is right where there is no
        container: the SDK package is an expensive fetch and a session
        that never builds should not pay for it. The first such command
        is ``verify`` or ``build``, so everything expensive happens here.

        The pins are cross-checked on the way (§9.1): the SDK package
        really hashes to ``mcuhome.package.sha256``. The other two,
        ``zephyr`` and ``target.board``, are compared against the pins the
        session was admitted on by
        :func:`~mcuhome_buildserver.contextstore.recheck_locked_context`
        before every invocation, which is the only place a board can be
        compared to anything on this side.

        **One session, one build environment.** The environment is *not*
        re-selected here — :meth:`resolve_image` is a
        ``send-context``-time call only. That is where the choice belongs:
        it is the moment the pins arrive, and ``lock-context`` writes the
        chosen environment into ``manifest.yaml``, which §3.2 makes "the
        record of which build environment answered this context's
        requirement … the requirement says what was needed, this says what
        actually ran". What happens here is a **presence check and never a
        choice** (:meth:`_session_environment`).
        """
        existing = self._runtimes.get(session.id)
        if existing is not None:
            return existing
        paths: SessionPaths = session.paths
        profile = await self._session_environment(session)
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
            # The operator's own material, not the client's upload — the
            # SDK gets its own bounds (sdkstore.SDK_CAPS), because E44's
            # numbers were argued for contexts and holding the operator's
            # source tree to the client's budget shape makes the two
            # knobs fight.
            caps=sdkstore.SDK_CAPS,
            max_bytes=sdkstore.SDK_MAX_BYTES,
        )
        runtime = await self._materialize(session, profile, paths, package, patched)
        self._runtimes[session.id] = runtime
        logger.info(
            "session %s: %s build environment %s (context %s)",
            session.id,
            self.profile,
            profile.resolution.reference(),
            context_id,
        )
        return runtime

    def _shared_cache(self, profile: ProgramProfile) -> TreeEntry | None:
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

        It is profile-independent because §10 is: a cache is a directory,
        and only the ``container`` profile has to also make it *reachable*
        by mounting it.
        """
        root = self.config.ccache_dir
        if root is None:
            return None
        identity = profile.identity
        if not _PATH_SEGMENT.fullmatch(identity):
            logger.warning("no shared cache for program id %r: not a path segment", identity)
            return None
        store = root / identity
        try:
            store.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:  # pragma: no cover - an operator's directory
            logger.warning("no shared cache at %s: %s", store, exc)
            return None
        return TreeEntry(path=store, writable=False)

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
        completion travels as a typed ``invocation.verdict`` event
        carrying the status and the artifact list, because a build is
        minutes to hours long and a command frame that waited for it
        would make every client's socket a build timer.

        Everything §9.1 requires **before** an invocation happens here,
        in one place so that the list can be read against the contract:
        the per-invocation directory, an empty ``out``, an empty
        ``tmp``, the session's ``work``, the ``events`` file, the
        request document written atomically, and write protection of
        ``context`` and of every non-writable tree — the last of which
        the profile arranges when it materializes the environment, since
        a mount cannot be added to a running container.
        """
        runtime = await self.ensure_runtime(session, pins, context_id=context_id)
        if action not in runtime.image.actions:
            # §7.1.1: "A backend MUST NOT invoke an action absent from
            # the list." The program would answer `unsupported.action`
            # legibly, which is precisely why there is no reason to make
            # it: the refusal is already knowable.
            raise SessionError(
                "version.builder-unavailable",
                f'The build environment serving this session does not implement "{action}". '
                f"It announced {sorted(runtime.image.actions)}, and describe is the only "
                "declaration of an action set there is.",
                action=action,
                actions=sorted(runtime.image.actions),
                digest=runtime.image.resolution.digest,
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
                "invocation.verdict event."
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
        inside = functools.partial(self._inside, runtime)
        return abi.request_document(
            result=inside(record.result),
            session=record.session_id,
            out=inside(record.out),
            work=inside(runtime.paths.work),
            tmp=inside(record.directory / "tmp"),
            context=inside(runtime.paths.context),
            trees=runtime.trees,
            jobs=self.config.build_jobs,
            deadline_seconds=self.config.build_deadline_seconds,
            cancel_grace_seconds=self.config.cancel_grace_seconds,
            events=inside(record.events),
            cancel=inside(record.cancel),
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
            exit_code = await self._supervise(runtime, record)
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
            protocol.event_frame("invocation.verdict", self._verdict(outcome, record)),
        )

    async def _supervise(self, runtime: SessionRuntime, record: InvocationRecord) -> int | None:
        """Invoke the program, relay what it says, and enforce liveness.

        The ladder, in order and with the reason for each rung:

        1. **The cancel sentinel.** Its *existence* means stop. It is
           first because it is the only rung that lets the program write
           a result document — ``status: "cancelled"``, with ``reason``
           and ``error`` both null, because nothing was diagnosed. It is
           also the only rung that works identically in both profiles,
           which is why the contract has it: "a cooperative sentinel is
           used rather than a signal because killing a ``docker exec``
           client does not kill the process inside the container, and
           because the same mechanism works unchanged in the
           ``subprocess`` profile" (§8).
        2. **SIGTERM at ``cancel_grace_seconds``**, to whatever
           :meth:`_start` handed back. **What that reaches is the one
           thing the two profiles do not share.** In the ``container``
           profile it is the ``docker exec`` client and *not* the process
           inside the container — killing an exec client never has been —
           so the rung buys the server's own file descriptors back. In
           the ``subprocess`` profile it is the program itself, which is
           what §1.2 means by "cancellability … remain[s]".
        3. **SIGKILL**, and then whatever :meth:`_release_runtime` can
           still reach at ``close-session``.

        The deadline enters the same ladder at the top rather than
        beside it: ``limits.deadline_seconds`` is advisory to the
        program and enforced here, and a program that honours it stops
        itself and says ``error.deadline.exceeded``.
        """
        reader = events.EventReader(path=record.events)
        process = await self._start(runtime, record)
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

    def _verdict(self, outcome: abi.InvocationOutcome, record: InvocationRecord) -> dict[str, Any]:
        """The payload of the ``invocation.verdict`` frame (E46, E58).

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

        **The name is this server's own, and no longer the program's**
        (E58). E46 first called this frame ``invocation.finished``, which
        is the name contract §8 seeds the event registry with — emitted
        by the *program*, "once, immediately before the result document
        is written", while this frame is emitted after that document has
        been read and judged. Both reach the client, because a relayed
        event is never dropped, and the only thing that told them apart
        was the absence of ``seq``: a program that violated §8 by
        omitting its counter would have had its own announcement read as
        this server's verdict. The contract is frozen and keeps its
        event name; the session layer renamed its frame while renaming
        still cost nothing, so **the discrimination is the name**.
        ``invocation.finished`` is always the program's, and
        ``invocation.verdict`` is always this server's — and only the
        verdict carries ``artifacts``, ``context`` and ``error``.
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

    async def release(self, session_id: str, *, reaped: str | None = None) -> None:
        """Reap the session's build environment, if it had one. Never raises.

        *reaped* is the half of the lease that ran out, and it is set by
        the sweep alone: a session this server took away owes its
        audience an explanation, while ``close-session`` is the client's
        own act and process shutdown reaches nobody anyway.

        Called from ``close-session``, from the reaper's sweep and from
        process shutdown — the same three exits the per-session
        directory has, because the environment and the directory are one
        thing: in the ``container`` profile the directory *is* the
        container's mounts, and in the ``subprocess`` profile it is the
        working area of a child of this process. Either way, something
        still running against a deleted tree is the one state neither
        half can recover from.
        """
        runtime = self._runtimes.pop(session_id, None)
        if reaped is not None:
            self._announce_reaping(session_id, reaped)
        self._audience.pop(session_id, None)
        for key in [key for key in self._records if key[0] == session_id]:
            self._records.pop(key, None)
        if runtime is None:
            return
        await self._release_runtime(runtime)

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
                        "status": abi.STATUS_FAILURE,
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

    async def release_all(self) -> None:
        for session_id in list(self._runtimes):
            await self.release(session_id)


# --------------------------------------------------------------------------
# The container backend
# --------------------------------------------------------------------------


class ContainerBackend(SessionBackend):
    """Everything one build-server process knows about containers."""

    #: ``container``, and never ``subprocess``: this backend starts a
    #: container per session and is an orchestrator of it.
    profile = "container"

    def __init__(self, config: Config, *, docker: container.Docker | None = None) -> None:
        super().__init__(config)
        self.docker = container.Docker(config.docker) if docker is None else docker
        self._images: dict[str, ImageProfile] = {}

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
        """The image that serves a context's Zephyr line, described and gated.

        Called from ``send-context``, which is where ADR 0019's
        amendment puts container discovery: "``send-context`` answers
        what the context determines — the serving build container's
        contract version and its command set", because only with the
        pins in hand does the backend know *which* container serves the
        session.

        **This server chooses; the context only requires** (E61). The
        requirement is ``pins.zephyr``, a Zephyr release line; the
        candidates are the images of :meth:`~container.Docker.inventory`
        — the same set ``capabilities`` announces, so a client that read
        that answer and a server that acts on it are looking at one list
        — and the choice among them is :func:`_select_image`. Nothing is
        pulled, so an unsatisfiable line is a final answer and not a
        deferred fetch.

        Four gates, in the order that makes each one's refusal legible:
        the runtime is there; some image on this host carries the
        required line; ``describe`` answers and answers conformingly; and
        what ``describe`` said is something this server can actually
        drive.
        """
        await self.docker.require_runtime()
        facts = _select_image(await self.docker.inventory(), line=pins.zephyr)
        # Memoized per image, because `describe` costs a container start
        # and its answer is a property of the image — so the key has to
        # name bytes, or the memo starts answering for an image that no
        # longer exists. The repo digest does; the local image ID does
        # too, and is what an image that was never pushed has instead
        # (docker's `Id`, content-addressed and new on every rebuild).
        # The reference is last and is a tag, which names bytes only
        # until somebody rebuilds it — kept solely so that an inspect
        # answer without either id is memoized under *something* rather
        # than crashing, which is a defensive branch and not a case.
        key = facts.digest or facts.image_id or facts.reference
        cached = self._images.get(key)
        if cached is not None:
            return cached
        profile = await self._describe(facts)
        self._images[key] = profile
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
        static = await self._read_static_description(facts)
        if static is not None:
            program = static
            problem = describe_problem(program) or _label_problem(program, facts)
            if problem is not None:
                raise _not_conforming(facts, problem)
            return ImageProfile(facts=facts, program=program)

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
                image=_pinned(facts),
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
        problem = describe_problem(program) or _label_problem(program, facts)
        if problem is not None:
            raise _not_conforming(facts, problem)
        return ImageProfile(facts=facts, program=program)

    async def _read_static_description(self, facts: container.ImageFacts) -> dict[str, Any] | None:
        """``/mcuhome/describe.json``, where the image carries one (§2.2.1).

        The contract's answer to the chicken-and-egg the SDK split
        creates: the program body arrives with a mounted tree, but where
        that tree must be mounted is what discovery would have supplied —
        so an image MAY ship its ``describe`` answer as a static file,
        and this backend reads it in place of invoking ``describe``
        pre-mount. §2.2.1 binds the file by §2.1's rule ("a disagreement
        is a violation against the image"), and it is exactly a
        ``describe`` result document, so it goes through the same §5.4
        reading as a live answer.

        ``None`` means "no file" — absent, unreadable, or not parseable
        as a result document — and the caller then invokes ``describe``
        exactly as it always did: "there is no new failure mode in
        either direction, because the fallback is the thing that was
        already mandatory."
        """
        completed = await self.docker.read_file(image=_pinned(facts), path="/mcuhome/describe.json")
        if completed is None:
            return None
        outcome = abi.read_static_describe(completed)
        if outcome is None:
            _LOGGER.warning(
                "image %s carries an unreadable /mcuhome/describe.json; falling back "
                "to invoking describe",
                facts.reference,
            )
        return outcome

    # ----------------------------------------------------------------
    # The session's container
    # ----------------------------------------------------------------

    async def _session_environment(self, session: Any) -> ImageProfile:
        """The image this session was answered with, still on this host.

        The whole of "one session, one build environment": the profile
        is the one :meth:`resolve_image` produced at ``send-context`` and
        :func:`~mcuhome_buildserver.sessions.lock_context` froze into
        ``manifest.yaml``, taken off the session rather than chosen
        again. Nothing here compares releases or reads labels — the
        choice was made, and re-making it is what would make the manifest
        lie.

        What is checked is that the choice is still there. An operator
        may remove an image while a session sits locked, and the pinned
        name is looked up rather than assumed because that name is what
        ``docker run`` will be handed a moment later: a refusal here says
        which image went away, where the same absence at container start
        would surface as a docker error about a name the client never
        chose. ``version.builder-unavailable`` is that refusal's code by
        its own registry entry — "the image is not on this host" — and it
        is deliberately not the retryable ``builder.runtime-unavailable``:
        this server pulls nothing, so a missing image is a final answer,
        while a missing *runtime* is not and is asked about first.
        """
        profile: ImageProfile | None = session.image
        if profile is None:  # pragma: no cover - set with the pins at send-context
            raise SessionError(
                "context.missing",
                f'Session "{session.id}" holds no build container to work in.',
                session_id=session.id,
            )
        await self.docker.require_runtime()
        pinned = _pinned(profile.facts)
        if await self.docker.image(pinned) is None:
            raise SessionError(
                "version.builder-unavailable",
                f"The build container {pinned} this session was answered with is no longer "
                "on this host. It is the image send-context chose for this context's Zephyr "
                "line and the one lock-context recorded as what built it, so the session "
                "refuses rather than building in another image and recording this one.",
                image=profile.resolution.image,
                tag=profile.resolution.tag,
                digest=profile.facts.digest,
            )
        return profile

    async def _materialize(
        self,
        session: Any,
        profile: ProgramProfile,
        paths: SessionPaths,
        package: sdkstore.SdkPackage,
        patched: tuple[str, ...],
    ) -> SessionRuntime:
        """Compose the mounts and start the session's container.

        The container-profile half of :meth:`SessionBackend.ensure_runtime`:
        the trees are resolved against what ``describe`` reported, the
        mounts are composed, and the container is started with the
        resource limits §1.2 promises for this profile.

        The image is not re-selected here — :meth:`_session_environment`
        has already turned the session's own choice into a presence check
        — because a second selection would re-open exactly what
        ``manifest.yaml`` records: an operator pulling a newer release of
        the same line between the lock and the first ``build`` would have
        the build run in an image the manifest does not name, silently,
        with no downstream check able to notice. The recorded resolution
        is outside the ID by design and outside the per-invocation
        re-check's pin list.
        """
        assert isinstance(profile, ImageProfile)  # noqa: S101 - resolve_image's own type
        trees, mounts = self._arrange_trees(profile, paths, package, patched)
        # The cache is mounted, never stated. An image configures ccache
        # itself — contract §10.1 — so the read-only shared store goes on
        # the path its configuration already names, and the request
        # document says nothing about a cache at all. The writable half
        # is deliberately not mounted here: this server serves contexts
        # it does not trust, and §10 makes a shared store read-only for
        # exactly that reason.
        shared = self._shared_cache(profile)
        if shared is not None:
            mounts.append(
                container.Mount(
                    source=shared.path,
                    target=containerpaths.CCACHE_SHARED,
                    read_only=True,
                )
            )
        container_id = await self.docker.start(
            image=_pinned(profile.facts),
            mounts=container.mounts_for(mounts),
            session_id=session.id,
            user=container.current_user(),
            limits=container.ResourceLimits(
                memory=self.config.container_memory,
                cpus=self.config.container_cpus,
                pids=self.config.container_pids,
            ),
        )
        logger.info(
            "session %s: container %s from %s",
            session.id,
            container_id[:12],
            profile.facts.reference,
        )
        return SessionRuntime(
            session_id=session.id,
            image=profile,
            container_id=container_id,
            paths=paths,
            trees=trees,
            patched_layers=patched,
            # Not `shared`: in this profile the cache is a mount and not a
            # field, so the request document must not carry one.
            ccache=None,
        )

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
            container.Mount(source=paths.context, target=containerpaths.CONTEXT, read_only=True),
            container.Mount(source=paths.work, target=containerpaths.WORK),
            container.Mount(source=paths.invocations, target=containerpaths.INVOCATIONS),
        ]
        sdk_writable = "sdk" in patched
        sdk_target = profile.tree_path("sdk") or containerpaths.SDK
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

    def _inside(self, runtime: SessionRuntime, path: Path) -> PurePosixPath | Path:
        """*path*, as the container spells it — through this session's mounts.

        Three directories of this session are visible in there, each at a
        path that is the same for every session on every machine
        (:mod:`mcuhome.model.containerpaths`), so this is a substitution
        of prefixes and nothing more. It is the reason a build cannot
        tell this server from a workbench building locally, and the
        reason the compiler cache is worth keeping at all: Zephyr puts
        three ``-fmacro-prefix-map=<absolute path>`` options on every
        compile, so a session directory in here would be a session
        directory in every cache key.

        A path under none of the three is a path the container cannot
        see, and putting one in a request document would produce a
        refusal the client cannot act on — so it is a defect here, raised
        as one.
        """
        for host, target in (
            (runtime.paths.context, containerpaths.CONTEXT),
            (runtime.paths.work, containerpaths.WORK),
            (runtime.paths.invocations, containerpaths.INVOCATIONS),
        ):
            if path == host:
                return target
            if host in path.parents:
                return target / path.relative_to(host)
        raise AssertionError(f"{path} is not mounted into the session's container")

    async def _start(self, runtime: SessionRuntime, record: InvocationRecord) -> processes.Process:
        """``docker exec`` the program: the contract's whole invocation.

        Two positional operands after the program's fixed absolute path,
        and never a flag (§5.1). It runs in the session's own container,
        which is the trust boundary this profile promises, and as this
        server's own user so that everything the program writes comes
        back readable to egress (§9.3).
        """
        return await self.docker.invoke(
            container=str(runtime.container_id),
            action=record.action,
            request=self._inside(runtime, record.request),
            on_line=lambda line: self._log(record, line),
            user=container.current_user(),
        )

    async def _release_runtime(self, runtime: SessionRuntime) -> None:
        """Reap the session's container. Never raises.

        It is also the only thing that actually reaps a program that
        ignored both the cancel sentinel and SIGTERM: killing a ``docker
        exec`` client never reached the process inside the container, and
        removing the container does. One session is one container, so
        there is always that hammer.
        """
        await self.docker.remove(str(runtime.container_id))


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
    this server's own frames carry no ``seq``. The ``seq`` test is the
    load-bearing one here — a replay boundary is a position in the
    program's numbered stream, and a frame without a number has no
    position in it — while ``invocation.verdict`` is told from the
    program's ``invocation.finished`` by name since E58.
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


def _select_image(
    inventory: tuple[container.ImageFacts, ...], *, line: str
) -> container.ImageFacts:
    """Which of this server's build containers serves *line*, or a refusal.

    The backend half of E61: a context requires a Zephyr line and this
    picks the image that answers it. Candidates are exactly what
    ``capabilities`` announces — every local image carrying the
    ``org.mcuhome.contract`` label — and the property compared is the
    ``org.mcuhome.zephyr`` coupling label, which §2.1.1 makes the image's
    own statement of what it builds against. The match itself is
    ``mcuhome-model``'s :func:`~mcuhome.model.toolchain.satisfies_line`,
    borrowed for the reason the ID rule is borrowed: the local build
    method matches the same requirement against an image on a developer's
    machine, and two spellings of "this container serves 4.4" is how the
    two start disagreeing about one container.

    **The choice among several is the newest release of the line**, ties
    broken by the reference string. It has to be deterministic — two
    sessions sending one context to one server must build in one image,
    or the manifests they get back describe different builds — and of the
    deterministic rules available, "the newest patch release of the
    required line" is the one ADR 0013 already argues for: "a line, never
    a frozen point release — patch releases with security backports are
    always taken".

    An image whose label is absent, unparseable, or of another line is
    simply not a candidate: "a container that does not carry a named
    label does not qualify — absence is never read as compatible"
    (§2.1.1).
    """
    candidates = [
        facts
        for facts in inventory
        if satisfies_line(facts.labels.get(container.ZEPHYR_LABEL, ""), line=line)
    ]
    if not candidates:
        # **Lines, not labels.** ADR 0019's amendment names this field
        # "the lines actually served" and the error registry repeats it,
        # so it carries what a client could actually put in a context's
        # `zephyr`: a label states a *release*, and echoing releases back
        # under the name of lines offers values that either pin a frozen
        # point release (which ADR 0013 forbids) or, for a pre-release
        # like `4.5.0-rc1`, satisfy no line at all — including their own.
        # `line_of` is the reduction and `satisfies_line`'s own inverse,
        # so every entry here is a line some image on this host serves.
        offered = sorted(
            {
                served
                for facts in inventory
                if (served := line_of(facts.labels.get(container.ZEPHYR_LABEL, ""))) is not None
            },
            key=lambda entry: tuple(int(part) for part in entry.split(".")),
        )
        raise SessionError(
            "version.builder-unsatisfiable",
            f"No build container on this server carries Zephyr {line}. This server "
            "answers a context's Zephyr line out of the images it already has and pulls "
            f"nothing, so the {line} line has to be on this host before a context "
            "requiring it can build.",
            required=line,
            available=offered,
        )
    return max(candidates, key=lambda facts: (_release_key(facts), facts.reference))


def _pinned(facts: container.ImageFacts) -> str:
    """How this backend names *facts* to docker: by digest where it has one.

    ``inventory`` reports the tag ``docker image ls`` listed, and a tag
    is a name that can be made to point at other bytes between the
    selection at ``send-context`` and the container start of the first
    working command — while "a tag or tag suffix carries no
    compatibility meaning" (§2.1) and no identity (ADR 0018 §7). So every
    ``docker`` call this backend makes about a chosen image names it by
    digest **wherever the image has one**.

    Where it has none it is named by the tag ``inventory`` listed, and
    that window stays open: an image built on this host and never pushed
    carries no repo digest, which is why the manifest records
    ``digest: null`` for it (§3.2). The format declares that window
    rather than hiding it — such an image names no bytes anybody could
    fetch, and there is nothing to pin it with that a client could ever
    check.

    The digest is the one docker paired with *this* reference's own
    repository (:func:`~mcuhome_buildserver.container._facts_from`), so
    the two halves joined here always name the same image. A digest
    borrowed from another repository the image also lives under would
    compose a reference this host cannot resolve — and on a server that
    pulls nothing, an unresolvable name is a session that cannot build.

    The tag is **not** thrown away: it stays on ``facts.reference``,
    which is how this host lists the image and what the manifest records
    beside the digest.
    """
    return ContainerResolution.from_reference(facts.reference, digest=facts.digest).reference()


def _release_key(facts: container.ImageFacts) -> tuple[int, ...]:
    """A candidate's Zephyr release, ordered numerically.

    Only ever called on a candidate :func:`_select_image` already
    accepted, so the label is a suffix-free dotted number by
    construction and there is nothing here to refuse.
    """
    return tuple(int(part) for part in facts.labels[container.ZEPHYR_LABEL].strip().split("."))


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


def describe_problem(program: dict[str, Any]) -> str | None:
    """Everything that has to hold about a ``describe`` before it is used.

    §7.1.1 makes every field of the block mandatory in a ``describe``
    result, ``trees`` included, and the gates that follow are the ones a
    backend has to pass before it may invoke anything: a contract
    version it implements, a request version the program parses and a
    result version it writes.

    **Profile-independent, and that is why the label cross-check is not
    here.** Every gate below is asked of the ``program`` block alone,
    which is the only discovery channel the ``subprocess`` profile has
    (§7.1); §2.1's "labels that do not contradict what the block just
    said" is asked separately, by :func:`_label_problem`, because there
    are no labels where there is no image.
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
    return None


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
