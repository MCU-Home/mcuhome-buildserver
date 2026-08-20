# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The backend: this server's half of one session's build.

:class:`SessionBackend` is what one build-server process knows about
running builds. It is **not** an orchestrator — a session's build
environment is the workbench's, the same object a local build gets — and
what stays here is what a *protocol* has and a build does not:
which images this host can serve, whether a client may run the one it
pinned, invocation ids, the audience watching them, the replay boundary,
egress and the verdict frame.

**A backend is never a build environment.** Nothing here compiles
anything; it materializes an environment, prepares an invocation in it,
relays what the program says and reads what came back.

The layering, from the outside in:

* :mod:`mcuhome.buildserver.sessions` owns the verbs and the state
  machine and calls into this module through ``state.backend``;
* this module owns the *lifecycle* — build-environment discovery, the
  session's runtime, the invocation record, the event and log relay, and
  what an invocation is worth at the end of it;
* :mod:`mcuhome.buildserver.container` owns docker discovery,
  :mod:`mcuhome.buildserver.abi` owns the result document's vocabulary,
  :mod:`mcuhome.buildserver.events` owns the NDJSON stream and
  :mod:`mcuhome.buildserver.artifacts` owns egress.

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
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcuhome.model.context import EnvironmentPin
from mcuhome.model.sdkindex import SDK_PACKAGE_NAME
from mcuhome.workbench import api as workbench

from mcuhome.buildserver import (
    abi,
    artifacts,
    container,
    environments,
    errors,
    events,
    protocol,
)
from mcuhome.buildserver.abi import Artifact, TreeEntry
from mcuhome.buildserver.config import Config
from mcuhome.buildserver.contextstore import ContextPins, SessionPaths
from mcuhome.buildserver.errors import SessionError
from mcuhome.buildserver.processes import LineSink

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "ACTION_BUILD",
    "ACTION_DESCRIBE",
    "ACTION_VERIFY",
    "CONTRACT_VERSION",
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

    What a subclass adds on top is only how the environment is *named*:
    :class:`ImageProfile` names it by image reference and repo digest.
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
    def environment(self) -> str:
        """How **this host** names the environment serving the session.

        The one thing a profile has to answer for itself, because it is
        the one thing ``describe`` does not answer: what an environment
        is *called* is exactly what the two profiles do not share. It no
        longer goes into ``manifest.yaml`` — the client's pin does — so
        this is a statement about this server, for a client that wants to
        know what its pin was answered with.
        """
        raise NotImplementedError

    def to_wire(self) -> dict[str, Any]:
        """What ``send-context`` answers about the serving environment.

        ``build_environment`` is now an **acknowledgement**: the context
        pinned one image, this server found it, and this is the name that
        image answers to here. It is worth answering even though the
        client already knows what it asked for — the two spellings differ
        (a client may pin an image the server lists under another tag),
        and in the ``subprocess`` profile there is no image at all, which
        this is the field that says.

        The four fields after it come out of ``describe``, which is
        authoritative, rather than out of an image's labels, which are a
        pre-start hint that is cross-checked against it — so they are
        answered here once, for both profiles.
        """
        return {
            "build_environment": self.environment,
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
    def environment(self) -> str:
        """How this host names the image: by digest where it has one."""
        return _pinned(self.facts)


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
    #: What ``describe`` answered for the environment serving this session.
    image: ProgramProfile
    paths: SessionPaths
    #: The ``trees`` block every invocation of this session writes. Fixed
    #: for the session because the patch set of a locked context cannot
    #: change (§6.2) and because mounts cannot be added to a running
    #: container.
    trees: dict[str, TreeEntry]
    patched_layers: tuple[str, ...]
    #: The build environment, which is the workbench's and not this
    #: server's: it holds the container, the session's ``work`` and the
    #: trees, and it is what an invocation is prepared and run against.
    environment: Any = None
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
    #: What the orchestrator judged, kept between :meth:`_supervise` and
    #: :meth:`_collect`.
    local_outcome: Any = None
    #: The workbench invocation this record stands for. It owns the
    #: request document, the sentinel and the judgement; this record owns
    #: the id, the wire and the replay.
    invocation: Any = None
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
    """Everything one build-server process knows about running builds.

    One instance per :class:`~mcuhome.buildserver.app.ServerState`. It
    holds no session state of its own beyond what a build environment
    needs — the session record stays in
    :class:`~mcuhome.buildserver.sessions.Session` — because the two have
    different lifetimes: a session exists from ``open-session``, and its
    build environment exists from the first command that needs one.

    **It is not an orchestrator.** A session's build environment is the
    workbench's — the same object a local build gets — and what is left
    here is what a *protocol* has and a build does not: which images this
    host can serve, whether a client may run the one it pinned,
    invocation ids, the audience watching them, the replay boundary and
    the verdict frame. Everything below :meth:`_prepare_invocation` is
    the orchestrator's: the request document, the mounts, the liveness
    ladder, §5.3's judgement.

    **Two seams onto one docker, and they answer different questions.**
    :attr:`docker` is discovery: is there a runtime, which images are
    here, fetch one. It is asynchronous because it is asked from verb
    handlers, on the event loop. :attr:`driver` is the orchestrator's,
    synchronous, and used only inside a worker thread — because driving a
    container means blocking on a build. Merging them would mean giving
    one of the two the other's concurrency shape for nothing; the
    discovery half goes away when ``capabilities`` is rebuilt.
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
        driver: workbench.Docker | None = None,
    ) -> None:
        self.config = config
        self.docker = container.Docker(config.docker) if docker is None else docker
        self.driver = workbench.Docker(config.docker) if driver is None else driver
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
    # The session's build environment
    # ----------------------------------------------------------------

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

    async def resolve_image(
        self, pins: ContextPins, context: Path, *, on_progress: LineSink | None = None
    ) -> ImageProfile:
        """The image the context pins, found or fetched, described and gated.

        Called from ``send-context``, which is where ADR 0019's
        amendment puts container discovery: "``send-context`` answers
        what the context determines — the serving build container's
        contract version and its command set", because only with the
        pins in hand does the backend know *which* container serves the
        session.

        **The client chose; this server finds, fetches or refuses.** The
        context names one image, pinned to a digest, and it is hashed
        into the context's identity — so an image "of the same line" is
        not a substitute for it, and there is nothing here to select.
        What there is, is the question of whether this host already has
        those bytes: with fetching allowed (the default) a miss is a
        pull, because a digest names exactly one set of bytes and
        fetching them decides nothing. What *is* a decision — may this
        server run images from that repository at all — was settled
        before the first ``docker`` command, and independently of the
        switch.

        Four gates, in the order that makes each one's refusal legible:
        the repository is allowed; the runtime is there; this host has
        the pinned image, or can get it; ``describe`` answers, answers
        conformingly, and says something this server can actually drive.

        *on_progress* receives the pull's own output line by line. A
        fetch is minutes long and a client that asked for a session is
        entitled to see why it is waiting.
        """
        del context  # a digest answers itself; nothing is read off the bytes
        # First, and before any `docker` command names this image: every
        # gate below costs a container, so a conformance check cannot be
        # what decides whether a stranger's image may run
        # (:mod:`mcuhome.buildserver.environments`).
        environments.check_allowed(
            pins.build_environment.reference,
            allowed=self.config.allowed_environments,
            what="the context",
        )
        await self.docker.require_runtime()
        facts = await self._present(pins.build_environment, on_progress=on_progress)
        # And again on what the digest actually found. An image is
        # matched by digest alone, so a context may name a listed
        # repository while its pin belongs to an image from somewhere
        # else entirely — checking only the client's spelling would be
        # checking a string the client chose.
        environments.check_allowed(
            facts.reference,
            allowed=self.config.allowed_environments,
            what="the image its digest found",
        )
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

    async def _present(
        self, pin: EnvironmentPin, *, on_progress: LineSink | None
    ) -> container.ImageFacts:
        """The pinned image, on this host — fetched first if it is not.

        The inventory is asked twice on the fetching path, and the
        second answer is the one that counts: a pull that reports
        success and still leaves nothing this server recognizes is an
        image without the contract label, which the inventory filters
        out and which would otherwise become a confusing failure two
        gates later.
        """
        inventory = await self.docker.inventory()
        found = _pinned_image_in(inventory, pin=pin)
        if found is not None:
            return found
        if not self.config.auto_pull:
            raise _no_such_environment(inventory, pin=pin, fetched=False)
        logger.info("fetching build environment %s", pin.reference)
        pulled = await self.docker.pull(
            pin.reference, on_line=on_progress if on_progress is not None else lambda _line: None
        )
        found = _pinned_image_in(await self.docker.inventory(), pin=pin) if pulled else None
        if found is None:
            raise _no_such_environment(await self.docker.inventory(), pin=pin, fetched=True)
        return found

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

        The whole of "one session, one build environment": the profile is
        the one :meth:`resolve_image` produced at ``send-context`` and
        ``lock-context`` froze into ``manifest.yaml``, taken off the
        session rather than chosen again. What is checked here is only
        that it is still present, because a build that started against an
        image removed in between would fail somewhere unhelpful.
        """
        profile = session.image
        assert isinstance(profile, ImageProfile)  # noqa: S101 - resolve_image's own type
        await self.docker.require_runtime()
        pin = session.pins.build_environment
        # Asked about **this** image and not about the inventory: the
        # choice was made at `send-context` and re-listing what this host
        # has would be the shape of making it again. A targeted inspect
        # answers the only question left — are those bytes still here.
        #
        # Asked as ``repository@digest`` and not as the pin's own
        # spelling: docker resolves ``repo:tag@digest`` happily, but what
        # it reports back are the names it *has* — repo tags and repo
        # digests — and a pin carrying both is neither of them, so an
        # inspect by it comes back matching nothing.
        if await self.docker.image(environments.digest_reference(pin.reference)) is not None:
            return profile
        raise SessionError(
            "version.builder-unavailable",
            f"The build environment {pin.reference} is no longer on this host. This "
            "session was opened against it and its manifest names it, so another image "
            "of the same line is not a substitute: the firmware would be attributed to "
            "a context that does not describe it.",
            environment=pin.reference,
            digest=pin.digest,
        )

    async def ensure_runtime(
        self, session: Any, pins: ContextPins, *, context_id: str
    ) -> SessionRuntime:
        """The session's build environment, materialized by the workbench.

        Everything this used to do itself — verify the SDK package
        against its pin, learn the mount layout from ``describe``,
        arrange the trees piece by piece, start the container with this
        profile's resource ceilings — is one call now, and it is the same
        call a local build makes. That is the whole of the rebuild: a
        context that arrived over a socket and one created on this
        machine reach the same orchestrator, so a fix to either is a fix
        to both.

        Materialization stays **lazy**, as ADR 0019 §2 asks: the first
        command that needs an environment is ``verify`` or ``build``, and
        a session that never builds should not pay for an SDK fetch.

        Off the event loop, because underneath it hashes a multi-gigabyte
        package, streams a zstd decompression to disk and untars it. On
        the loop that would stall every other session, every other
        connection and the WebSocket heartbeat, which drops unrelated
        clients after thirty seconds.
        """
        existing = self._runtimes.get(session.id)
        if existing is not None:
            return existing
        paths: SessionPaths = session.paths
        profile = await self._session_environment(session)
        paths.prepare_backend()
        try:
            environment = await asyncio.to_thread(
                workbench.open_environment,
                paths.context,
                work_root=paths.root,
                config=self._backend_config(),
                docker=self.driver,
                # The protocol's own name for this session, so that the
                # marker §6.3 writes into `work`, this server's logs and
                # the id a client is holding are one string.
                session=session.id,
            )
        except workbench.MCUHomeError as refusal:
            raise _materialization_refusal(refusal) from refusal
        runtime = SessionRuntime(
            session_id=session.id,
            image=profile,
            paths=paths,
            trees=dict(environment.trees),
            patched_layers=environment.patched,
            environment=environment,
        )
        self._runtimes[session.id] = runtime
        logger.info(
            "session %s: container build environment %s (context %s)",
            session.id,
            profile.environment,
            context_id,
        )
        return runtime

    def _backend_config(self) -> workbench.BackendConfig:
        """This server's configuration, as the orchestrator's own.

        The two lists that are **not** here are the point of the mapping
        rather than an omission. There is no image: the locked context
        names it, pinned to a digest. And the compiler cache is offered
        read-only or not at all — contract §10 makes a shared store
        read-only for untrusted work, and this server serves contexts it
        does not trust, so the writable half of the orchestrator's cache
        layout is deliberately left unmounted.
        """
        return workbench.BackendConfig(
            sdk_sources=tuple(self.config.sdk_sources),
            jobs=self.config.build_jobs,
            shared_ccache_dir=self.config.ccache_dir,
            labels={container.SESSION_LABEL: "1"},
            memory=self.config.container_memory,
            cpus=self.config.container_cpus,
            pids=self.config.container_pids,
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
        mode: str | None,
    ) -> InvocationRecord:
        """The workbench prepares it; this server numbers it and remembers it.

        The split is exactly the one the rebuild draws. The directory,
        the empty ``out`` and ``tmp``, the events file, the sentinel and
        the request document are contract duties and belong to the
        orchestrator. The invocation **id**, the session's record of it
        and the audience watching it are session-protocol duties and
        belong here.
        """
        invocation = runtime.environment.prepare(action, mode=mode)
        session.invocation_counter += 1
        record = InvocationRecord(
            id=f"inv-{session.invocation_counter}",
            session_id=session.id,
            action=action,
            directory=invocation.directory,
            context_id=context_id,
            patched_layers=runtime.patched_layers,
            invocation=invocation,
        )
        session.invocations[record.id] = _RUNNING
        self._records[(session.id, record.id)] = record
        return record

    async def _supervise(self, runtime: SessionRuntime, record: InvocationRecord) -> int | None:
        """Run the invocation through the orchestrator, relaying as it goes.

        The ladder is the orchestrator's now — the sentinel first,
        SIGTERM after the grace period, SIGKILL after that, and the
        deadline entering at the top by touching the same sentinel — and
        so is draining the event file. What stays here is the wire: every
        log line is numbered and offered to the session's audience, and
        every event is relayed verbatim under the frame shape this
        protocol uses.

        Off the event loop for the whole invocation, which is where a
        build spends its minutes. The relays are called from that thread
        and reach the loop through
        :meth:`~asyncio.AbstractEventLoop.call_soon_threadsafe`, because
        an outbox is not thread-safe and a build log is the one thing
        written fast enough for that to matter.
        """
        loop = asyncio.get_running_loop()

        def on_line(line: str) -> None:
            loop.call_soon_threadsafe(self._log, record, line)

        def on_event(event: dict[str, Any]) -> None:
            frame = protocol.event_frame(event.get("event", ""), _event_payload(record, event))
            loop.call_soon_threadsafe(lambda: self._publish(record, frame, drop_when_full=True))

        outcome = await asyncio.to_thread(record.invocation.run, on_line=on_line, on_event=on_event)
        record.local_outcome = outcome
        return outcome.exit_code

    async def _collect(
        self, record: InvocationRecord, *, exit_code: int | None
    ) -> abi.InvocationOutcome:
        """What the orchestrator judged, as this server's wire vocabulary.

        Nothing is judged twice. §5.3's seven conditions and §9.3's
        re-hashing of every declared artifact happened inside the
        orchestrator, which is where they happen for a local build too;
        this is the adaptation of one outcome shape to the other, so that
        the verdict frame, the error envelope and the reason-to-code
        table stay exactly what they were.
        """
        del exit_code  # the orchestrator's outcome carries its own
        local = record.local_outcome
        if local is None:
            return abi.InvocationOutcome(
                action=record.action,
                exit_code=None,
                result=None,
                problems=("the invocation did not run",),
            )
        declared = tuple(local.artifacts)
        leftovers = await asyncio.to_thread(artifacts.undeclared, record.out, declared)
        if leftovers:
            # Not served and not deleted: they are diagnostic material
            # (§9.3), and saying so in the log is the only way anybody
            # finds out they exist.
            logger.info(
                "invocation %s: %d undeclared file(s) left in out", record.id, len(leftovers)
            )
        return abi.InvocationOutcome(
            action=local.action,
            exit_code=local.exit_code,
            result=None if local.result is None else abi.ResultDocument(local.result),
            successful=local.successful,
            problems=tuple(local.problems),
            violation=local.violation,
            artifacts=tuple(local.artifacts),
        )

    async def _release_runtime(self, runtime: SessionRuntime) -> None:
        """Reap the container. That, and not a signal, is what stops a build.

        Killing a ``docker exec`` client never stopped the process inside
        the container, so this is the rung the ladder ends at — and it is
        the orchestrator's, because the container is.
        """
        environment = runtime.environment
        if environment is None:
            return
        with contextlib.suppress(Exception):
            await asyncio.to_thread(environment.close)

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
                environment=runtime.image.environment,
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

        record = self._prepare_invocation(
            session, runtime, action=action, context_id=context_id, mode=mode
        )
        runtime.busy = True
        self.attach(session.id, connection)
        task = asyncio.create_task(
            self._drive(session, runtime, record), name=f"mcuhome-invocation-{record.id}"
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return record

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
        # The idle clock counts absent commands, and the command that
        # started this invocation was sent before it ran: a fifteen-minute
        # build would end into a session already minutes past its idle
        # timeout, and the next verb — `get-artifact`, the one that
        # collects what the build produced — would be refused
        # `session.expired`. Observed exactly so, on a build that had
        # just finished linking. Finishing work is activity.
        session.touch()
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

    def _verdict(self, outcome: abi.InvocationOutcome, record: InvocationRecord) -> dict[str, Any]:
        """The payload of the ``invocation.verdict`` frame (E46, E58).

        It carries the status and the artifact list, which is what E46
        asks for, plus the two things a client cannot get anywhere else:
        the context id **this server** computed — attribution always
        uses that one, never ``result.context`` — and, on a failure, the
        session protocol's own error envelope, mapped from the
        program's ``reason`` through
        :data:`~mcuhome.buildserver.errors.REASON_CODES`.

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
            "artifacts": [entry.to_dict() for entry in outcome.artifacts],
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


def _materialization_refusal(refusal: Exception) -> SessionError:
    """One of the orchestrator's typed refusals, as this protocol says it.

    The orchestrator refuses in words, because its first caller is a
    person at a terminal; the session protocol refuses in codes, because
    its caller is a program deciding whether to try another server. The
    translation is a table of **types** and not of messages — matching on
    wording is how a rephrased sentence becomes a wrong error code — and
    the words are carried into the details, where they are the most
    useful thing in the frame.

    Anything unrecognized stays ``error.internal`` by not being caught
    here: an orchestrator failure this server has no code for is a defect
    on this side, and dressing it as a client-facing refusal would send a
    client looking for a mistake it did not make.
    """
    if isinstance(refusal, workbench.SdkUnavailable):
        # The pin, and **not** the directories that were searched: those
        # are this operator's filesystem, and a client that pinned a
        # package this server does not have has no use for the paths it
        # is not in. The orchestrator carries them because a person at a
        # terminal is looking at their own machine; here they stop.
        return SessionError(
            "sdk.unavailable",
            f"This server has no {SDK_PACKAGE_NAME} {refusal.version} whose bytes hash to "
            f"{refusal.sha256}. Its SDK packages come from directories its operator "
            "configured, and the url in a context is a hint that is never fetched.",
            version=refusal.version,
            sha256=refusal.sha256,
        )
    if isinstance(refusal, workbench.EnvironmentUnavailable):
        code = "version.builder-unsatisfiable"
    elif isinstance(refusal, workbench.EnvironmentUnusable):
        code = "version.builder-unavailable"
    else:
        raise refusal
    return SessionError(code, str(refusal.message), problem=str(refusal))


def _event_payload(record: InvocationRecord, event: dict[str, Any]) -> dict[str, Any]:
    """One program event, addressed to a session and otherwise untouched.

    §8: "a backend passes an event whose name it does not know through to
    its client verbatim, with its fields intact". The two identifiers are
    added because a client watching one socket may be watching several
    sessions; nothing else is added, removed or rewritten.
    """
    return {"session_id": record.session_id, "invocation_id": record.id, **event}


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

#: Mirrors of :mod:`mcuhome.buildserver.sessions`' invocation states.
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


def _pinned_image_in(
    inventory: tuple[container.ImageFacts, ...], *, pin: EnvironmentPin
) -> container.ImageFacts | None:
    """The image this context is pinned to, out of what this host has.

    Matched on the **digest and nothing else**. A reference is a name and
    names move; the digest is what the context's identity is computed
    over, so an image that answers to the right name with other bytes is
    not the pinned environment and building in it would attribute the
    firmware to a context that does not describe it.

    Two digests can match, and both are legitimate. A **repository
    digest** is what an image pulled from a registry carries, and it is
    the portable case. An **image ID** is what an image built on a
    machine and never pushed has instead, and a client on this same host
    pins one of those by its ID — which is why a build server and its
    client sharing a machine can use a container neither of them could
    fetch.

    Candidates are the images of :meth:`~container.Docker.inventory` —
    the same set ``capabilities`` announces, so a client that read that
    answer and a server that acts on it are looking at one list.
    """
    for facts in inventory:
        if pin.digest in (facts.digest, facts.image_id):
            return facts
    return None


def _no_such_environment(
    inventory: tuple[container.ImageFacts, ...], *, pin: EnvironmentPin, fetched: bool
) -> SessionError:
    """This server will not be building that context, and why.

    Two codes, because a client acts on them differently and
    ``retryable`` is what says so. ``version.builder-unsatisfiable`` is
    an operator's standing decision: the images here are placed by hand,
    and nothing about waiting changes it. ``version.builder-unfetchable``
    covers everything a pull can fail at — no network, a registry wanting
    a login, a private repository, a digest nothing answers to, or bytes
    that arrived carrying no contract label. Most of those come back, so
    it is retryable; the reason itself is in the pull output the client
    already watched.

    Both name **what this host could build** instead, so the answer is
    actionable rather than only negative: every environment it has,
    spelled the way a client would have to pin one.
    """
    offered = sorted({facts.reference for facts in inventory})
    if not fetched:
        return SessionError(
            "version.builder-unsatisfiable",
            f"This server does not have the build environment {pin.reference}, and it "
            "does not fetch. Its build environments are placed by its operator, so a "
            "context naming one it does not have cannot build here.",
            required=pin.reference,
            available=offered,
        )
    return SessionError(
        "version.builder-unfetchable",
        f"This server could not fetch the build environment {pin.reference}. The pull "
        "output above says why; the usual reasons are no network, a registry that wants "
        "a login, and a digest nothing answers to.",
        required=pin.reference,
        available=offered,
    )


def _pinned(facts: container.ImageFacts) -> str:
    """How this backend names *facts* to docker: by digest where it has one.

    ``inventory`` reports the tag ``docker image ls`` listed, and a tag
    is a name that can be made to point at other bytes between the
    selection at ``send-context`` and the container start of the first
    working command — while "a tag or tag suffix carries no
    compatibility meaning" (§2.1) and no identity (ADR 0018 §7). So every
    ``docker`` call this backend makes about a chosen image names it by
    digest **wherever the image has one**.

    Where it has none it is named by the tag ``inventory`` listed: an
    image built on this host and never pushed carries no repo digest.
    That is a narrower window than it reads: the *pin* such an image is
    matched against is its docker ID, which is content-addressed and
    changes on every rebuild, so a rebuild between the lock and the
    build makes :meth:`~SessionBackend._session_environment` refuse
    rather than silently building in the new bytes.

    The digest is the one docker paired with *this* reference's own
    repository (:func:`~mcuhome.buildserver.container._facts_from`), so
    the two halves joined here always name the same image. A digest
    borrowed from another repository the image also lives under would
    compose a reference this host cannot resolve — and on a server that
    pulls nothing, an unresolvable name is a session that cannot build.

    The tag is **not** thrown away: it stays on ``facts.reference``,
    which is how this host lists the image and how a log names it.
    """
    if not facts.digest:
        return facts.reference
    name, _, _ = facts.reference.partition("@")
    head, colon, tail = name.rpartition(":")
    repository = head if colon and "/" not in tail else name
    return f"{repository}@{facts.digest}"


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
    "MUST equal the ``org.mcuhome.build-environment.contract`` label; where the two
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
