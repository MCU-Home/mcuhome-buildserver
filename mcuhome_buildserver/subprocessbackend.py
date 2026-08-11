# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The subprocess backend: one filesystem, one build environment, one child.

The second profile of build-container contract §1.2, and the deployment
ADR 0019 calls the Home Assistant App case: "the build environment runs
**in the same filesystem as the build server**, but as a **separate
process** … the backend runs the program as a subprocess in its own
filesystem namespace instead of via ``docker exec``."

**It is still a backend and still never a build environment.** Nothing
here compiles anything: it materializes the paths, writes the request
document, starts the program and reads its result — §1.2's own sentence,
which "is what lets 'the build server drives build environments and is
never one itself' hold without an exception". What is shared is the
**filesystem, not the process**, and that is the whole difference from
the in-process embedding this superficially resembles: a build running
inside the server process cannot be cancelled without killing the server,
an out-of-memory kill or a segfault takes the queue with it, and only a
separate process leaves a third party free to write the program in any
language.

Everything §9 asks of a backend is
:class:`~mcuhome_buildserver.backend.SessionBackend`'s and is shared
verbatim with the container profile — the per-invocation directory, the
request document, the SDK verified against the pin, liveness, the event
and log relay, egress hardening, the verdict. §9.1 says of that list that
"neither shape moves a duty from this list onto the program". What this
module adds is the profile's own four things.

**1. The reduced promises, named rather than absent.** §1.2 lists three
and this module keeps none of them: **no network isolation** (there is no
namespace to take the network away from, so §9.1's "no network during an
invocation" is an obligation on the program and nothing this server can
check), **no per-session resource limits** (``--memory``, ``--cpus`` and
``--pids-limit`` are container flags and there is no container; the
operator's ``--container-*`` settings are not read here and this server
says so rather than pretending they apply), and **no container trust
boundary**. The third has a consequence worth spelling out because it is
easy to assume otherwise: §9.1 asks the backend to write-protect
``context`` and every non-writable tree "with the strongest means its
profile has", and in this profile that means is *nothing stronger than
the obligation*. The program runs as this server's own user, so any mode
this server could set it could also undo. A read-only ``context`` here is
§9.2 rule 1 being honoured, not enforced.

What survives is precisely what §1.2 says survives: **cancellability and
process-level isolation**. A cancel reaches the program itself here, and
through the program's process group the compile it started — the one
place this profile is *stronger* than the other, where SIGTERM reaches a
``docker exec`` client and never the process behind it. The group is not
a detail: the program is what *starts* west, cmake and ninja, so a signal
to its pid alone would reach an entry point and leave the build running
(:func:`~mcuhome_buildserver.processes.spawn_command`).

**2. One build environment, and it is the one this server runs in.**
§1.2: "A ``subprocess``-profile backend serves **exactly one build
environment — the one it runs in**. It MUST reject, typed, any session
whose context requires a Zephyr line that build environment does not
carry." The line that environment carries is read off **the program's
own ``describe``** — ``program.trees.zephyr.version``, §7.1.1's record of
"where the image keeps each layer it carries" and what it says that layer
is (:func:`served_lines`). That is the only source that can be right for
both deployments this profile has: the default program is the installed
MCUHome compiler and answers out of the west workspace on this host,
while a configured ``--program`` (§2.2) may be a third party's binary in
any language over a build environment this server installed nothing of.
A constant in a package installed beside the *server* would describe the
server in both cases, and in the second case describe the wrong machine
entirely. The refusal itself is the container profile's, unchanged —
``version.builder-unsatisfiable``, with the required line and the lines
actually served in its details — and a program that declares no Zephyr
line at all serves none, which is refused at discovery rather than read
as compatible (§2.1.1).

**3. No fixed paths, ever.** "Because the filesystem is shared, nothing
in this profile may depend on a fixed path: several concurrent sessions
live side by side in one namespace and cannot all have the same context,
work or output directory" (§1.2). Every path this backend names is under
the per-session directory
:class:`~mcuhome_buildserver.contextstore.SessionPaths` already gives it,
so two sessions collide nowhere. The one place a fixed path could still
enter is §4's declared tree path — "a declared path is then a requirement
the backend MUST satisfy" — and this backend cannot satisfy one: it has
no mount namespace, so it cannot give each concurrent session its own
view of one path. §4 states exactly that case and its consequence ("a
backend that cannot give each concurrent session its own view of that
path cannot use that image. It learns so from ``describe``, before it
starts a session"), so a program declaring a path for ``sdk`` is refused
at discovery rather than served into a collision.

**4. Only the tree this backend owns is handed over writable.** The SDK
is unpacked per session (§9.1's verified SDK) and dies with the session,
so it is a writable view by construction when the ``sdk`` layer carries
patches — exactly as in the container profile. Every other layer lives in
a **persistent** build environment here, and §6.2 makes constructing a
writable view of it the backend's job in this profile: "a copy-on-write
overlay on the host … or a copy as the conforming fallback". **This
backend constructs neither**, so it names no ``trees`` entry for such a
layer, and a context that patches one is refused by the program with
``unsupported.required`` before it does any work: the pointer
``/trees/<layer>`` still goes into the request's ``required`` list, and
§5.2 rule 2 makes a required pointer the program cannot honour a refusal
it must make while parsing, ahead of anything it would look at a layer
for. Asserting ``writable: true`` for a shared persistent tree would be
the one thing that must not happen here: it would leak one session's
patches into every later build on this host, silently.
"""

from __future__ import annotations

import contextlib
import logging
import uuid
from dataclasses import dataclass
from typing import Any

from mcuhome.model.context import ContainerResolution
from mcuhome.model.toolchain import line_of, satisfies_line

from mcuhome_buildserver import abi, container, processes, sdkstore
from mcuhome_buildserver.abi import TreeEntry
from mcuhome_buildserver.backend import (
    ACTION_DESCRIBE,
    InvocationRecord,
    ProgramProfile,
    SessionBackend,
    SessionRuntime,
    describe_problem,
)
from mcuhome_buildserver.config import Config
from mcuhome_buildserver.contextstore import ContextPins, SessionPaths
from mcuhome_buildserver.errors import SessionError
from mcuhome_buildserver.program import Program, program_argv

__all__ = ["HostProfile", "SubprocessBackend", "served_lines"]

logger = logging.getLogger(__name__)


def served_lines(profile: ProgramProfile) -> tuple[str, ...]:
    """The Zephyr lines the build environment behind *profile* carries.

    Discovered from the program and never configured — see this module's
    docstring for why it cannot be either a knob or a constant. The
    source is ``describe``'s ``program.trees.zephyr.version``, which
    §7.1.1 makes the environment's own statement about the tree it
    carries, and the whole of the derivation is two steps:

    **West's spelling to the contract's.** A version in that field is a
    *revision* — MCUHome's own program reports what ``west list`` prints,
    which is the manifest's tag, ``v4.4.0``. §2.1.1's value range has no
    leading ``v``, and MCUHome's own image already normalizes the same
    way for its ``org.mcuhome.zephyr`` label (the r7 repair: "§2.1.1 asks
    for the version *without* west's leading ``v``"). Exactly one leading
    ``v`` is dropped and nothing else about the value is touched — a
    branch name or a commit sha is not a release, and what does not parse
    as one below must not be repaired into one here.

    **Release to line.** :func:`~mcuhome.model.toolchain.line_of`, the
    same function the container backend reads its labels through, so
    "this environment serves 4.4" has one spelling on both paths. It
    answers ``None`` for anything that is not a plain release — a sha, a
    branch, ``v4.5-rc1`` — and this returns nothing at all in that case
    rather than a line it guessed.

    An empty answer is a build environment that serves nothing, which is
    §2.1.1's rule about the missing label applied to the missing field:
    absence is never read as compatible.
    """
    version = profile.tree_version("zephyr")
    if version is None:
        return ()
    candidate = version[1:] if version.startswith("v") else version
    line = line_of(candidate)
    return () if line is None else (line,)


@dataclass(frozen=True)
class HostProfile(ProgramProfile):
    """This host's build environment, as its own ``describe`` answers.

    The counterpart of
    :class:`~mcuhome_buildserver.backend.ImageProfile`, and it is shorter
    for the reason §2 gives: "In the ``subprocess`` profile there is no
    image; the backend knows its own program's path and its own identity,
    and answers the same questions from ``describe``." There is no
    reference, no repo digest and no label to cross-check against —
    ``describe`` is the whole of what is known, and §7.1 makes it the
    authority anyway.
    """

    @property
    def resolution(self) -> ContainerResolution:
        """This environment as ``manifest.yaml``'s ``container:`` records it.

        §3.2 makes the block "the record of which build environment
        answered this context's requirement … what reproduces the build
        years later", and it has three fields. Here the honest filling is
        the program's own identity and version — the two things §7.1.1
        makes a program state about itself — with ``digest: null``,
        because there is no image and therefore nothing that names
        fetchable bytes. E61 already made ``null`` a first-class value of
        that field for the never-pushed image, and it says the same thing
        here: this record names no bytes anybody can pull, and saying so
        is better than inventing a digest for a filesystem.

        The two ``mcuhome-model`` requires to be non-empty strings are
        both there: ``id`` is reverse-DNS and mandatory in the block, and
        ``version`` is the implementation's own — opaque to a backend,
        which is why it is recorded rather than parsed.
        """
        version = self.program.get("version")
        return ContainerResolution(
            image=self.identity,
            tag=version if isinstance(version, str) and version.strip() else "unknown",
            digest=None,
        )


class SubprocessBackend(SessionBackend):
    """The build environment this server runs in, driven as a child process."""

    #: ``subprocess``, and it is what ``open-session`` answers in
    #: ``negotiated.backend_profile``. A client reading it knows the
    #: three promises of §1.2's second row are not being made.
    profile = "subprocess"

    def __init__(self, config: Config, *, program: Program | None = None) -> None:
        super().__init__(config)
        self.program = Program(program_argv(config.program)) if program is None else program
        #: ``describe``'s answer, asked once. The program is a property
        #: of this **deployment** rather than of a session: there is one
        #: of it, it is the environment this process runs in, and an
        #: operator who upgrades it under a running server restarts the
        #: server — which is the honest cache key here, where the
        #: container profile has an image digest to name bytes with.
        self._profile: HostProfile | None = None

    # ----------------------------------------------------------------
    # Discovery
    # ----------------------------------------------------------------

    async def inventory(self) -> list[dict[str, Any]]:
        """What this server can serve, for ``capabilities``.

        ADR 0019 §2 asks this verb for "available builder images (tag +
        digest + contract labels)", and there is no image here — but the
        question a client asks it is "what can this server build", and
        answering nothing would say this server can build nothing. So the
        same three fields are answered about the one build environment
        there is: the reference is the program's identity and version,
        the digest is ``null`` (there are no bytes to fetch), and the
        labels carry what this backend can state **truthfully**.

        **One entry per served Zephyr line**, which with today's single
        supported line is exactly one entry. A label holds one value, and
        the line is what a client reads off it, so an environment serving
        two lines cannot be described by one entry without dropping a
        line or stating a false one.

        ``org.mcuhome.toolchain`` is **absent, and deliberately**. §2.1's
        coupling labels are properties of an *image*; there is none here,
        and this backend cannot state the toolchain identity of a host it
        did not build. §2.1.1's "absence is never read as compatible" is
        the correct reading of that gap: a client writing a constraint
        over the toolchain finds nothing here, which is true.

        A program that cannot answer ``describe`` answers an empty list
        rather than a refusal, for the reason the container backend gives
        about an unreachable runtime: the question is which environments
        this server can serve, "none" is a fact rather than an error, and
        the refusal belongs to the verb that actually needs one.
        """
        try:
            profile = await self._host()
        except SessionError:
            return []
        reference = profile.resolution.reference()
        return [
            {
                "reference": reference,
                "digest": None,
                "labels": {
                    container.CONTRACT_LABEL: str(profile.program.get("contract")),
                    container.ZEPHYR_LABEL: line,
                },
            }
            for line in served_lines(profile)
        ]

    async def resolve_image(self, pins: ContextPins) -> HostProfile:
        """The build environment for a context's Zephyr line — or the refusal.

        Called from ``send-context``, the same place the container
        backend resolves an image, and it answers the same question with
        one candidate instead of an inventory: "a backend with exactly
        one build environment cannot choose, so it can only accept or
        refuse" (ADR 0019's amendment, in the sentence that replaced the
        digest rule with the line rule).

        The match is ``mcuhome-model``'s
        :func:`~mcuhome.model.toolchain.satisfies_line`, borrowed for the
        reason the ID rule is borrowed: the same function decides it in
        the container backend and in the workbench's local method, and
        two spellings of "this environment serves 4.4" is how two of them
        start disagreeing about one build.
        """
        profile = await self._host()
        served = served_lines(profile)
        if not any(satisfies_line(line, line=pins.zephyr) for line in served):
            raise SessionError(
                "version.builder-unsatisfiable",
                f"This build server's own build environment does not carry Zephyr "
                f"{pins.zephyr}. It runs in the subprocess profile, so it serves exactly "
                "one build environment — the one it runs in — and cannot answer a context "
                "requiring another line by choosing something else.",
                required=pins.zephyr,
                available=sorted(served),
            )
        return profile

    async def _host(self) -> HostProfile:
        """Ask the program what it is, once, and gate what it answered.

        ``describe`` is "the only discovery channel that exists in the
        ``subprocess`` profile, where there is no image and therefore no
        labels" (§7.1), and §2.2.1's static self-description explicitly
        "has no meaning" here. So this is the whole of discovery, and it
        "doubles as the first conformance test: a program that cannot
        answer ``describe`` cannot be trusted with a build" — which is
        why every failure below is one refusal,
        ``version.builder-unavailable``, and why none of them is
        retryable: nothing about this program will be different in a
        second.

        The probe directory is per call, for the same reason §5.1 step 1
        gives about invocations: it is a backend-owned per-invocation
        directory, ``describe`` is an invocation, and two concurrent ones
        sharing a directory would have the second delete the first's
        answer.
        """
        if self._profile is not None:
            return self._profile
        probe = self.config.context_root / ".probe" / f"describe-{uuid.uuid4().hex}"
        probe.mkdir(mode=0o700, parents=True, exist_ok=True)
        request = probe / "request.json"
        result = probe / "result.json"
        result.unlink(missing_ok=True)
        try:
            # The preamble alone: `describe` "needs only `request` and
            # `result`, never touches the context, writes nothing but the
            # result document". A backend that sent more would be
            # inviting a program to echo a field it was never promised.
            abi.write_request({"request": abi.REQUEST_VERSION, "result": str(result)}, request)
            completed = await self.program.describe(request=request)
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
            raise self._not_conforming("; ".join(outcome.problems) or "describe failed")
        block = outcome.result.program
        found = HostProfile(program=block)
        problem = describe_problem(block) or self._tree_problem(found) or self._line_problem(found)
        if problem is not None:
            raise self._not_conforming(problem)
        self._profile = found
        return self._profile

    def _tree_problem(self, profile: HostProfile) -> str | None:
        """The one gate §4 adds for a backend with no mount namespace.

        A ``trees`` entry with a concrete ``path`` is a *requirement*
        since the D1 erratum — "a declared path is then a requirement the
        backend MUST satisfy for that image, and not a convention" — and
        the tree this backend supplies is ``sdk``, unpacked per session
        into the session's own directory. Satisfying a declared path for
        it would mean putting several sessions' SDKs at one path, which
        is the collision §1.2 forbids and which only a mount namespace
        can resolve. §4 names this exact case and its outcome: "a backend
        that cannot give each concurrent session its own view of that
        path cannot use that image. It learns so from ``describe``,
        before it starts a session and before it promises a client
        anything."

        Only ``sdk`` is checked, because only ``sdk`` is a tree this
        backend supplies. A path declared for a layer that lives in the
        environment is the program describing its own filesystem, which
        is exactly what §7.1.1 says such a path is for.
        """
        declared = profile.tree_path("sdk")
        if declared is None:
            return None
        return (
            f"it requires the sdk tree at the fixed path {declared}, and this backend has no "
            "mount namespace to give each concurrent session its own view of one path — the "
            "SDK is unpacked per session, so a fixed path would be two sessions' SDKs in one "
            "directory"
        )

    def _line_problem(self, profile: HostProfile) -> str | None:
        """The gate §1.2's line rule needs before it can refuse anything.

        "It MUST reject, typed, any session whose context requires a
        Zephyr line that build environment does not carry" presupposes
        knowing which line it carries, and :func:`served_lines` learns
        that from the program. A program that names none has not said it
        carries every line — it has said nothing, and §2.1.1 fixes what
        nothing means: "absence is never read as compatible".

        It is a discovery-time refusal rather than a per-context one
        because the fact is about the deployment and not about any
        context: an installed compiler with no west workspace behind it
        (the ``pip install`` and nothing else case) answers ``describe``
        with every tree ``null``, and every ``build`` it is ever sent
        would die deep inside the program, after the SDK package has been
        fetched, hashed and unpacked, with a message about a workspace
        the client cannot supply. Refusing here makes ``capabilities``
        answer an empty inventory and ``send-context`` refuse, which is
        the truth about that host said at the first moment it is
        knowable.
        """
        if served_lines(profile):
            return None
        stated = profile.tree_version("zephyr")
        if stated is None:
            found = "declares no version for its zephyr tree"
        else:
            found = f"declares zephyr tree version {stated!r}, which names no Zephyr release line"
        return (
            f"it {found}, so there is no line this build environment can be said to carry — and a "
            "backend serving exactly one build environment has to know its line before it can "
            "reject a context requiring another one"
        )

    def _not_conforming(self, problem: str) -> SessionError:
        """A program that cannot be trusted with a build, and why.

        ``version.builder-unavailable`` rather than a code of its own,
        for the reason its registry entry gives: from the client's side
        there is no build environment on this server that can serve its
        context. The detail says what was wrong with it, because the
        party who can act on it is the operator and the client is only
        the messenger.
        """
        return SessionError(
            "version.builder-unavailable",
            f"The program this server invokes ({self.program.display}) cannot serve a "
            f"session: {problem}. describe is authoritative about what a build environment "
            "can do and doubles as the first conformance test, so a program that cannot "
            "answer it conformingly is not one this server will invoke a build on.",
            program=self.program.display,
            problem=problem,
        )

    # ----------------------------------------------------------------
    # The session's build environment
    # ----------------------------------------------------------------

    async def _session_environment(self, session: Any) -> HostProfile:
        """The environment this session was answered with — this one.

        The container profile has to check that its choice is still on
        the host between the lock and the first build. Here there is
        nothing to check and nothing that could have changed: there is
        one build environment, it is the process's own filesystem, and
        the profile the session holds is the answer ``describe`` gave for
        it. What is asserted is only that the session *has* one, which
        means ``send-context`` ran.
        """
        profile: HostProfile | None = session.image
        if profile is None:  # pragma: no cover - set with the pins at send-context
            raise SessionError(
                "context.missing",
                f'Session "{session.id}" holds no build environment to work in.',
                session_id=session.id,
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
        """Name the trees, and start nothing (§4.1).

        There is nothing to start: the build environment is already
        running this process, and the program is started per invocation
        rather than per session. So this is the whole of materialization
        — deciding what the request document's ``trees`` block will say.

        **``sdk``, at the per-session path it was unpacked into.** No
        mount, no target path of anyone's choosing: the tree is where
        :mod:`~mcuhome_buildserver.sdkstore` put it, inside the session's
        own directory, which is what keeps two concurrent sessions apart
        in one namespace. It is handed over writable exactly when the
        ``sdk`` layer carries patches, and that assertion is truthful for
        the same reason it is in the other profile — a per-session copy
        that dies with the session *is* the writable view §6.2 asks for.

        **Nothing else**, and the module docstring says why: every other
        layer of this environment is persistent and shared, this backend
        constructs no host-side overlay and makes no copy, and asserting
        ``writable: true`` for a shared tree would leak one session's
        patches into every later build. A patched layer therefore gets no
        entry while its pointer still goes into ``required`` (the base's
        ``_document``) — and *that* pair is what a conforming program
        refuses, with ``unsupported.required`` and ``/trees/<layer>`` in
        ``error.details.required``. Not ``error.layer.unknown``: §5.2
        rule 2 makes an unhonourable ``required`` pointer a parsing
        refusal, which comes before the layer scan that would have
        produced the other reason. Both map to ``builder.failed`` on the
        wire (:mod:`mcuhome_buildserver.errors`), so the difference is
        invisible in the code and visible in exactly one place: the
        ``reason`` a client reads and an operator greps the log for.
        """
        sdk_writable = "sdk" in patched
        trees: dict[str, TreeEntry] = {"sdk": TreeEntry(path=package.tree, writable=sdk_writable)}
        unservable = tuple(layer for layer in patched if layer != "sdk")
        if unservable:
            logger.warning(
                "session %s: no writable view for patched layer(s) %s in the subprocess "
                "profile; the program will refuse this context with unsupported.required, "
                "naming /trees/<layer>",
                session.id,
                ", ".join(unservable),
            )
        return SessionRuntime(
            session_id=session.id,
            image=profile,
            paths=paths,
            trees=trees,
            patched_layers=patched,
            ccache=self._shared_cache(profile),
        )

    # ----------------------------------------------------------------
    # Invocations
    # ----------------------------------------------------------------

    async def _start(self, runtime: SessionRuntime, record: InvocationRecord) -> processes.Process:
        """Start the program as a child of this process (§5.1).

        ``<program> <action> <absolute path of the request document>``,
        with a **stated** environment
        (:class:`~mcuhome_buildserver.program.Program`) and nothing else:
        no flags, no container, no shell. The handle is kept on the
        runtime because in this profile it is the only address the build
        has — there is no container to remove at ``close-session``, so
        :meth:`_release_runtime` needs the child itself.

        **And it is checked back against the registry the moment it
        exists.** The handle can only be published *after* the spawn, so
        between the two there is a window in which teardown finds no
        child and kills nothing: ``close-session`` is deliberately not
        serialized against work in flight
        (:mod:`mcuhome_buildserver.sessions`), and it pops the runtime,
        releases it and then deletes the session's tree. A child started
        into that window would be a build against a directory being
        deleted, with the profile's only teardown hook already run. So
        the state is re-read after the await instead of assumed across
        it — the same move ``_require_still_ours`` makes for the sibling
        race — and a runtime that is no longer this session's is a child
        that is killed here, at the first instant it can be.
        """
        process = await self.program.invoke(
            action=record.action,
            request=record.request,
            on_line=lambda line: self._log(record, line),
        )
        runtime.child = process
        if self._runtimes.get(runtime.session_id) is not runtime:
            logger.warning(
                "session %s: released while invocation %s was starting; killing it at once",
                runtime.session_id,
                record.id,
            )
            process.kill()
            runtime.child = None
        return process

    async def _release_runtime(self, runtime: SessionRuntime) -> None:
        """Stop the session's child and everything it started. Never raises.

        This is this profile's ``docker rm --force``, and it ends in a
        kill rather than a request for E39's reason: by the time this
        runs the session's lifetime is over, its directory is about to be
        deleted, and the program's result document is not a deliverable
        any more — there is nowhere left to deliver it to. The
        cooperative path was already offered, by the cancel sentinel
        ``close-session`` sets before it calls here.

        **What is signalled is the child's process group and not the
        child**, which is the whole difference between reaching the
        program and reaching the build. The program is not the compile:
        it starts west, which starts cmake, which starts ninja, which
        starts the compilers, and a signal to one pid leaves that tree
        running against a directory ``close-session`` deletes a moment
        later — unreaped, on a host that by §1.2 has no per-session
        memory, CPU or PID ceiling to bound it. The group is what
        :func:`~mcuhome_buildserver.processes.spawn_command` arranges and
        :meth:`~mcuhome_buildserver.processes.Process.stop` addresses:
        SIGTERM first, so ninja can stop its own edges, then SIGKILL for
        whatever is still there. *That* is §1.2's "cancellability …
        remain[s]" made concrete, and it is why a session left with a
        running compile cannot outlive its directory here.
        """
        child: processes.Process | None = runtime.child
        if child is None:
            return
        await child.stop()
        runtime.child = None
