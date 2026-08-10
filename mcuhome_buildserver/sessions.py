# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Session protocol v2 — the session registry and one handler per verb.

The remote-build architecture replaced the one-shot job protocol with a
**session model**: one session = one ephemeral build container = one
effective build context. The same verb set has a local backend (the
workbench drives the container runtime directly) and this remote one,
which adds auth, policy and scheduling on top of the identical verbs.

These verbs are the whole vocabulary of the ``/ws`` endpoint. The job
protocol they replaced was dismantled rather than migrated; what
survived it is the transport underneath — the frame envelope, the
connection handling and the bearer token.

**The context has a lifetime of its own inside the session, and
``lock-context`` is where the two part company** (ADR 0019's amendment
of 2026-08-09). A context arrives, is extended any number of times, and
is then frozen by an explicit verb; the freeze writes ``manifest.yaml``,
computes the context ID and unlocks the working commands. That order is
ADR 0019 §2's flow diagram, and it is what the state machine on
:class:`Session` enforces::

    open-session       session id, lease, version negotiation (no context yet)
    send-context       base context incl. the pins; the container can be created
    extend-context     repeatable; MUST NOT touch the pin file
    [read-only commands permitted]
    lock-context       freezes the context, writes manifest.yaml, computes and
                       returns the context id; unlocks the writing commands
    verify / build     only from here
    get-artifact
    close-session

Before the lock, ``verify`` and ``build`` are refused with
``context.not-locked``; after it, every writing command is refused with
``context.locked``, because the lock is one-way and adding to a locked
context is a new session rather than an extension.

**The context path is real.** ``send-context`` receives an archive
under streaming ingress caps, unpacks it safely into a per-session
directory this server owns, parses the pins out of ``context.yaml`` and
answers what it accepted. ``extend-context`` does the same for
additions and takes a list of removals with it, staging everything so
that a refusal leaves the accepted context untouched.
``lock-context`` hashes the bytes received, computes the context ID
through ``mcuhome-model`` and writes ``manifest.yaml``. The transport
under all three — the JSON announcement, the BINARY frames, the caps,
the whitelist — lives in :mod:`mcuhome_buildserver.ingress`, and the
directory, the pin document and the freeze in
:mod:`mcuhome_buildserver.contextstore`.

What is deliberately not here yet — the container backend, the overlay
patch views, invocations and scheduling — answers with a typed
``session.not-implemented`` instead of a guess, so a client sees a
protocol that is honest about its state rather than one that almost
works. ``cancel`` is real since the second amendment settled its wire
shape (E38) — bookkeeping, acknowledgement, the ``already_finished``
answer — and only the sentinel file the acknowledgement promises stays
with the container backend (:func:`_signal_cancellation`).

Admission and negotiation live at ``open-session``, not in ``verify``:
a version mismatch is a typed rejection at the door, never a downstream
failure. Container materialization is lazy by design — opening a
session reserves nothing but a record and a lease, and the backend may
defer creating a container until the first command that needs one,
which is also why the serving container's own contract version is
answered by ``send-context`` rather than here.
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcuhome.model.context import CONTEXT_FILE
from mcuhome.model.hashes import sha256_file

from mcuhome_buildserver.contextstore import (
    ContextPins,
    SessionPaths,
    count_context_files,
    freeze_context,
    parse_context_yaml,
    recheck_patch_policy,
)
from mcuhome_buildserver.errors import SessionError
from mcuhome_buildserver.ingress import (
    IngressCaps,
    IngressLedger,
    Upload,
    ancestors,
    check_file_target,
    check_path_shape,
    type_conflict,
    unpack,
)
from mcuhome_buildserver.protocol import Command, ProtocolError

__all__ = [
    "CONTEXT_FORMAT_MAX",
    "CONTEXT_FORMAT_MIN",
    "CONTEXT_LOCKED",
    "CONTEXT_NONE",
    "CONTEXT_UNLOCKED",
    "DEFAULT_IDLE_TIMEOUT",
    "DEFAULT_MAX_OPEN_SESSIONS",
    "DEFAULT_REAP_INTERVAL",
    "DEFAULT_SESSION_TTL",
    "PATCH_LAYERS",
    "PROFILES",
    "SESSION_PROTOCOL_VERSION",
    "SESSION_VERBS",
    "Session",
    "SessionManager",
    "UPLOAD_VERBS",
    "capabilities_payload",
    "is_patch_layer_name",
]

#: Bumped when the *session* protocol changes shape. Version 2 because
#: the one-shot job protocol of dashboard ADR 0006 was version 1. That
#: protocol no longer exists here, but the number is not reclaimed: a
#: client that speaks 1 must be told it is behind, not handed a 2 that
#: means something else.
SESSION_PROTOCOL_VERSION = 2

#: The context format range this server accepts (`context: N` in the
#: context's entry file `context.yaml`). Not "manifest format": ADR
#: 0018's amendment splits the request from the record, and the version
#: is declared in the document that travels with the base context —
#: `manifest.yaml` repeats it, but that document is written by this side
#: at `lock-context` and is never an input. Two constants for the same
#: reason as the model version range: accepting an older format later is
#: a change here, not a protocol change.
CONTEXT_FORMAT_MIN = 1
CONTEXT_FORMAT_MAX = 1

#: The session profiles. The profile drives admission, TTL, idle
#: timeout and the per-profile resource budget; commands outside the
#: declared profile are rejected typed. (Per-profile budgets are future
#: work — today every profile gets the defaults below.)
PROFILES = ("oneshot", "dev", "test")

#: The patch layers the protocol knows. A patch's layer is its subfolder
#: in the context (``patches/<layer>/``); policy is always re-derived
#: from the files actually present, never from a declared list.
#:
#: **Four**, since 2026-08-09: build-container contract §1.1 defines
#: ``zephyr``, ``sdk``, ``chip`` and ``mcuboot``, and ``mcuboot`` is a
#: layer because every device build is ``west build --sysbuild`` with
#: MCUboot as the second image. It was missing here, which meant an
#: operator could not allow a layer the contract names.
PATCH_LAYERS = ("sdk", "zephyr", "chip", "mcuboot")

#: Third-party layer names carry an ``x-`` prefix, "so that two vendors
#: cannot collide on one name and have a context silently patch the
#: wrong tree" (contract §1.1). The registry of un-prefixed names is
#: owned by the MCUHome project and is :data:`PATCH_LAYERS`; an ``x-``
#: name is nameable by anyone and, like every other layer, allowed only
#: where an operator listed it.
_X_LAYER = re.compile(r"x-[a-z0-9][a-z0-9._-]*\Z")


def is_patch_layer_name(name: str) -> bool:
    """Whether *name* is a layer name a config may allow at all.

    Nameable is not the same as allowed: this says the string could be a
    layer, while :data:`~mcuhome_buildserver.config.Config.allowed_patch_layers`
    says whether contexts may patch it. Keeping them apart is what lets
    a third-party ``x-`` layer be configured without this server having
    to know what it is.
    """
    return name in PATCH_LAYERS or _X_LAYER.fullmatch(name) is not None


#: Hard TTL: a session older than this is reaped no matter what it is
#: doing. Generous relative to one cold build (~14 min on a slow
#: machine), small relative to a forgotten one.
DEFAULT_SESSION_TTL = 3600.0

#: Idle timeout: absent *commands*, not absent connections — a client
#: may disconnect and attach-session back without losing the session.
#: Enforced by :meth:`SessionManager.reap` and by
#: :meth:`SessionManager.require`, which is what makes it a timeout
#: rather than a number in a lease document.
DEFAULT_IDLE_TIMEOUT = 600.0

#: How often the reaper sweeps. Well under both timeouts above and far
#: enough apart that a sweep costs nothing: the work is a walk over a
#: dictionary that holds at most :data:`DEFAULT_MAX_OPEN_SESSIONS`
#: entries. It is a constant rather than an option because it is not a
#: policy — the policy is the lease, and this is only how long a reaped
#: session's directory may still be on disk after its lease ran out.
DEFAULT_REAP_INTERVAL = 30.0

#: Concurrent open sessions, per **server**. v1.0 is single-tenant and
#: one bearer token is one principal, so a per-user quota would be a
#: per-server quota with a misleading name (ADR 0019's amendment); the
#: per-user machinery, work metering and cost classes belong to the
#: hosted phase and are not implemented here.
DEFAULT_MAX_OPEN_SESSIONS = 4

STATE_OPEN = "open"
STATE_CLOSED = "closed"

#: The context's three states inside a session. They exist because the
#: freeze is an **explicit verb** rather than an implicit one on "the
#: first writing command": an implicit freeze needs an enumerated list
#: of writing commands kept in sync with a verb set that is append-only
#: by decision, and a third-party command could not know which side of
#: the line it falls on (ADR 0019's amendment). The two states that
#: matter are named after the two typed errors that hang on them —
#: `context.not-locked` while the context is still open to writes,
#: `context.locked` once it is not.
CONTEXT_NONE = "none"
CONTEXT_UNLOCKED = "unlocked"
CONTEXT_LOCKED = "locked"

#: One invocation's place in its life, as `cancel` and `close-session`
#: see it. The container backend moves invocations to FINISHED when a
#: result document lands; CANCELLING is "the stop signal is set" — the
#: acknowledged state of ADR 0019's second amendment, never "it
#: stopped", which only the result document says.
INVOCATION_RUNNING = "running"
INVOCATION_CANCELLING = "cancelling"
INVOCATION_FINISHED = "finished"


@dataclass
class Session:
    """One admitted session: its identity, profile, lease and context state.

    The session is admitted on **no context at all** — that is what
    ADR 0019's amendment takes away from ``open-session`` — so a fresh
    session starts at :data:`CONTEXT_NONE` and the pins arrive later,
    with ``send-context``, in ``context.yaml``.
    """

    id: str
    profile: str
    created_at: float
    expires_at: float
    idle_timeout: float
    #: The context format this session was **admitted on**. Recorded
    #: because ``send-context`` measures ``context.yaml`` against it and
    #: says so in the refusal ("this session was admitted on N"): reading
    #: :data:`CONTEXT_FORMAT_MAX` there instead made that sentence true
    #: only for as long as the accepted range has one number in it, and
    #: the range exists precisely so it can widen.
    context_format: int = CONTEXT_FORMAT_MAX
    state: str = STATE_OPEN
    #: Where the context stands: :data:`CONTEXT_NONE`,
    #: :data:`CONTEXT_UNLOCKED` or :data:`CONTEXT_LOCKED`. One-way in
    #: that order — the lock is a boundary, not a mode.
    context_state: str = CONTEXT_NONE
    last_command_at: float = 0.0
    #: Poisoned means "can no longer do work": the second amendment's
    #: terminal state after an interrupted patch application. One-way.
    #: Deliberately NOT a session state — the session stays OPEN so
    #: get-artifact and close-session keep working, which is the point.
    poisoned: bool = False
    #: Every invocation this session ever ran, id -> INVOCATION_* state.
    #: The bookkeeping `cancel` addresses; the container backend is what
    #: will populate it and flip entries to FINISHED.
    invocations: dict[str, str] = field(default_factory=dict)
    #: The per-session directory this session owns, once ``send-context``
    #: has created one. ``None`` until then and after :meth:`discard`,
    #: which is the same thing as "there is nothing on disk to delete".
    paths: SessionPaths | None = None
    #: What ``context.yaml`` declared, kept because ``manifest.yaml``
    #: repeats the pin blocks exactly as it stated them.
    pins: ContextPins | None = None
    #: The hash of ``context.yaml`` as it was accepted. The freeze
    #: re-measures the file against it — the pin document is outside the
    #: integrity list by construction, so nothing else would notice.
    context_yaml_sha256: str | None = None
    #: What this session has spent of the ingress caps and its disk
    #: quota. Cumulative across the base context and every extension
    #: (E44), which is the only way a cap can bound a repeatable verb.
    ledger: IngressLedger = field(default_factory=IngressLedger)
    #: True while a context command is running. One at a time, per
    #: session — see :func:`_context_work`.
    context_busy: bool = False
    #: Which half of the lease reaped this session, or ``None`` if
    #: nothing did. Kept apart from :data:`STATE_CLOSED` so that a client
    #: coming back to a session the sweep took still hears
    #: ``session.expired`` — "it outlived its lease" and "you closed it"
    #: are different pieces of news, and the sweep must not turn the
    #: first into the second. It carries the reason rather than a flag
    #: because the two halves are different advice: a hard TTL says the
    #: work was too long for one session, an idle timeout says nobody was
    #: driving it.
    reaped: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "profile": self.profile,
            "state": self.state,
            "context_state": self.context_state,
            "created_at": round(self.created_at, 3),
        }

    def lease_dict(self) -> dict[str, Any]:
        return {
            "ttl_seconds": round(self.expires_at - self.created_at, 3),
            "idle_timeout_seconds": self.idle_timeout,
            "expires_at": round(self.expires_at, 3),
        }

    # ----------------------------------------------------------------
    # The context state machine, as three guards
    # ----------------------------------------------------------------

    def require_writable_context(self) -> None:
        """Refuse a writing command once the context is frozen.

        Every command that would change the context — ``send-context``,
        ``extend-context`` and a second ``lock-context`` — passes
        through here. After the lock the context is closed to writes
        **entirely**, which is wider than the rule it replaced: the old
        one protected ``manifest.yaml`` alone, and there is no manifest
        before the lock and nothing left to add after it.
        """
        if self.context_state == CONTEXT_LOCKED:
            raise SessionError(
                "context.locked",
                f'The context of session "{self.id}" is locked. The lock is one-way: '
                "send-context, extend-context and a second lock-context are all refused "
                "from here. Adding to a locked context is a new session.",
                session_id=self.id,
                context_state=self.context_state,
            )

    def require_workable(self) -> None:
        """Refuse every working command of a poisoned session.

        The second amendment's terminal state: an interrupted patch
        application "fails typed, and every further working command in
        that session is refused". The session is deliberately NOT reaped
        on the spot — ``get-artifact`` and ``close-session`` stay
        permitted, because the moment a session poisons is exactly the
        moment its owner most wants the logs and partial artifacts that
        explain what happened, and destroying them to simplify the state
        machine would trade diagnosis for tidiness. Cleanup happens where
        it always happens: ``close-session`` or lease expiry.

        ``cancel`` deliberately does not pass through here: it stops
        work rather than doing any, and a poisoned session may still
        have an invocation worth stopping.
        """
        if self.poisoned:
            raise SessionError(
                "session.poisoned",
                f'Session "{self.id}" can no longer do work: a patch application was '
                "interrupted and the trees cannot be trusted. Collect what get-artifact "
                "still offers, close the session, and start a new one with pristine trees.",
                session_id=self.id,
            )

    def poison(self) -> None:
        """One-way. The caller is the future container backend (§6.3)."""
        self.poisoned = True

    def require_context(self) -> None:
        """Refuse a command that has no context to work on.

        ``extend-context`` and ``lock-context`` both need a base context
        to exist. No ADR names a code for the case, and this is the
        registry's own entry for "the command needs a context and
        send-context has not happened" — which is exactly it.
        """
        if self.context_state == CONTEXT_NONE:
            raise SessionError(
                "context.missing",
                f'Session "{self.id}" has no context yet. send-context delivers the base '
                "context with its pins in context.yaml; extend-context and lock-context "
                "both need one to work on.",
                session_id=self.id,
            )

    def require_no_context(self) -> None:
        """Refuse a second base context before the lock (E43).

        ``send-context`` delivers *the* base context, once. A second one
        is not an extension — it would replace the pins the session was
        admitted on, which is the one thing the format forbids for the
        life of a session — and it is not a reset either, because the
        server has already answered what it accepted. So it is refused
        and the client is told which of the two it meant: changes go
        through ``extend-context``, a fresh start is a new session.
        """
        if self.context_state != CONTEXT_NONE:
            raise SessionError(
                "context.exists",
                f'Session "{self.id}" already has a base context. Add to it with '
                "extend-context, or open a new session to send different pins — "
                "send-context delivers the base context once.",
                session_id=self.id,
                context_state=self.context_state,
            )

    def require_locked_context(self) -> None:
        """Refuse a working command issued before the lock.

        ``verify`` and ``build`` run **only from the lock onwards**, and
        they are the only two verbs of the flow the documents qualify
        that way. It is what makes ``verify`` mean anything: the lock
        writes the ``files`` integrity list, so there is something
        stable to check the effective context against.
        """
        if self.context_state != CONTEXT_LOCKED:
            raise SessionError(
                "context.not-locked",
                f'The context of session "{self.id}" is not locked, and verify and build '
                "run only from the lock onwards. lock-context freezes the file set, "
                "writes manifest.yaml and returns the context id.",
                session_id=self.id,
                context_state=self.context_state,
            )

    # ----------------------------------------------------------------
    # The directory the session owns
    # ----------------------------------------------------------------

    def discard_context(self) -> None:
        """Delete the session's directory and forget the context.

        ADR 0019's amendment: the per-session directory — the context
        and every artifact in it — is destroyed at ``close-session``,
        which is also why ``get-artifact`` has to run before it. The same
        call is what a refused ``send-context`` uses, so that a rejected
        upload leaves the session exactly as it found it: no directory,
        no pins, and ``context_state`` back at :data:`CONTEXT_NONE`.
        """
        if self.paths is not None:
            self.paths.discard()
        self.paths = None
        self.pins = None
        self.context_yaml_sha256 = None
        self.context_state = CONTEXT_NONE
        self.ledger.disk_bytes = 0


def _lease_over(session: Session, now: float) -> str | None:
    """Which half of the lease has run out, or ``None``.

    Two halves and one answer, so that admission, the reaper and
    ``require`` cannot disagree about whether a session is still alive.
    The hard TTL bounds a session that is working; the idle timeout
    bounds one that is not, and it counts absent **commands** rather than
    absent connections — a client may drop its socket and
    ``attach-session`` back without losing anything, which is exactly
    what makes a closed socket unusable as the signal here.
    """
    if now > session.expires_at:
        return "lease"
    if session.idle_timeout > 0 and now > session.last_command_at + session.idle_timeout:
        return "idle timeout"
    return None


class SessionManager:
    """Every session this process knows, and the admission rules.

    In-memory on purpose: a session is bound to one container instance
    on this machine, so unlike a job record it has nothing worth
    surviving a restart — a restarted server has no containers, and
    leases guarantee the clients find out through typed
    ``session.unknown`` answers rather than hangs.
    """

    def __init__(
        self,
        *,
        ttl: float = DEFAULT_SESSION_TTL,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        max_open: int = DEFAULT_MAX_OPEN_SESSIONS,
    ) -> None:
        self._sessions: dict[str, Session] = {}
        self.ttl = ttl
        self.idle_timeout = idle_timeout
        self.max_open = max_open

    @property
    def open_count(self) -> int:
        """Sessions that hold an admission slot **right now**.

        A session past its lease does not, even before the reaper has
        walked over it. Counting one would let four abandoned clients
        close this server to new sessions until somebody restarted it —
        the sweep runs every :data:`DEFAULT_REAP_INTERVAL` seconds and
        the answer must not depend on where in that interval the
        question is asked.
        """
        now = time.time()
        return sum(
            1
            for session in self._sessions.values()
            if session.state == STATE_OPEN and _lease_over(session, now) is None
        )

    def reap(self, *, now: float | None = None) -> tuple[str, ...]:
        """Close and discard every session whose lease ran out.

        **The sweep is what makes "deleted at lease expiry" true.**
        Before it existed, a lease expired only when a client came back
        with the session id and asked — so a client that crashed, or
        simply closed its socket, left ``context.yaml`` and ``keys/`` on
        disk with nothing left in the process that could ever name them
        again, and held one of :data:`DEFAULT_MAX_OPEN_SESSIONS`
        admission slots for the life of the server. The directory holds a
        device's Matter commissioning credentials, and "until somebody
        asks about it" is not a retention policy for those.

        Both halves of the lease are swept, because both are real: the
        hard TTL bounds a session that is working, and the idle timeout
        bounds one that is not. Returns the ids reaped, for the log.
        """
        moment = time.time() if now is None else now
        reaped: list[str] = []
        for session in list(self._sessions.values()):
            over = _lease_over(session, moment) if session.state == STATE_OPEN else None
            if over is None:
                continue
            session.state = STATE_CLOSED
            session.reaped = over
            session.discard_context()
            reaped.append(session.id)
        return tuple(reaped)

    def shutdown(self) -> None:
        """Discard every live session's directory. For process exit.

        A stopping server is a server whose sessions are already over —
        they are in-memory records bound to this process (see the class
        docstring), so nothing that survives it could use one. What can
        survive it is the directory, and that is the half worth deleting
        on the way out.

        A process that is killed outright still leaves its directories
        behind, and no in-memory record can name them afterwards. That
        case is deliberately **not** answered by sweeping ``context_root``
        at startup: two servers sharing one root is a misconfiguration,
        and a startup sweep would answer it by deleting the other's live
        sessions — trading a directory nobody can reach for credentials
        somebody is using.
        """
        for session in list(self._sessions.values()):
            if session.state == STATE_OPEN:
                session.state = STATE_CLOSED
            session.discard_context()

    def open(
        self,
        *,
        profile: str,
        protocol_version: int,
        context_format: int,
    ) -> Session:
        """Admission. Every refusal is typed, at the door (concept §4).

        Three operands and no fourth: ADR 0019's amendment takes the
        manifest header away from ``open-session``, so admission decides
        the protocol version, the context-format version and the
        profile, and nothing about the context itself.
        """
        if protocol_version != SESSION_PROTOCOL_VERSION:
            raise SessionError(
                "version.protocol-mismatch",
                f"This server speaks session protocol {SESSION_PROTOCOL_VERSION} and the "
                f"client asked for {protocol_version}. Neither side may guess: upgrade "
                "the one that is behind.",
                server=SESSION_PROTOCOL_VERSION,
                client=protocol_version,
            )
        if not CONTEXT_FORMAT_MIN <= context_format <= CONTEXT_FORMAT_MAX:
            raise SessionError(
                "version.context-format-unsupported",
                f"This server reads context formats {CONTEXT_FORMAT_MIN}-"
                f"{CONTEXT_FORMAT_MAX}, and this context claims format {context_format}.",
                supported={"min": CONTEXT_FORMAT_MIN, "max": CONTEXT_FORMAT_MAX},
                received=context_format,
            )
        if profile not in PROFILES:
            raise SessionError(
                "session.profile-unknown",
                f'"{profile}" is not a session profile this server has.',
                profiles=list(PROFILES),
            )
        if self.open_count >= self.max_open:
            raise SessionError(
                "session.limit-exceeded",
                f"This server admits at most {self.max_open} concurrent sessions and "
                "they are all taken. Close one, or retry when a lease runs out.",
                max_open=self.max_open,
            )
        now = time.time()
        session = Session(
            id=f"s-{secrets.token_urlsafe(12)}",
            profile=profile,
            created_at=now,
            expires_at=now + self.ttl,
            idle_timeout=self.idle_timeout,
            context_format=context_format,
            last_command_at=now,
        )
        self._sessions[session.id] = session
        return session

    def require(self, session_id: str) -> Session:
        """The open session called *session_id*, or a typed refusal."""
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionError(
                "session.unknown",
                f'This server has no session called "{session_id}". It may have been '
                "reaped, or it belonged to a previous server process.",
                session_id=session_id,
            )
        over = _lease_over(session, time.time()) if session.state == STATE_OPEN else None
        if over is not None:
            session.state = STATE_CLOSED
            session.reaped = over
            # Reaped means reaped: the context goes with the lease, not
            # at some later sweep. It holds a device's Matter
            # commissioning credentials, and "we will get to it" is not
            # a retention policy for those. The periodic sweep
            # (:meth:`reap`) does the same thing for the client that
            # never comes back at all.
            session.discard_context()
        if session.reaped is not None:
            raise SessionError(
                "session.expired",
                f'Session "{session_id}" outlived its {session.reaped} and was reaped.',
                session_id=session_id,
            )
        if session.state != STATE_OPEN:
            raise SessionError(
                "session.closed",
                f'Session "{session_id}" is closed.',
                session_id=session_id,
            )
        session.last_command_at = time.time()
        return session

    def close(self, session_id: str) -> Session:
        """Close a session. Closing a closed one is not an error: the
        client asked for a state and that state holds.

        **A busy session is cancelled implicitly** (E39): every running
        invocation gets the stop signal first, its result document is
        still written by the backend, then the session is reaped.
        Refusing to close while an invocation runs was rejected because
        connection loss is never abandonment — that is
        ``attach-session``'s reason to exist — so closing must never
        require a live client to first cancel, reattach, or wait; a
        crashed client's session would otherwise hold its resources
        until lease expiry as the *normal* path rather than the
        fallback.
        """
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionError(
                "session.unknown",
                f'This server has no session called "{session_id}".',
                session_id=session_id,
            )
        for invocation_id, found in session.invocations.items():
            if found == INVOCATION_RUNNING:
                session.invocations[invocation_id] = INVOCATION_CANCELLING
                _signal_cancellation(session, invocation_id)
        session.state = STATE_CLOSED
        session.discard_context()
        return session


# --------------------------------------------------------------------------
# The verbs
# --------------------------------------------------------------------------


def capabilities_payload(state: Any) -> dict[str, Any]:
    """What the ``capabilities`` verb answers — pre-session, cheap.

    It stays the **pre-session query** after the freeze verb landed:
    ahead of a session at all, this is what lets the workbench choose a
    build container during pin resolution rather than discover the
    mismatch from inside one (ADR 0019's amendment). It fails fast
    ("this server has no build container for zephyr-4.4.0-r1") instead
    of dying mid-session, and it is the one verb that carries no session
    id, because there is no session yet to carry.

    ``containers`` is a placeholder, marked as such until its backend
    lands: it will list the available build-container images as
    ``{"tag", "digest", "labels"}`` entries once the container backend
    exists. Empty until then, and an empty list is the truthful answer —
    this server can admit sessions and build nothing.

    There is deliberately **no ``quota.work``** and no cost class. ADR
    0019's amendment binds work metering and cost classes to the hosted
    phase and says of v1.0, in as many words, that there is neither; a
    field promising a concept the valid layer removed is worse than a
    field that is not there.
    """
    config = state.config
    allowed = frozenset(config.allowed_patch_layers)
    # The four names contract §1.1 fixes, plus any third-party `x-` layer
    # this operator listed. An `x-` name cannot be enumerated — the
    # prefix exists precisely so vendors need no registration — so the
    # only ones this server can name are the ones it was told about.
    layers = list(PATCH_LAYERS) + sorted(allowed - set(PATCH_LAYERS))
    return {
        "protocol": {
            "version": SESSION_PROTOCOL_VERSION,
            "context_format": {"min": CONTEXT_FORMAT_MIN, "max": CONTEXT_FORMAT_MAX},
            "profiles": list(PROFILES),
        },
        "containers": [],
        # The server's patch configuration IS the policy; unlisted layers
        # are denied by default (concept §6). Advertised per layer so the
        # workbench refuses a patched context before uploading it.
        "patch_policy": {layer: {"allow": layer in allowed} for layer in layers},
        "quota": {
            "sessions": {
                "open": state.sessions.open_count,
                "max_open": state.sessions.max_open,
            },
        },
    }


async def capabilities(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``capabilities`` — see :func:`capabilities_payload`."""
    return capabilities_payload(state)


async def open_session(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``open-session`` — admission, and nothing about the context.

    Payload::

        {"profile": "oneshot",            # oneshot | dev | test
         "protocol_version": 2,           # required; mismatch is typed
         "context_format": 1}             # the format the context will use

    **There is no manifest operand.** ADR 0019's amendment takes
    ``open-session``'s first operand away: admission negotiates the
    protocol version, the context-format version and the profile, and
    the pins arrive with ``send-context``, in ``context.yaml``. The term
    "manifest header" is retired outright (ADR 0018's amendment) —
    there is no header separate from ``context.yaml``, and
    ``manifest.yaml`` does not exist until ``lock-context`` writes it.

    The response carries what **admission alone** decides::

        {"session": {"id", "profile", "state", "context_state", "created_at"},
         "lease": {"ttl_seconds", "idle_timeout_seconds", "expires_at"},
         "negotiated": {"protocol_version", "context_format", "backend_profile"}}

    The serving build container's contract version and command set are
    **not** here. With no context at ``open-session`` the backend does
    not yet know *which* container serves the session — the digest
    arrives with the pins — so ``send-context`` answers that half. What
    discovering early was for survives the split intact, because
    ``send-context`` precedes ``lock-context`` and therefore precedes
    every working command.

    ``negotiated.backend_profile`` is ``container`` or ``subprocess``
    (build-container contract §1.2), the field ADR 0019's amendment puts
    in this response, and ``null`` until this server has a backend: a
    server that drives neither cannot truthfully declare one. Patch
    *policy* is enforced against the files actually present, so it runs
    at ``send-context``/``extend-context`` time, not here.
    """
    protocol_version = command.optional_int("protocol_version")
    if protocol_version is None:
        raise SessionError(
            "version.protocol-mismatch",
            'open-session needs "protocol_version" in its payload; this server speaks '
            f"session protocol {SESSION_PROTOCOL_VERSION}.",
            server=SESSION_PROTOCOL_VERSION,
            client=None,
        )
    # Absent means "take the default"; present means "this is what I
    # asked for", and the two are told apart by `is None` rather than by
    # truthiness. An `or` here read `context_format: 0` and `profile: ""`
    # as absent, so both walked past the admission checks below them and
    # were answered `result` — the one thing ADR 0019 decision 2 says
    # must not happen, since "version mismatch is a typed rejection at
    # the door, never a downstream failure".
    profile = command.optional_str("profile", "oneshot")
    context_format = command.optional_int("context_format", CONTEXT_FORMAT_MAX)
    session = state.sessions.open(
        profile="oneshot" if profile is None else profile,
        protocol_version=protocol_version,
        context_format=CONTEXT_FORMAT_MAX if context_format is None else context_format,
    )
    return {
        "session": session.to_dict(),
        "lease": session.lease_dict(),
        "negotiated": {
            "protocol_version": SESSION_PROTOCOL_VERSION,
            "context_format": {"min": CONTEXT_FORMAT_MIN, "max": CONTEXT_FORMAT_MAX},
            "backend_profile": None,
        },
    }


def _not_implemented(verb: str, session: Session, **details: Any) -> SessionError:
    """The typed answer of every verb whose backend is future work."""
    return SessionError(
        "session.not-implemented",
        f'"{verb}" is part of session protocol {SESSION_PROTOCOL_VERSION} and its '
        "server logic lands with the container backend. The session itself is real: "
        "it was admitted, it holds its lease, and close-session releases it.",
        verb=verb,
        session_id=session.id,
        **details,
    )


def _archive_announcement(command: Command, key: str = "archive") -> tuple[int, str]:
    """The ``{"size", "sha256"}`` object a context upload is announced with.

    **The wire shape is E41's and nothing in the documents fixed it.**
    ADR 0019 §2 spells ``send-context(archive)`` and that single word is
    the whole wire specification the verb set gives it; the product
    owner settled the rest on 2026-08-09. The JSON payload announces the
    archive's compressed size and its SHA-256, the bytes follow as
    WebSocket BINARY frames within the existing frame cap, and the
    result frame of the verb is the acknowledgement.

    Two values and no third. There is deliberately no ``format`` field:
    the format is **tar.zst**, fixed, chosen for family consistency with
    the SDK package the same contract pins, and a field whose only legal
    value is the default is a negotiation nobody asked for.
    """
    announcement = command.optional_dict(key)
    if not announcement:
        raise ProtocolError(
            f'"{command.type}" announces its archive as '
            f'"{key}": {{"size": <bytes>, "sha256": "<64 hex digits>"}}, and then sends '
            "the tar.zst as binary frames.",
            frame_id=command.id,
        )
    size = announcement.get("size")
    digest = announcement.get("sha256")
    if isinstance(size, bool) or not isinstance(size, int):
        raise ProtocolError(f'"{command.type}" wants "{key}.size" as a whole number of bytes.')
    if not isinstance(digest, str):
        raise ProtocolError(f'"{command.type}" wants "{key}.sha256" as a string.')
    return size, digest


async def _receive_archive(
    state: Any, connection: Any, command: Command, session: Session, spool: Path
) -> Path:
    """Announce, take the binary frames, and hand back the spooled tar.

    The connection carries the upload rather than the session, because
    the frames carrying it do not: a BINARY frame has no frame id and no
    session id, so "which upload do these bytes belong to" can only be
    answered by *when* they arrive. One upload at a time per connection
    is therefore not a limitation but the wire's own shape, and a second
    concurrent announcement is refused rather than interleaved.
    """
    size, digest = _archive_announcement(command)
    upload = Upload(
        declared_size=size,
        declared_sha256=digest,
        spool=spool,
        caps=IngressCaps.from_config(state.config),
        ledger=session.ledger,
    )
    try:
        connection.begin_upload(upload)
    except BaseException:
        # The spool handle is open from the constructor; a connection
        # that refuses the announcement must not leak it.
        upload.close()
        raise
    try:
        return await upload.result(timeout=session.idle_timeout)
    finally:
        connection.end_upload(upload)


def _unpack_into(
    state: Any,
    session: Session,
    archive: Path,
    target: Path,
    *,
    allow_context_file: bool,
) -> tuple[str, ...]:
    """Unpack *archive* into *target* under this server's policy."""
    return unpack(
        archive,
        into=target,
        caps=IngressCaps.from_config(state.config),
        ledger=session.ledger,
        allowed_layers=frozenset(state.config.allowed_patch_layers),
        quota_bytes=state.config.session_quota_bytes,
        allow_context_file=allow_context_file,
    )


def _signal_cancellation(session: Session, invocation_id: str) -> None:
    """Raise the stop signal for one invocation. **Seam for the backend.**

    What this becomes is fixed by build-container contract §8 and is
    deliberately one small thing: the backend creates the **cancel
    sentinel file** that this invocation's request document named, and
    the *existence* of the file means "stop". The program polls it,
    stops within ``limits.cancel_grace_seconds`` and writes a result
    document with ``status: "cancelled"`` — which carries ``reason:
    null`` and ``error: null``, because nothing was diagnosed. SIGTERM/
    SIGKILL stays the backend's hard path behind the cooperative one.

    A sentinel file rather than a signal, for the same reason the verb
    exists at all: killing a ``docker exec`` client does not kill the
    process inside the container, and a file works unchanged in the
    ``subprocess`` profile. It lives in the backend-owned per-invocation
    directory and never inside the context, which is what keeps the
    context a genuinely read-only mount.

    The bookkeeping the verb needs exists now (:attr:`Session.invocations`,
    the E38 wire shape), so this is no longer a refusal: the caller has
    already recorded :data:`INVOCATION_CANCELLING`, and what is missing
    is only the file — which needs a per-invocation directory, which
    needs the container backend. Until then the mark IS the signal, and
    the backend's arrival changes this function's body, not its callers.

    One consequence is already fixed and belongs to the backend rather
    than here: a cancellation that lands **mid patch application**
    poisons the session (:meth:`Session.poison`, ``session.poisoned``) —
    a crash, a cancel or an out-of-memory kill after some patches but
    before all leaves trees no future build may trust.
    """
    del session, invocation_id  # the sentinel file arrives with the backend


async def send_context(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``send-context`` — upload the base context and its pins.

    Payload::

        {"session_id": "s-…",
         "archive": {"size": 4711, "sha256": "<64 hex digits>"}}

    followed by the tar.zst as BINARY frames (E41; see
    :func:`_archive_announcement`). The result frame is the
    acknowledgement, and it arrives when the declared number of bytes
    has been received, hashed to the declared value, unpacked safely and
    parsed.

    The base context carries ``context.yaml``: the format version, the
    resolved pins — container digest, SDK package sha256, target board —
    and the constraint they were resolved from. It is **required**, even
    for the empty context ADR 0019's amendment says may be locked: three
    of the four inputs of the context ID live in it, so a context
    without it has no identity to freeze. "Empty" means no *content*
    files, and that is allowed here — what a ``build`` needs beyond
    existence, ``keys/signing.pub`` above all, is checked by ``build``.

    **What the response does not carry, and why.** ADR 0019's amendment
    has ``send-context`` answer "the serving build container's contract
    version and its command set", the half of the discovery payload that
    only the context determines. This server has no container backend,
    so it can name no serving container; that half arrives with the
    backend rather than as a placeholder. What is answered is what this
    server actually decided: the pins it accepted and where the context
    now stands.

    **The pins are checked for spelling and not for truth, and the gap
    is deliberate rather than overlooked.** Build-container contract
    §9.1 requires the backend to check ``container.digest`` against the
    image it actually pulled, ``mcuhome.package.sha256`` against the
    package bytes it actually fetched and unpacked, and ``target.board``
    against the pins the session was admitted on. This server pulls no
    image and fetches no package, so two of the three have nothing to
    compare against yet, and the third has nothing either — admission
    carries no pins since ADR 0019's amendment took the manifest header
    away from ``open-session``. What stands in its place today is the
    freeze's re-check of ``context.yaml`` against the bytes accepted
    here. The remaining two land with the backend that pulls and fetches.

    For the same reason no ``version.builder-unavailable`` is raised
    here: the registry entry exists for "no build container on this
    server satisfies the context's container.digest pin", and this
    server's container inventory is an empty placeholder rather than an
    inventory. Refusing every context against it would be a false
    refusal, not a strict one.

    On any refusal the whole upload is discarded — the directory is
    deleted and the session goes back to :data:`CONTEXT_NONE`, so the
    client can send a corrected context over the same session. That is
    also the answer for a base context carrying a denied patch layer: it
    fails wholesale rather than partially, because a context is one
    artifact and half of one has no meaning.
    """
    session = state.sessions.require(command.require_str("session_id"))
    session.require_workable()
    session.require_writable_context()
    with _context_work(session):
        session.require_no_context()
        paths = SessionPaths.create(state.config.context_root, session.id)
        session.paths = paths
        try:
            archive = await _receive_archive(state, connection, command, session, paths.spool)
            _require_still_ours(session, paths)
            _unpack_into(state, session, archive, paths.context, allow_context_file=True)
            paths.spool.unlink(missing_ok=True)
            entry = paths.context / CONTEXT_FILE
            if not entry.is_file():
                raise ProtocolError(
                    "This base context carries no context.yaml. It is what carries the "
                    "pins into a session — the container digest, the SDK package hash "
                    "and the target board — and a context without it has no identity "
                    "to freeze."
                )
            pins = parse_context_yaml(
                entry,
                expected_version=session.context_format,
                max_bytes=state.config.max_context_yaml_bytes,
            )
            recheck_patch_policy(paths.context, frozenset(state.config.allowed_patch_layers))
            context_yaml_sha256 = sha256_file(entry)
        except BaseException:
            session.discard_context()
            raise
    session.pins = pins
    session.context_yaml_sha256 = context_yaml_sha256
    session.context_state = CONTEXT_UNLOCKED
    return {
        "session_id": session.id,
        "context": {"state": session.context_state, "format": pins.context_version},
        "pins": pins.to_wire(),
    }


@contextlib.contextmanager
def _context_work(session: Session) -> Iterator[None]:
    """One context command at a time, per session.

    All three context verbs pass through here — ``send-context``,
    ``extend-context`` and ``lock-context``. They share one directory,
    one ledger and one spool file, and two of them running at once take
    each other's: the second ``send-context`` of a race would create the
    directory the first is unpacking into, and its refusal would delete
    the first's bytes on the way out, while a ``lock-context`` racing an
    upload would freeze a file set the upload is still adding to and
    answer an ID for a context that no longer exists.

    Serializing rather than queueing, because queueing deadlocks by
    construction here: an upload's bytes arrive through the same reader
    that would be waiting to start the queued command. So the second
    caller is refused and told to wait, and it is refused pre-registry —
    no registered code means "a context command is already running in
    this session", and inventing one is a protocol decision rather than
    an implementation choice.
    """
    if session.context_busy:
        raise ProtocolError(
            f'A context command is already running in session "{session.id}". The '
            "context verbs share one directory and one budget, so they run one at a "
            "time; wait for the one in flight to be acknowledged."
        )
    session.context_busy = True
    try:
        yield
    finally:
        session.context_busy = False


def _require_still_ours(session: Session, paths: SessionPaths) -> None:
    """Refuse an upload whose session went away while its bytes arrived.

    ``close-session`` is deliberately not serialized against the context
    verbs — a client must be able to close a session whatever it is doing
    — so it can run while a ``send-context`` is waiting for BINARY
    frames, and it deletes the per-session directory on its way out. The
    upload then woke up holding a :class:`SessionPaths` for a directory
    that no longer exists, and unpacking into it **re-created** the tree
    ``close-session`` had just destroyed, with nothing left in the
    process that could ever name it again; the missing spool file then
    escaped as an untyped ``internal_error``.

    So the state is re-read after the await instead of assumed across
    it, and the answer is the code that says what actually happened. The
    identity check is on the object rather than on the id: a session
    cannot be re-opened today, and a check that only compares states
    would silently start passing if one ever could.
    """
    if session.state != STATE_OPEN or session.paths is not paths:
        raise SessionError(
            "session.closed",
            f'Session "{session.id}" was closed while this upload was still arriving, and '
            "its directory went with it. Nothing of the archive was kept; open a new "
            "session to send it.",
            session_id=session.id,
        )


def _require_paths(session: Session) -> SessionPaths:
    """The session's directory, or the refusal that says it has none.

    ``require_context`` reads the state machine and this reads the disk;
    the two agree by construction, because the only thing that sets
    :data:`CONTEXT_UNLOCKED` is the ``send-context`` that created the
    directory. Both are checked anyway, so that a future path into the
    state machine cannot hand a verb a context that is not there.
    """
    session.require_context()
    if session.paths is None:  # pragma: no cover - the two are set together
        raise SessionError(
            "context.missing",
            f'Session "{session.id}" has no context directory on this server. Send the '
            "base context again.",
            session_id=session.id,
        )
    return session.paths


def _removals(command: Command, key: str = "remove") -> tuple[str, ...]:
    """The ``remove`` list of an extension, validated as context paths.

    A malformed removal path is answered ``context.unsafe-entry``, the
    same code an archive entry of the same shape gets. That is one
    meaning with one code rather than two: the refusal is "this names
    something outside the context", and whether the client asked for it
    to appear or to disappear does not change what is wrong with it.
    ``context.yaml`` is the exception, and it is
    ``context.pins-immutable`` in both directions — deleting the pin
    file is touching it in the most final way there is.
    """
    raw = command.payload.get(key)
    if raw is None:
        return ()
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        raise ProtocolError(f'"{command.type}" wants "{key}" as a list of context paths.')
    for path in raw:
        check_file_target(check_path_shape(path), allow_context_file=False)
    return tuple(dict.fromkeys(raw))


async def extend_context(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``extend-context`` — per-layer replace semantics, repeatable.

    Payload (both halves optional, at least one required)::

        {"session_id": "s-…",
         "archive": {"size": 812, "sha256": "<64 hex digits>"},   # add / overwrite
         "remove": ["patches/zephyr/0002-old.patch"]}             # remove

    ADR 0019 §2 gives the verb "per-layer **replace semantics** (add /
    overwrite / remove)" and names no wire shape for any of the three;
    E42 settles it as the same archive mechanics as ``send-context``
    plus a list of paths, both allowed in one call. An extension that
    asks for neither is refused rather than answered "nothing changed":
    a client that sent it meant something.

    **Order within one call is removals first, then the archive**, so a
    path named in both ends up as the archive's version. The archive is
    the positive statement of what the context should contain, and a
    client that says "remove X" and "here is X" means the new X. No
    document settles it; this is the determination.

    **It MUST NOT touch ``context.yaml``** — the pins the session was
    admitted on, and "changing them is a new session, not an extension"
    (ADR 0018's amendment, contract §3.2). ADR 0018 requires a typed
    error and names no code, so ``context.pins-immutable`` was added to
    the registry for it: deliberately distinct from
    ``context.unsafe-entry``, because a ``context.yaml`` in the archive
    is a perfectly well-formed entry aimed at a forbidden target, and
    telling a client its path was unsafe would send it looking for the
    wrong mistake.

    **Nothing is applied until everything is accepted.** The archive is
    unpacked into a staging directory beside the context and moved in
    only once every cap, every path and the patch policy have passed, so
    a refused extension leaves the accepted context byte for byte as it
    was. Atomicity is settled nowhere, and the alternative — a
    half-applied extension on a context whose ID is about to be computed
    — is not a state worth being able to reach. Staging alone did not
    reach that far: the merge itself could fail partway, so the whole
    merge is now checked against the context before the first removal
    runs (:func:`_check_merge`).

    After the change the patch-layer set is re-derived **from the files
    actually present** and policy is re-run, which is ADR 0019 §2's own
    wording. There is no cost class to re-run with it: v1.0 has none.

    Removing a path that is not in the context is not an error. The
    client asked for a state and that state holds — the rule
    ``close-session`` already follows — and the answer says how many of
    the named paths existed, so a typo is still visible.
    """
    session = state.sessions.require(command.require_str("session_id"))
    session.require_workable()
    session.require_writable_context()
    paths = _require_paths(session)
    removals = _removals(command)
    has_archive = command.payload.get("archive") is not None
    if not has_archive and not removals:
        raise ProtocolError(
            '"extend-context" needs an "archive" to add or overwrite files, a "remove" '
            "list of context paths, or both. An extension that changes nothing is a "
            "command that meant something else."
        )

    with _context_work(session):
        paths.clear_staging()
        try:
            if has_archive:
                archive = await _receive_archive(state, connection, command, session, paths.spool)
                _require_still_ours(session, paths)
                _unpack_into(state, session, archive, paths.staging, allow_context_file=False)
                paths.spool.unlink(missing_ok=True)
            _check_merge(paths.staging, paths.context, removals)
            removed = _apply_removals(session, paths.context, removals)
            _merge_staging(session, paths.staging, paths.context)
            recheck_patch_policy(paths.context, frozenset(state.config.allowed_patch_layers))
        except BaseException:
            # The staged files were charged to the disk meter as they
            # were unpacked and are about to be thrown away, so the
            # meter is re-read off the context rather than adjusted:
            # subtracting what was staged would be wrong the moment a
            # removal had already run.
            session.ledger.disk_bytes = _measure(paths.context)
            raise
        finally:
            paths.clear_staging()
            paths.spool.unlink(missing_ok=True)

    return {
        "session_id": session.id,
        "context": {"state": session.context_state, "format": session.context_format},
        "files": count_context_files(paths.context),
        "removed": removed,
    }


def _measure(context: Path) -> int:
    """The bytes the context actually holds, for the disk meter.

    Measuring beats bookkeeping on the failure path: the meter moves in
    three places — an unpack charges, a removal credits, an overwrite
    does both — so after a refusal there is no single amount to undo,
    and the directory is right there to be asked.
    """
    return sum(path.stat().st_size for path in context.rglob("*") if path.is_file())


def _apply_removals(session: Session, context: Path, removals: tuple[str, ...]) -> int:
    """Delete the named files, returning how many actually existed.

    The disk meter falls with them: a quota that only ever counted up
    would turn ``extend-context``'s remove half into a way of spending a
    session's budget without keeping anything.
    """
    removed = 0
    for path in removals:
        target = context / path
        if not target.is_file():
            continue
        session.ledger.disk_bytes = max(0, session.ledger.disk_bytes - target.stat().st_size)
        target.unlink()
        removed += 1
    _prune_empty_directories(context)
    return removed


def _prune_empty_directories(context: Path) -> None:
    """Drop directories a removal emptied.

    Cosmetic for the ID — the integrity list holds files and an empty
    ``patches/zephyr/`` contributes nothing to it — and not cosmetic for
    the reader: a context whose shape still says it patches Zephyr after
    the last Zephyr patch was removed describes a build that no longer
    exists.
    """
    for directory in sorted(context.rglob("*"), key=lambda path: len(path.parts), reverse=True):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()


def _staged_paths(staging: Path) -> tuple[str, ...]:
    """The context-relative paths an extension's archive would place."""
    if not staging.is_dir():
        return ()
    return tuple(
        path.relative_to(staging).as_posix()
        for path in sorted(staging.rglob("*"))
        if path.is_file()
    )


def _check_merge(staging: Path, context: Path, removals: tuple[str, ...]) -> None:
    """Refuse the whole extension **before** any of it is applied.

    ``extend-context``'s own promise is that "nothing is applied until
    everything is accepted", and it was not kept: the removals ran first
    and the staged files were moved in one by one, so a staged path whose
    parent was an existing regular file raised out of the middle of the
    merge and left a context with the removals done, some files moved in
    and the rest not — answered as an untyped ``internal_error``, on
    input a client fully controls. A half-applied extension on a context
    whose ID is about to be computed is not a state worth being able to
    reach, so the question is asked while the answer is still free.

    What is checked is the type collision, in both directions and
    including ancestors: a staged file may not land where the context
    holds a directory, and none of its parent directories may be an
    existing file. The removals are part of the picture rather than a
    step before it — a removal is the legitimate way to make room for a
    file at a path that used to be one — so a path this call is about to
    delete does not block anything. Directories are never removed by a
    removal, so no exception runs the other way.
    """
    doomed = {path for path in removals if (context / path).is_file()}
    for path in _staged_paths(staging):
        for parent in ancestors(path):
            if parent in doomed:
                continue
            existing = context / parent
            if existing.exists() and not existing.is_dir():
                raise type_conflict(path, conflict=parent, where="context")
        target = context / path
        if target.exists() and not target.is_file():
            below = sorted(
                child.relative_to(context).as_posix()
                for child in target.rglob("*")
                if child.is_file()
            )
            raise type_conflict(path, conflict=below[0] if below else path, where="context")


def _merge_staging(session: Session, staging: Path, context: Path) -> None:
    """Move the staged files into the context, overwriting by path.

    A rename rather than a copy: staging is a sibling of the context
    inside the same session directory, so this is one filesystem and the
    move is atomic per file. Overwriting by path is what "replace
    semantics" means — the extension names files, and a file it names
    replaces the one that was there.

    :func:`os.replace` rather than :func:`shutil.move`, which is not a
    detail. ``shutil.move`` documents that an **existing directory** as
    the destination means "move the source *inside* it", so an extension
    naming ``model/a`` while the context held ``model/a/b.json`` used to
    land the client's bytes at ``model/a/a`` — a path it never named,
    answered ``result``, and visible only as an unexplained mismatch when
    the client compared the context ID it computed against the one the
    lock returned. ``os.replace`` never re-parents; it raises, and
    :func:`_check_merge` has already refused the case typed before this
    function runs.

    The overwritten file's bytes are given back to the disk meter. They
    were charged when the staged file was unpacked, so leaving the old
    ones on the meter would make overwriting one file twenty times cost
    twenty files' worth of quota while the context never grew.
    """
    for path in _staged_paths(staging):
        source = staging / path
        target = context / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_file():
            session.ledger.disk_bytes = max(0, session.ledger.disk_bytes - target.stat().st_size)
        os.replace(source, target)


async def lock_context(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``lock-context`` — freeze the context. **Guarded here, stubbed behind.**

    The verb ADR 0019's amendment adds to the set, append-only as its
    Consequences require, to say where the session's lifetime and the
    context's part company. The alternative was an implicit freeze on
    "the first writing command", rejected structurally: it needs an
    enumerated list of writing commands kept in sync with a verb set
    that is append-only by decision, and a third-party command could not
    know which side of the line it falls on.

    The explicit verb buys three things. The context ID gets an
    **observable moment**, at which both sides compare values they
    computed independently. It makes ``verify`` meaningful, because
    there is a stable ``files`` list to check against. And it yields
    clean typed errors instead of a command that quietly means something
    different depending on what ran before it.

    It does exactly four things and unlocks a fifth: freeze the context,
    write ``manifest.yaml``, compute the context ID, return it — and
    from here ``verify`` and ``build`` are permitted.

    A second ``lock-context`` is ``context.locked``, because the lock is
    one-way: adding a patch after a ``verify`` is a new session, not an
    extension. A ``lock-context`` on a session that never received a
    base context is ``context.missing``.

    **The wire shape is minimal by explicit product-owner choice**
    against the richer alternative (E37, ADR 0019's second amendment):
    the request carries ``session_id`` and nothing else, the response
    carries the context ID and nothing else. The comparison ADR 0019
    requires — "both sides compare values they computed independently" —
    therefore happens **on the client**: the workbench computes the ID
    from the bytes it sent, compares it against this answer, and closes
    the session on a disagreement. The consequence is stated here so
    nobody rediscovers it as a gap: this server never sees the client's
    value, so it can never raise that mismatch, and holding the
    workbench to its comparison duty is a requirement on the session
    client rather than on the protocol.

    An empty context may be locked. It has a well-defined ID, and the
    things a ``build`` needs beyond existence — ``keys/signing.pub``
    above all — are checked by ``build``, which is where the contract
    scopes them, not by the lock.

    The context state flips to :data:`CONTEXT_LOCKED` only once
    ``manifest.yaml`` is durably on disk. The lock is one-way and it is
    what unlocks ``verify`` and ``build``, so a session that answered a
    context ID and then lost the manifest to a crash would be a session
    that can neither build nor be extended.

    **The freeze takes the same in-flight guard the uploads take**
    (:func:`_context_work`), and that is the one thing standing between
    this verb and a context ID that means nothing. Every command runs as
    its own task and the reader keeps taking TEXT frames while an
    announced upload is still arriving, so a ``lock-context`` sent
    between an ``extend-context``'s announcement and its bytes used to
    freeze *around* it: the manifest listed the files present at that
    instant, the extension then applied to the locked context, and the
    session ended up holding files that are in neither ``manifest.yaml``
    nor the ID already answered. ``require_writable_context`` cannot see
    that — it reads the context's state, and the state of a context that
    is being written to is still ``unlocked``. What is in flight is a
    different question, and the guard is the only thing that answers it.
    Re-checking after the await would not do on its own either: the
    extension must not begin applying to a context that was locked while
    it waited.
    """
    session = state.sessions.require(command.require_str("session_id"))
    session.require_workable()
    session.require_writable_context()
    with _context_work(session):
        paths = _require_paths(session)
        if session.pins is None or session.context_yaml_sha256 is None:  # pragma: no cover
            raise SessionError(
                "context.missing",
                f'Session "{session.id}" holds no pins to freeze against.',
                session_id=session.id,
            )
        identity = freeze_context(
            paths, session.pins, context_yaml_sha256=session.context_yaml_sha256
        )
        session.context_state = CONTEXT_LOCKED
    return {"context_id": identity}


async def verify(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``verify`` — check the effective context against the lock. **Stub.**

    A working command, so it runs **only from the lock onwards** and
    answers ``context.not-locked`` before it. That gate repairs the verb
    rather than restricting it: with a manifest frozen at admission and
    mid-session extension allowed, every added file was reported
    "present but not in the integrity list" and the check returned
    ``ok == False`` by construction. ``lock-context`` gives the
    integrity list a defined moment — after the last extension, before
    the first working action — which is what leaves something to check
    against.

    Optional even when real: the fast path skips it. It applies no
    patches and touches no source tree (contract §7.3).
    """
    session = state.sessions.require(command.require_str("session_id"))
    session.require_workable()
    session.require_locked_context()
    raise _not_implemented("verify", session)


async def build(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``build [mode]`` — clean or incremental. **Stub.**

    The other working command, and the other half of "only from here":
    before the lock it answers ``context.not-locked``, which is also the
    structural reason the verb set could not stay at nine — a client
    that never locks the context can never reach ``build``.

    When real: every invocation gets a server-assigned invocation id,
    outputs land in ``/out/<invocation-id>/``, and the result names the
    effective context id actually built, so artifacts stay attributable.
    That id is what ``get-artifact`` and ``cancel`` address.
    """
    session = state.sessions.require(command.require_str("session_id"))
    session.require_workable()
    session.require_locked_context()
    raise _not_implemented("build", session)


async def cancel(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``cancel(invocation id)`` — abort one invocation. **Seam. Stub.**

    The second verb of ADR 0019's amendment. It aborts the running
    invocation, and **the session and its warm container survive** —
    that is the whole promise, and it is why this handler neither closes
    the session nor touches the context state.

    It is a necessity rather than a convenience, for one mechanical
    reason: **killing a ``docker exec`` client does not stop the process
    inside the container.** A local backend that merely drops the exec
    connection leaves the compile running and the session's resources
    held. At the protocol level it is the deliberate counterpart to
    ``attach-session``: a running build continues detached across a lost
    connection, and the idle timeout counts absent *commands* rather
    than absent connections — so a closed socket can never mean "stop",
    and cancellation has to be something a client *says*.

    The id it addresses is the **server-assigned** invocation id that
    ``build`` hands out. ADR 0019 names the operand and no document
    fixes the payload's field name; ``invocation_id`` is the spelling
    this package already uses for the same value at ``get-artifact``.

    The wire shape is the second amendment's (E38): the answer means
    "the stop signal is set", never "the invocation has stopped" — the
    actual end travels on the invocation's event stream, and its result
    document carries ``status: "cancelled"``. Three answers, one each:

    * an id the session does not know is ``invocation.unknown`` — the
      one wrong answer this verb could give is "cancelled" for an
      invocation that was never running;
    * an invocation that already finished (or was already cancelled and
      completed as such) is ``already_finished: true`` and is **not** an
      error, because a cancel racing a natural completion is legitimate
      and both parties behaved correctly;
    * a running one is marked :data:`INVOCATION_CANCELLING` and
      acknowledged — idempotently, so the second cancel of a race gets
      the same answer as the first.

    It is deliberately not gated on the lock and not gated on poison:
    only working commands produce invocations, and a poisoned session
    may still have an invocation worth stopping. The sentinel file the
    acknowledgement promises is :func:`_signal_cancellation`'s, which
    the container backend fills in.
    """
    session = state.sessions.require(command.require_str("session_id"))
    invocation_id = command.require_str("invocation_id")
    found = session.invocations.get(invocation_id)
    if found is None:
        raise SessionError(
            "invocation.unknown",
            f'Session "{session.id}" has no invocation "{invocation_id}".',
            session_id=session.id,
            invocation_id=invocation_id,
            known=sorted(session.invocations),
        )
    if found == INVOCATION_FINISHED:
        return {
            "session_id": session.id,
            "invocation_id": invocation_id,
            "cancelled": False,
            "already_finished": True,
        }
    session.invocations[invocation_id] = INVOCATION_CANCELLING
    _signal_cancellation(session, invocation_id)
    return {
        "session_id": session.id,
        "invocation_id": invocation_id,
        "cancelled": True,
        "already_finished": False,
    }


async def get_artifact(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``get-artifact(invocation id, path)`` — streamed, hash-verified. **Stub.**

    **Inside the session and nowhere else.** The per-session directory —
    the context and every artifact in it — is deleted at
    ``close-session``, so download happens after the build and before
    closing. ADR 0019's amendment removed decision 2's "and for a
    bounded grace period after close" together with an undefined bound:
    nothing said how long, while the directory it kept alive holds a
    device's Matter commissioning credentials.

    Like ``cancel``, it is deliberately not gated on the lock. The flow
    diagram lists it after ``verify``/``build``, but only those two
    carry the "only from here" qualification, and an invocation id can
    only exist because a build produced it. The refusal for an unknown
    invocation id or an unknown path is named nowhere, so this stub does
    not invent one.
    """
    session = state.sessions.require(command.require_str("session_id"))
    raise _not_implemented("get-artifact", session)


async def attach_session(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``attach-session`` — connection loss is not abandonment.

    Answers the session record and its lease, which is the real half:
    a reconnecting client learns its session survived, and the record
    says where the context stands, which is what tells the client
    whether it still has to lock. Permitted in **any** context state —
    it is the read-only reconnection verb, and no document restricts it
    to one side of the lock. The buffered event replay (server-side
    sequence numbers, resume from an offset) is future work and lands
    with the streams it would replay.
    """
    session = state.sessions.require(command.require_str("session_id"))
    return {"session": session.to_dict(), "lease": session.lease_dict()}


async def close_session(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``close-session`` — release the session (and, later, its container).

    It reaps the container and deletes the per-session directory with
    the context and every artifact in it, which is why ``get-artifact``
    has to run before it. Permitted in any context state; the lock does
    not gate the way out.

    Whether it must first cancel a still-running invocation, whether the
    client gets a result for that invocation, and whether closing a busy
    session is refused at all are **not settled** by any document. This
    server closes the record either way, and the question lands with the
    container backend that would have something to reap.
    """
    session = state.sessions.close(command.require_str("session_id"))
    return {"session": session.to_dict()}


#: The verb table. The ``/ws`` command table is derived from this one
#: (``ws.COMMANDS = dict(SESSION_VERBS)``), so an entry here is the
#: whole registration — there is no second list to keep in step.
#: Hyphenated names as in the concept.
#:
#: **Eleven**, which is the complete set of dashboard ADR 0012 decision
#: 3 (amended 2026-08-09 from ADR 0019), in that decision's own order.
#: ``lock-context`` and ``cancel`` were the two missing, and neither is
#: optional: without ``lock-context`` a client can never reach
#: ``build``, and without ``cancel`` a closed socket would be the only
#: stop signal a client had — which ADR 0019 says is no stop signal at
#: all, because killing a ``docker exec`` client does not stop the
#: process inside the container.
#: The verbs whose body arrives as BINARY frames after the JSON that
#: announced it (E41). The transport needs this and cannot derive it: a
#: binary frame carries no id, so the reader has to know **before** it
#: reads on that the command it just spawned is about to claim the next
#: frames — see :meth:`~mcuhome_buildserver.ws.Connection.await_announcement`.
#: The set is here rather than in the transport because whether a verb
#: takes an archive is a property of the verb.
UPLOAD_VERBS = frozenset({"send-context", "extend-context"})

SESSION_VERBS = {
    "capabilities": capabilities,
    "open-session": open_session,
    "send-context": send_context,
    "extend-context": extend_context,
    "lock-context": lock_context,
    "verify": verify,
    "build": build,
    "cancel": cancel,
    "get-artifact": get_artifact,
    "attach-session": attach_session,
    "close-session": close_session,
}
