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

**This is the protocol skeleton.** What is real here is the protocol
surface itself: the verb set, admission with version negotiation at
``open-session``, the lease bookkeeping, the context state machine and
its typed refusals, the per-layer patch policy read from configuration,
and the typed error envelope of :mod:`mcuhome_buildserver.errors`. What
is deliberately not here yet — the container backend, context upload and
extraction, the overlay patch views, invocations and scheduling —
answers with a typed ``session.not-implemented`` instead of a guess, so
a client sees a protocol that is honest about its state rather than one
that almost works.

One stub is a **seam** rather than a bare refusal:
:func:`_freeze_context` is the body of ``lock-context``, and its
docstring says what replaces it and why it waits for the wiring onto
``mcuhome-model``. ``cancel`` is real since the second amendment settled
its wire shape (E38) — bookkeeping, acknowledgement, the
``already_finished`` answer — and only the sentinel file the
acknowledgement promises stays with the container backend
(:func:`_signal_cancellation`).

Admission and negotiation live at ``open-session``, not in ``verify``:
a version mismatch is a typed rejection at the door, never a downstream
failure. Container materialization is lazy by design — opening a
session reserves nothing but a record and a lease, and the backend may
defer creating a container until the first command that needs one,
which is also why the serving container's own contract version is
answered by ``send-context`` rather than here.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from mcuhome_buildserver.errors import SessionError
from mcuhome_buildserver.protocol import Command

__all__ = [
    "CONTEXT_FORMAT_MAX",
    "CONTEXT_FORMAT_MIN",
    "CONTEXT_LOCKED",
    "CONTEXT_NONE",
    "CONTEXT_UNLOCKED",
    "DEFAULT_IDLE_TIMEOUT",
    "DEFAULT_MAX_OPEN_SESSIONS",
    "DEFAULT_SESSION_TTL",
    "PATCH_LAYERS",
    "PROFILES",
    "SESSION_PROTOCOL_VERSION",
    "SESSION_VERBS",
    "Session",
    "SessionManager",
    "capabilities_payload",
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
#: from the files actually present, never from a declared list. Layers
#: not in this tuple are denied unconditionally.
PATCH_LAYERS = ("sdk", "zephyr", "chip")

#: Hard TTL: a session older than this is reaped no matter what it is
#: doing. Generous relative to one cold build (~14 min on a slow
#: machine), small relative to a forgotten one.
DEFAULT_SESSION_TTL = 3600.0

#: Idle timeout: absent *commands*, not absent connections — a client
#: may disconnect and attach-session back without losing the session.
#: (Recorded in the lease today; enforcement by a reaper task lands
#: with the container backend, which is what holds the resources worth
#: reaping.)
DEFAULT_IDLE_TIMEOUT = 600.0

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
        return sum(1 for session in self._sessions.values() if session.state == STATE_OPEN)

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
        if session.state == STATE_OPEN and time.time() > session.expires_at:
            session.state = STATE_CLOSED
            raise SessionError(
                "session.expired",
                f'Session "{session_id}" outlived its lease and was reaped.',
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
        "patch_policy": {layer: {"allow": layer in allowed} for layer in PATCH_LAYERS},
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
    session = state.sessions.open(
        profile=command.optional_str("profile", "oneshot") or "oneshot",
        protocol_version=protocol_version,
        context_format=command.optional_int("context_format", CONTEXT_FORMAT_MAX)
        or CONTEXT_FORMAT_MAX,
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


def _freeze_context(session: Session) -> SessionError:
    """The freeze at the heart of ``lock-context``. **Seam. Stub.**

    Two of the four things the verb does are one computation, and that
    computation does not belong to this repository. ``manifest.yaml``
    repeats the pins of ``context.yaml`` and adds the ``files``
    integrity list and the context ``id``; the ID is the SHA-256 over
    the RFC 8785 canonical JSON of exactly four inputs, and that rule is
    **locked for context format version 1 and can never change**
    (ADR 0018 §6, build-container contract §3.3). ``lock-context``
    changed *when* and *from what* the ID is derived; it did not change
    the rule.

    Its whole purpose is that independent parties compute the same
    value, which is why ADR 0020 decision 4 puts it in ``mcuhome-model``
    and has this server consume that package and nothing else. A second
    implementation in a second repository, with no conformance vectors
    between them, is two chances to disagree about a value whose only
    job is to be identical on both sides — and a disagreement that
    surfaces as a rejected upload or a misattributed artifact rather
    than as a test failure. So this side does not re-implement the rule
    to ship the verb sooner. ``mcuhome-model`` is not a distribution yet
    (see the dependency note in ``pyproject.toml``), and until it is,
    this is a typed refusal instead of a guess.

    **What replaces this function**, once there is a context on disk and
    a model package to hash it with: recompute every file hash from the
    received bytes; verify the three declared pins no file hash can
    measure — the container digest against the image actually pulled,
    the SDK hash against the package bytes actually fetched, the board
    against the pins the session was admitted on; build the ``files``
    list; compute the ID through ``mcuhome-model``; write
    ``manifest.yaml`` beside ``context.yaml`` (written by this side,
    never an extraction target); set the session's
    :attr:`Session.context_state` to :data:`CONTEXT_LOCKED`; answer the
    ID. A recomputed value that disagrees with the received bytes is
    ``context.integrity-mismatch``.

    **The wire shape is settled** (E37, ADR 0019's second amendment),
    minimal by explicit product-owner choice against the richer
    alternative: the request carries ``session_id`` and nothing else,
    the response carries the context ID and nothing else. The comparison
    ADR 0019 requires happens **on the client** — the workbench computes
    the ID from the bytes it sent, compares against the answer, and
    closes the session on a disagreement. This server never sees the
    client's value and therefore never raises that mismatch;
    ``context.integrity-mismatch`` remains what the recomputation
    against *received bytes* raises, which is a different check and
    entirely this side's. What the stub still waits for is only the
    computation itself, above.
    """
    return SessionError(
        "session.not-implemented",
        '"lock-context" reached its freeze. The state machine in front of it is real — '
        "this session has a context and it is not locked — and the freeze itself is not: "
        "writing manifest.yaml and computing the context id belong to mcuhome-model "
        "(ADR 0020 decision 4), which is not a distribution yet. This server will not "
        "re-implement the frozen hash rule of ADR 0018 §6 to answer sooner.",
        verb="lock-context",
        session_id=session.id,
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
    """``send-context`` — upload the base context and its pins. **Stub.**

    The base context carries ``context.yaml``: the context format
    version, the resolved pins — container digest, SDK package sha256,
    target board — and the constraint they were resolved from. When this
    is real, its response answers what the context determines and
    ``open-session`` could not: the serving build container's contract
    version and its command set (ADR 0019's amendment).

    The transport in front of that — archive upload with streaming
    ingress caps, safe extraction, server-side re-hashing — is future
    work; the session handshake and the context state machine around it
    are real. A context may not arrive after the lock, because the lock
    closes the context to writes entirely, so this is a writing command
    and ``context.locked`` refuses it.
    """
    session = state.sessions.require(command.require_str("session_id"))
    session.require_workable()
    session.require_writable_context()
    raise _not_implemented("send-context", session)


async def extend_context(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``extend-context`` — per-layer replace semantics. **Stub.**

    Repeatable, and bounded to the phase before the lock. When real,
    every extension re-derives the patch-layer set from the files
    *actually present* and re-runs policy — patch semantics live
    entirely in the paths (ADR 0018 decision 2), so there is no declared
    patch list that could disagree. There is no cost class to re-run
    with it: v1.0 has none.

    **It MUST NOT touch ``context.yaml``**, which carries the pins the
    session was admitted on; changing them is a new session, not an
    extension (ADR 0018's amendment). That file is what "immutable for
    the session" means now — the rule it replaced named
    ``manifest.yaml``, which does not exist yet at this point in the
    flow. ADR 0018 says an attempt is a typed error but names no code,
    so this stub does not invent one. After the lock the whole context
    is closed to writes and the answer is ``context.locked``.
    """
    session = state.sessions.require(command.require_str("session_id"))
    session.require_workable()
    session.require_writable_context()
    session.require_context()
    raise _not_implemented("extend-context", session)


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

    What is real today is the state machine in front of the freeze. A
    second ``lock-context`` is ``context.locked``, because the lock is
    one-way: adding a patch after a ``verify`` is a new session, not an
    extension. A ``lock-context`` on a session that never received a
    base context is ``context.missing``. The freeze itself is
    :func:`_freeze_context`, which says why it cannot be written in this
    repository yet.
    """
    session = state.sessions.require(command.require_str("session_id"))
    session.require_workable()
    session.require_writable_context()
    session.require_context()
    raise _freeze_context(session)


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
