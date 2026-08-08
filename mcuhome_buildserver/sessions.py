# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Session protocol v2 — the session registry and one handler per verb.

The remote-build architecture replaces the one-shot job protocol with a
**session model**: one session = one ephemeral builder container = one
effective build context. The same verb set has a local backend (the lib
drives the container runtime directly) and this remote one, which adds
auth, policy and scheduling on top of the identical verbs.

**This is the protocol skeleton.** What is real here is the protocol
surface itself: the verb set, admission with version negotiation at
``open-session``, the lease bookkeeping, the per-layer patch policy
read from configuration, and the typed error envelope of
:mod:`mcuhome_buildserver.errors`. What is deliberately not here yet —
the container backend, context upload and extraction, the overlay patch
views, scheduling and metering — answers with a typed
``session.not-implemented`` instead of a guess, so a client sees a
protocol that is honest about its state rather than one that almost
works.

Admission and negotiation live at ``open-session``, not in ``verify``:
a version mismatch is a typed rejection at the door, never a downstream
failure. Container materialization is lazy by design — opening a
session reserves nothing but a record and a lease, and the backend may
defer creating a container until the first command that needs one.
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
#: the one-shot job protocol of ADR 0006 is version 1; the two share the
#: frame envelope and one ``/ws`` endpoint during the transition.
SESSION_PROTOCOL_VERSION = 2

#: The context manifest format range this server accepts (`context: N`
#: in manifest.yaml). Two constants for the same reason as the model
#: version range: accepting an older format later is a change here, not
#: a protocol change.
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

#: Concurrent open sessions. One bearer token is one user on this
#: server, so this is the per-user concurrent-session quota in its
#: simplest form.
DEFAULT_MAX_OPEN_SESSIONS = 4

STATE_OPEN = "open"
STATE_CLOSED = "closed"


@dataclass
class Session:
    """One admitted session: its identity, profile and lease."""

    id: str
    profile: str
    created_at: float
    expires_at: float
    idle_timeout: float
    state: str = STATE_OPEN
    #: The manifest header the session was admitted on. Immutable for
    #: the session's lifetime — a changed manifest is a new session.
    manifest_header: dict[str, Any] = field(default_factory=dict)
    last_command_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "profile": self.profile,
            "state": self.state,
            "created_at": round(self.created_at, 3),
        }

    def lease_dict(self) -> dict[str, Any]:
        return {
            "ttl_seconds": round(self.expires_at - self.created_at, 3),
            "idle_timeout_seconds": self.idle_timeout,
            "expires_at": round(self.expires_at, 3),
        }


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
        manifest_header: dict[str, Any],
    ) -> Session:
        """Admission. Every refusal is typed, at the door (concept §4)."""
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
                f"This server reads context manifest formats {CONTEXT_FORMAT_MIN}-"
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
            manifest_header=dict(manifest_header),
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
        client asked for a state and that state holds."""
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionError(
                "session.unknown",
                f'This server has no session called "{session_id}".',
                session_id=session_id,
            )
        session.state = STATE_CLOSED
        return session


# --------------------------------------------------------------------------
# The verbs
# --------------------------------------------------------------------------


def capabilities_payload(state: Any) -> dict[str, Any]:
    """What the ``capabilities`` verb answers — pre-session, cheap.

    The lib consults this during constraint resolution and fails fast
    ("this server has no builder for zephyr-4.4.0-r1") instead of dying
    mid-session. Placeholders, marked as such until their backends land:

    ``builders``
        will list the available builder images as
        ``{"tag", "digest", "labels"}`` entries once the container
        backend exists; empty until then, and an empty list is the
        truthful answer — this server can admit sessions and build
        nothing.
    ``quota.work``
        work metering (CPU-seconds, invocations against budgets) is
        future; the session quota half is real today.
    """
    config = state.config
    allowed = frozenset(config.allowed_patch_layers)
    return {
        "protocol": {
            "version": SESSION_PROTOCOL_VERSION,
            "context_format": {"min": CONTEXT_FORMAT_MIN, "max": CONTEXT_FORMAT_MAX},
            "profiles": list(PROFILES),
        },
        "builders": [],
        # The server's builder config IS the policy; unlisted layers are
        # denied by default (concept §6). Advertised per layer so the
        # lib refuses a patched context before uploading it.
        "patch_policy": {layer: {"allow": layer in allowed} for layer in PATCH_LAYERS},
        "quota": {
            "sessions": {
                "open": state.sessions.open_count,
                "max_open": state.sessions.max_open,
            },
            "work": None,
        },
    }


async def capabilities(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``capabilities`` — see :func:`capabilities_payload`."""
    return capabilities_payload(state)


async def open_session(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``open-session`` — policy check and admission.

    Payload::

        {"profile": "oneshot",            # oneshot | dev | test
         "protocol_version": 2,           # required; mismatch is typed
         "context_format": 1,             # manifest format the context uses
         "manifest": {...header...}}      # advisory at admission

    The response **carries the negotiation** — discovery lives here, not
    in ``verify``::

        {"session": {"id", "profile", "state", "created_at"},
         "lease": {"ttl_seconds", "idle_timeout_seconds", "expires_at"},
         "negotiated": {"protocol_version", "context_format",
                        "container", "cost_class"}}

    ``negotiated.container`` is ``null`` until the container backend
    exists (it will carry the serving container's contract version and
    command set; materialization is lazy either way), and
    ``negotiated.cost_class`` is a placeholder for resource-weighted
    scheduling. The manifest header is stored and immutable for the
    session's lifetime; patch *policy* is enforced against the files
    actually present, so it runs at ``send-context``/``extend-context``
    time, not here.
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
        manifest_header=command.optional_dict("manifest"),
    )
    return {
        "session": session.to_dict(),
        "lease": session.lease_dict(),
        "negotiated": {
            "protocol_version": SESSION_PROTOCOL_VERSION,
            "context_format": {"min": CONTEXT_FORMAT_MIN, "max": CONTEXT_FORMAT_MAX},
            "container": None,
            "cost_class": "default",
        },
    }


def _not_implemented(verb: str, session: Session) -> SessionError:
    """The typed answer of every verb whose backend is future work."""
    return SessionError(
        "session.not-implemented",
        f'"{verb}" is part of session protocol {SESSION_PROTOCOL_VERSION} and its '
        "server logic lands with the container backend. The session itself is real: "
        "it was admitted, it holds its lease, and close-session releases it.",
        verb=verb,
        session_id=session.id,
    )


async def send_context(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``send-context`` — upload the base context. **Stub.**

    The transport (archive upload with streaming ingress caps, safe
    extraction, server-side re-hashing) is future work; the session
    handshake in front of it is real.
    """
    session = state.sessions.require(command.require_str("session_id"))
    raise _not_implemented("send-context", session)


async def extend_context(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``extend-context`` — per-layer replace semantics. **Stub.**

    When real, every extension re-derives the patch-layer set from the
    files actually present and re-runs policy and cost class. The
    manifest itself is immutable for the session's lifetime
    (``session.manifest-immutable``).
    """
    session = state.sessions.require(command.require_str("session_id"))
    raise _not_implemented("extend-context", session)


async def verify(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``verify`` — deep in-session pin assertion. **Stub.**

    Optional even when real: discovery already happened at
    ``open-session``, and the fast path skips this.
    """
    session = state.sessions.require(command.require_str("session_id"))
    raise _not_implemented("verify", session)


async def build(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``build [mode]`` — clean or incremental. **Stub.**

    When real: every invocation gets a server-assigned invocation id,
    outputs land in ``/out/<invocation-id>/``, and the result names the
    effective context id actually built.
    """
    session = state.sessions.require(command.require_str("session_id"))
    raise _not_implemented("build", session)


async def get_artifact(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``get-artifact`` — streamed, hash-verified. **Stub.**

    When real, artifacts are fetchable throughout the session and for a
    bounded grace period after close.
    """
    session = state.sessions.require(command.require_str("session_id"))
    raise _not_implemented("get-artifact", session)


async def attach_session(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``attach-session`` — connection loss is not abandonment.

    Answers the session record and its lease, which is the real half:
    a reconnecting client learns its session survived. The buffered
    event replay (server-side sequence numbers, resume from an offset)
    is future work and lands with the streams it would replay.
    """
    session = state.sessions.require(command.require_str("session_id"))
    return {"session": session.to_dict(), "lease": session.lease_dict()}


async def close_session(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``close-session`` — release the session (and, later, its container)."""
    session = state.sessions.close(command.require_str("session_id"))
    return {"session": session.to_dict()}


#: The verb table, merged into the ``/ws`` command table. Hyphenated
#: names as in the concept; the v1 job commands keep their underscores.
SESSION_VERBS = {
    "capabilities": capabilities,
    "open-session": open_session,
    "send-context": send_context,
    "extend-context": extend_context,
    "verify": verify,
    "build": build,
    "get-artifact": get_artifact,
    "attach-session": attach_session,
    "close-session": close_session,
}
