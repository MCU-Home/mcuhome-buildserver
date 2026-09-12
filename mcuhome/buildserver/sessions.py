# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Session protocol v2 — the session registry and one handler per verb.

The remote-build architecture replaced the one-shot job protocol with a
**session model**: one session = one ephemeral build environment = one
effective build context. The same verb set has a local backend (the
workbench drives the container runtime directly) and this remote one,
which adds auth, policy and scheduling on top of the identical verbs.

These verbs are the whole vocabulary of the ``/ws`` endpoint. The job
protocol they replaced was dismantled rather than migrated; what
survived it is the transport underneath — the frame envelope, the
connection handling and the bearer token.

**The context has a lifetime of its own inside the session, and
``lock-context`` is where the two part company.** A context arrives, is
extended any number of times, and
is then frozen by an explicit verb; the freeze writes ``manifest.yaml``,
computes the context ID and unlocks the working commands. That order is
this protocol's own flow, and it is what the state machine on
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
the whitelist — lives in :mod:`mcuhome.buildserver.ingress`, and the
directory, the pin document and the freeze in
:mod:`mcuhome.buildserver.contextstore`.

**The working path is real too, and it lives one module over.**
``verify`` and ``build`` re-measure the locked context, hand it to
:mod:`mcuhome.buildserver.backend` and answer an invocation id
immediately; the completion arrives as an ``invocation.verdict`` event
with the status and the artifact list, named on its own so that it is
never confused with the program's own ``invocation.finished`` event,
the program's own events are relayed verbatim
and its raw log travels as its own frame kind.
``get-artifact`` answers a ``tar.zst`` announced in its result frame and
streamed as BINARY frames behind it, and ``attach-session``
replays an invocation's events from a sequence number the client states
— out of the NDJSON file on disk, which is the replay buffer.

Nothing in the verb set answers ``session.not-implemented`` any more.
The code stays registered, because the registry is append-only and a
future verb will want it; nothing raises it.

Admission and negotiation live at ``open-session``, not in ``verify``:
a version mismatch is a typed rejection at the door, never a downstream
failure. Container materialization is lazy by design — opening a
session reserves nothing but a record and a lease, and the backend may
defer creating a container until the first command that needs one,
which is also why the serving environment's own spec generation is
answered by ``send-context`` rather than here.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import secrets
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcuhome.model.context import CONTEXT_FILE
from mcuhome.model.hashes import sha256_file

from mcuhome.buildserver import __version__, artifacts, events, protocol
from mcuhome.buildserver.contextstore import (
    ContextPins,
    SessionPaths,
    count_context_files,
    freeze_context,
    parse_context_yaml,
    recheck_locked_context,
    recheck_patch_policy,
)
from mcuhome.buildserver.errors import SessionError
from mcuhome.buildserver.ingress import (
    IngressCaps,
    IngressLedger,
    Upload,
    ancestors,
    check_file_target,
    check_path_shape,
    type_conflict,
    unpack,
)
from mcuhome.buildserver.protocol import Command, ProtocolError

logger = logging.getLogger(__name__)

__all__ = [
    "CONTEXT_FORMAT_MAX",
    "CONTEXT_FORMAT_MIN",
    "CONTEXT_LOCKED",
    "CONTEXT_NONE",
    "CONTEXT_UNLOCKED",
    "DEFAULT_IDLE_TIMEOUT",
    "DEFAULT_MAX_OPEN_SESSIONS",
    "DEFAULT_MAX_SEATS",
    "DEFAULT_REAP_INTERVAL",
    "DEFAULT_SEAT_RETRY_MAX_SECONDS",
    "DEFAULT_SEAT_RETRY_SECONDS",
    "DEFAULT_SESSION_TTL",
    "PATCH_LAYERS",
    "PROFILES",
    "SEAT_GRACE",
    "SESSION_PROTOCOL_VERSION",
    "SESSION_VERBS",
    "SHUTDOWN_RELEASE_SECONDS",
    "Seat",
    "SeatQueue",
    "Session",
    "SessionManager",
    "UPLOAD_VERBS",
    "capabilities_payload",
    "is_patch_layer_name",
    "release_every_session",
    "release_pending",
    "release_session",
]

#: Bumped when the *session* protocol changes shape. Version 2 because
#: the one-shot job protocol that came before was version 1. That
#: protocol no longer exists here, but the number is not reclaimed: a
#: client that speaks 1 must be told it is behind, not handed a 2 that
#: means something else.
SESSION_PROTOCOL_VERSION = 2

#: The context format range this server accepts (`context: N` in the
#: context's entry file `context.yaml`). Not "manifest format": the
#: request is split from the record, and the version
#: is declared in the document that travels with the base context —
#: `manifest.yaml` repeats it, but that document is written by this side
#: at `lock-context` and is never an input. Two constants for the same
#: reason as the model version range: accepting an older format later is
#: a change here, not a protocol change.
#:
#: The minimum has always moved with the maximum rather than staying
#: behind, and for the same reason each time: nothing is published, no
#: client writes an older format, and a server that still accepted one
#: would have to carry that format's hashing rule — and the block it
#: hashes — for documents nobody sends. `mcuhome-model` drops the older
#: format outright, so accepting it here is not even possible.
#:
#: Both are 4 since the build environment became a package set: a format-3
#: context pinned one container image by digest, a format-4 context pins
#: the environment's packages, and the context ID is computed over
#: different inputs. A reader of one would get the other wrong, which is
#: precisely when the number moves.
CONTEXT_FORMAT_MIN = 4
CONTEXT_FORMAT_MAX = 4

#: The session profiles. The profile drives admission, TTL, idle
#: timeout and the per-profile resource budget; commands outside the
#: declared profile are rejected typed. (Per-profile budgets are future
#: work — today every profile gets the defaults below.)
PROFILES = ("oneshot", "dev", "test")

#: The patch layers the protocol knows. A patch's layer is its subfolder
#: in the context (``patches/<layer>/``); policy is always re-derived
#: from the files actually present, never from a declared list.
#:
#: **Four**, since 2026-08-09: this server's own patch layers are
#: ``zephyr``, ``sdk``, ``chip`` and ``mcuboot``, and ``mcuboot`` is a
#: layer because every device build is ``west build --sysbuild`` with
#: MCUboot as the second image. It was missing here, which meant an
#: operator could not allow a layer this server otherwise knows.
PATCH_LAYERS = ("sdk", "zephyr", "chip", "mcuboot")

#: Third-party layer names carry an ``x-`` prefix, so that two vendors
#: cannot collide on one name and have a context silently patch the
#: wrong tree. The registry of un-prefixed names is
#: owned by the MCUHome project and is :data:`PATCH_LAYERS`; an ``x-``
#: name is nameable by anyone and, like every other layer, allowed only
#: where an operator listed it.
_X_LAYER = re.compile(r"x-[a-z0-9][a-z0-9._-]*\Z")


def is_patch_layer_name(name: str) -> bool:
    """Whether *name* is a layer name a config may allow at all.

    Nameable is not the same as allowed: this says the string could be a
    layer, while :data:`~mcuhome.buildserver.config.Config.allowed_patch_layers`
    says whether contexts may patch it. Keeping them apart is what lets
    a third-party ``x-`` layer be configured without this server having
    to know what it is.
    """
    return name in PATCH_LAYERS or _X_LAYER.fullmatch(name) is not None


#: Hard TTL: a session older than this is reaped no matter what it is
#: doing. Generous relative to one cold build (~14 min on a slow
#: machine), small relative to a forgotten one.
DEFAULT_SESSION_TTL = 3600.0

#: What a session needs on top of one invocation's own deadline: the
#: context upload before it, and the artifact download after it. A build
#: that used its whole deadline would otherwise die of the hard TTL
#: *before* its deadline could ever fire — two numbers contradicting each
#: other, with the build's work thrown away either way.
SESSION_WORK_MARGIN = 900.0


def ttl_for(build_deadline_seconds: float) -> float:
    """The hard TTL a server with this build deadline has to give.

    The deadline is the operator's (``--build-deadline-seconds``) and the
    TTL was a constant, so raising one silently made the other the real
    limit. Deriving it keeps the promise the two numbers make together:
    a session can host one invocation that runs for its full deadline,
    plus :data:`SESSION_WORK_MARGIN` for the transfers around it. The
    floor stays :data:`DEFAULT_SESSION_TTL`, because a *short* deadline
    is no reason to shorten the lease of a session that is idle.
    """
    return max(DEFAULT_SESSION_TTL, build_deadline_seconds + SESSION_WORK_MARGIN)


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

#: How long process shutdown waits, **in total**, for the invocations of
#: every session it is releasing.
#:
#: One budget for the whole loop and not one per session: a server that
#: has been told to stop is expected to be gone, and spending the
#: liveness ladder once per session would make exit take
#: ``sessions × (cancel grace + the ladder's tail)`` — over six minutes
#: at this server's defaults with four sessions, which is longer than a
#: service manager waits before it sends SIGKILL and therefore a bound
#: that buys nothing.
#:
#: Thirty seconds is generous for what is actually being waited on. The
#: container of every session is removed first, and that is what stops
#: a build; what remains is the supervisor noticing on its next
#: half-second poll. What the wait cannot fix — a supervisor that
#: outlived its own ladder — is not fixed by waiting longer either:
#: the directories are deleted afterwards regardless, because a
#: stopping process is the last thing that could ever name them.
SHUTDOWN_RELEASE_SECONDS = 30.0

#: Concurrent open sessions, per **server**. v1.0 is single-tenant and
#: one bearer token is one principal, so a per-user quota would be a
#: per-server quota with a misleading name; the
#: per-user machinery, work metering and cost classes belong to the
#: hosted phase and are not implemented here.
DEFAULT_MAX_OPEN_SESSIONS = 4

#: The base of a seat's waiting time. A seat at position *n* is told to
#: come back after ``n ×`` this, capped by
#: :data:`DEFAULT_SEAT_RETRY_MAX_SECONDS` — so the head of the queue is
#: the fastest poller, which is what makes reserving a freed slot for it
#: affordable (:class:`SeatQueue`). An operator turns it up on a private
#: server, where a queue is rare and a chatty client buys nothing, and
#: down on a public one.
DEFAULT_SEAT_RETRY_SECONDS = 60.0

#: The ceiling on that number, so a deep queue does not answer "come
#: back in three hours" — a client told that has been refused, not
#: queued.
DEFAULT_SEAT_RETRY_MAX_SECONDS = 900.0

#: What a seat gets on top of its own appointment before it expires. A
#: constant rather than an option: it exists to absorb scheduling and
#: network jitter around a time the server itself named, and an operator
#: who wants a longer leash has :data:`DEFAULT_SEAT_RETRY_SECONDS` for
#: it. This is also why there is no "give up my seat" verb — a seat left
#: behind is gone within its appointment plus this.
SEAT_GRACE = 60.0

#: How many seats this server will hold. It bounds the queue's memory
#: and is the honest answer to a server being used as a queue rather
#: than as a build server; past it, admission refuses **without** handing
#: out a seat (``session.no-seat``).
DEFAULT_MAX_SEATS = 128

#: The shape of a seat token. Opaque and unguessable for the same reason
#: a session id is: it is the only thing standing between a caller and
#: somebody else's turn.
SEAT_ID_BYTES = 12

#: How long a session with no client attached is protected from being
#: handed to somebody who is waiting.
#:
#: Connection loss is never abandonment — that is what makes
#: ``attach-session`` worth having, and it stays true: a session is taken
#: away only when a *third party* wants the slot, and only after this
#: much quiet. What it stops being is unconditional. With
#: ``--max-sessions 1`` a client
#: that died without closing its session used to hold the whole server
#: for the full idle timeout, measured at ten minutes of a build server
#: doing nothing while a client polled its seat.
#:
#: Sixty seconds because that is a reconnect, generously: a client that
#: lost its socket dials back in seconds, and one that needs a minute has
#: not lost a socket, it has gone. Turning it up protects a flaky client
#: at a waiting one's expense, and turning it down to a second or two
#: hands a session over as soon as it is unattended. There is no
#: "never": that is the behaviour this replaces.
DEFAULT_RECONNECT_GRACE = 60.0

#: Why a session is gone, when it is gone: the values :attr:`Session.reaped`
#: carries. Two say the lease ran out — the client's own time was up —
#: and the third says this server took the session away while it still
#: had time, which is different news and gets a different sentence.
GONE_LEASE = "lease"
GONE_IDLE = "idle timeout"
GONE_HANDOVER = "handover"

_GONE_MESSAGE = {
    GONE_LEASE: 'Session "{session_id}" outlived its lease and was reaped.',
    GONE_IDLE: 'Session "{session_id}" outlived its idle timeout and was reaped.',
    GONE_HANDOVER: (
        'Session "{session_id}" had no client attached and nothing running while another '
        "client was waiting for a turn, so this server released it and deleted its "
        "directory. Open a new session."
    ),
}


def gone_message(session_id: str, reason: str) -> str:
    """The sentence for a session that is no longer there."""
    template = _GONE_MESSAGE.get(reason)
    if template is None:  # pragma: no cover - the three above are all there are
        return f'Session "{session_id}" was reaped ({reason}).'
    return template.format(session_id=session_id)


STATE_OPEN = "open"
STATE_CLOSED = "closed"

#: The shape of a server-assigned invocation id: ``inv-`` and a counter
#: that starts at 1 and rises for the life of one session. Monotonic per
#: session rather than random, because the id is a path segment
#: (``invocations/<id>/``) and an ordinal is the one form that is
#: readable in a log, sortable by age and impossible to collide inside
#: the session that issues it. It is never named to the program by this
#: server's own choice — the backend addresses an
#: invocation by the paths it chose for it — so nothing outside this
#: server depends on the spelling.
INVOCATION_ID = re.compile(r"inv-[1-9][0-9]{0,9}\Z")

#: The context's three states inside a session. They exist because the
#: freeze is an **explicit verb** rather than an implicit one on "the
#: first writing command": an implicit freeze needs an enumerated list
#: of writing commands kept in sync with a verb set that is append-only
#: by decision, and a third-party command could not know which side of
#: the line it falls on. The two states that
#: matter are named after the two typed errors that hang on them —
#: `context.not-locked` while the context is still open to writes,
#: `context.locked` once it is not.
CONTEXT_NONE = "none"
CONTEXT_UNLOCKED = "unlocked"
CONTEXT_LOCKED = "locked"

#: One invocation's place in its life, as `cancel` and `close-session`
#: see it. The container backend moves invocations to FINISHED when a
#: result document lands; CANCELLING is "the stop signal is set" — an
#: acknowledged state only, never "it
#: stopped", which only the result document says.
INVOCATION_RUNNING = "running"
INVOCATION_CANCELLING = "cancelling"
INVOCATION_FINISHED = "finished"

#: The invocation states that mean "this session is doing something".
#: A cancelling invocation counts: it is winding a program down, and
#: pulling its directory out from under it is the one state neither half
#: recovers from.
_WORKING = (INVOCATION_RUNNING, INVOCATION_CANCELLING)


@dataclass
class Session:
    """One admitted session: its identity, profile, lease and context state.

    The session is admitted on **no context at all** — deliberately —
    so a fresh
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
    #: Every invocation this session ever ran, id -> INVOCATION_* state.
    #: The bookkeeping `cancel` addresses; the container backend
    #: populates it and flips entries to FINISHED.
    invocations: dict[str, str] = field(default_factory=dict)
    #: What the next invocation of this session is called. Per session,
    #: so two sessions both have an `inv-1` and neither can name the
    #: other's — the id is only ever resolved against the session that
    #: issued it.
    invocation_counter: int = 0
    #: The context id ``lock-context`` computed and answered. Held
    #: because attribution always uses the id **this server** computed:
    #: it is what every working invocation is measured against before it
    #: starts and what the result document's own ``context`` is compared
    #: to when it comes back.
    context_id: str | None = None
    #: What ``send-context`` learned about the build environment serving
    #: this session, or ``None`` before it. Duck-typed rather than
    #: imported, because the verbs call the backend and the backend
    #: never calls the verbs.
    image: Any = None
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
    #: quota. Cumulative across the base context and every extension,
    #: which is the only way a cap can bound a repeatable verb.
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
    #: driving it. :data:`GONE_HANDOVER` is the third value and the one
    #: that is not a lease at all — this server took the session away
    #: while it still had time, for a client that was waiting.
    reaped: str | None = None
    #: The live connections speaking for this session. Never serialized
    #: and not part of the protocol: it is what "a client is attached"
    #: means to :meth:`SessionManager._hand_over`, and nothing else reads
    #: it. Bound by every command that names the session, so a client
    #: that reconnected without ``attach-session`` counts as attached too.
    connections: set[Any] = field(default_factory=set)
    #: When the last of them went away, or ``None`` while one is here. A
    #: session that never had one reads as unattended from the start,
    #: which is what it is.
    disconnected_since: float | None = None

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

    def touch(self, *, now: float | None = None) -> None:
        """Mark the session as having just done something.

        The idle half of the lease counts absent **commands**, so every
        verb refreshes this — and so does the *end* of an invocation,
        which is the one piece of activity no command marks: a build is
        one command that then runs for minutes, and its client sends
        nothing until it is over.
        """
        self.last_command_at = time.time() if now is None else now

    def require_context(self) -> None:
        """Refuse a command that has no context to work on.

        ``extend-context`` and ``lock-context`` both need a base context
        to exist. Nothing else in the protocol names a code for the
        case, and this is the registry's own entry for "the command
        needs a context and send-context has not happened" — which is
        exactly it.
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
        """Refuse a second base context before the lock.

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

        By design: the per-session directory — the context
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
        self.context_id = None
        self.image = None
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

    **Work is not idleness**, and the idle half has to know it, because
    the two long things this server does are both *one* command that then
    takes minutes:

    * **an invocation**, during which a well-behaved client sends nothing
      and only listens. Counting commands alone, a session compiling away
      looked idle after ten minutes and was reaped under its own build —
      observed, with the container removed mid-compile and a client left
      waiting on a verdict that could no longer come.
    * **a context command**, which is the same shape and was missed:
      ``send-context`` receives an archive and then *fetches the build
      environment the context pinned*, which is over a gigabyte. Observed
      the same way — "fetching build environment" at one second and
      "reaped 1 expired session" twenty-seven seconds later, on a server
      whose idle timeout was fifteen. The client was blocked on the very
      command frame whose work had just been thrown away.

    The hard TTL still applies, and so do the invocation's own deadline
    and the upload's (:attr:`Session.idle_timeout` bounds that await), so
    this cannot make a session immortal.
    """
    if now > session.expires_at:
        return GONE_LEASE
    if session.idle_timeout > 0 and now > session.last_command_at + session.idle_timeout:
        if _is_working(session):
            return None
        return GONE_IDLE
    return None


def _is_working(session: Session) -> bool:
    """Whether this session has work in flight.

    Two kinds, and they are the two things that take longer than a frame:
    an invocation that is running or being stopped, and a context command
    — an upload arriving, or the build environment it pinned being
    fetched (:func:`_context_work` holds that flag for exactly as long as
    one is in progress).

    Both callers want the same answer. The reaper must not take a session
    away from work; the handover must not take one away from a *waiting
    client*, which would be worse still — the directory goes with it, and
    a ``send-context`` unpacking into it would be writing into a tree
    nobody can name any more.
    """
    if session.context_busy:
        return True
    return any(state in _WORKING for state in session.invocations.values())


def _quiet_since(session: Session) -> float:
    """When this session was last attended, on the wall clock.

    The later of its last command and the moment its last connection went
    away, because both are ways of being unattended and the grace has to
    run from whichever came last: a client that goes quiet and *then*
    loses its socket has not been unattended for the length of its
    silence, and one that is uploading over a socket nobody attached is
    not unattended at all.
    """
    if session.disconnected_since is None:
        return session.last_command_at
    return max(session.last_command_at, session.disconnected_since)


@dataclass
class Seat:
    """One held turn: what it is called, and until when it is held."""

    #: The token the client presents. Opaque to everyone but this queue.
    id: str
    #: What the client was told to wait, in seconds. Echoed to it so the
    #: two sides agree on the appointment they are keeping.
    retry_after: float
    #: On the **monotonic** clock, so an NTP correction cannot reorder
    #: the queue or resurrect an expired seat.
    expires_at: float


class SeatQueue:
    """The waiting room in front of admission.

    A client refused for want of capacity is handed a seat token and a
    time to come back; it presents the token on its next ``open-session``
    and is either admitted or told to wait again — same token, fresh
    time. The token costs about forty bytes and survives a client that
    closes its socket, changes network or is a script invoked once a
    minute by something else, which a held connection does not: a waiting
    client that kept its socket open would spend a connection slot and an
    inflight budget for the whole wait, and both are caps this server
    announces.

    **Order is kept here and is never published.** Seats are served in
    arrival order today, and :meth:`position` exists to *compute* a
    waiting time rather than to answer one to a client. A later version
    with tariff tiers will admit a paying client ahead of a free one, and
    a protocol that had promised "you are second" would have become a lie
    the moment that shipped. What a client can act on is when to come
    back.

    The clock is monotonic throughout. Wall time here would let a clock
    correction expire every seat at once or none of them ever.
    """

    def __init__(
        self,
        *,
        retry_seconds: float = DEFAULT_SEAT_RETRY_SECONDS,
        retry_max_seconds: float = DEFAULT_SEAT_RETRY_MAX_SECONDS,
        max_seats: int = DEFAULT_MAX_SEATS,
    ) -> None:
        self.retry_seconds = retry_seconds
        self.retry_max_seconds = retry_max_seconds
        self.max_seats = max_seats
        self._seats: list[Seat] = []

    def __len__(self) -> int:
        return len(self._seats)

    @property
    def full(self) -> bool:
        return len(self._seats) >= self.max_seats

    def sweep(self, now: float) -> tuple[str, ...]:
        """Drop every seat whose appointment came and went.

        This is the whole of "the next one moves up": a client that
        misses its own appointment plus :data:`SEAT_GRACE` loses its
        place, and the seat behind it becomes the head. Returns the ids
        dropped, for the log.
        """
        gone = tuple(seat.id for seat in self._seats if now > seat.expires_at)
        if gone:
            self._seats = [seat for seat in self._seats if now <= seat.expires_at]
        return gone

    def position(self, token: str | None) -> int | None:
        """Where *token* stands, 1-based, or ``None`` if it is not held.

        ``None`` covers every way a token can fail — never issued,
        expired, already consumed, invented — because none of them is
        worth telling apart: all four mean the caller has no turn, and
        answering "your token expired" rather than "unknown" would let
        anyone probe which tokens once existed.
        """
        if token is None:
            return None
        for index, seat in enumerate(self._seats, start=1):
            if seat.id == token:
                return index
        return None

    def _wait_at(self, position: int) -> float:
        return min(self.retry_seconds * position, self.retry_max_seconds)

    def issue(self, now: float) -> Seat:
        """Append a new seat at the back and time it."""
        wait = self._wait_at(len(self._seats) + 1)
        seat = Seat(
            id=f"seat-{secrets.token_urlsafe(SEAT_ID_BYTES)}",
            retry_after=wait,
            expires_at=now + wait + SEAT_GRACE,
        )
        self._seats.append(seat)
        return seat

    def reissue(self, position: int, now: float) -> Seat:
        """Re-time the seat standing at *position*, in place.

        The token does not change — the client keeps the one it has, and
        the queue keeps the order it had. Re-timing at the *current*
        position is what corrects a seat that was told 180 seconds at
        position 3 and has since become the head: its next appointment is
        the head's.
        """
        seat = self._seats[position - 1]
        seat.retry_after = self._wait_at(position)
        seat.expires_at = now + seat.retry_after + SEAT_GRACE
        return seat

    def release(self, position: int) -> None:
        """Consume the seat at *position*. Its holder is being admitted."""
        del self._seats[position - 1]

    def reserved_against(self, position: int | None) -> int:
        """Slots held back from a caller standing at *position*.

        **A freed slot belongs to the head of the queue**, which is the
        guarantee the queue exists for: without it, the client that
        happens to be dialling in that microsecond wins and "you are
        first" means nothing. So one slot is held whenever anybody is
        waiting — held against a walk-in and against every seat further
        back, and never against the head itself.

        It costs idle capacity, and the cost is exactly the head's own
        appointment: at the default base that is 60 seconds, so an
        average handover loses 30 of them — about 3 % of a
        fifteen-minute build, which is what makes the guarantee worth
        having.
        """
        if not self._seats or position == 1:
            return 0
        return 1


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
        reconnect_grace: float = DEFAULT_RECONNECT_GRACE,
        seats: SeatQueue | None = None,
    ) -> None:
        self._sessions: dict[str, Session] = {}
        self.ttl = ttl
        self.idle_timeout = idle_timeout
        self.max_open = max_open
        self.reconnect_grace = reconnect_grace
        self.seats = SeatQueue() if seats is None else seats
        #: Sessions this manager has taken away and whose build
        #: environment is still running. Drained by :meth:`take_released`.
        self._released: list[str] = []
        #: Sessions whose **release** has not finished: their container
        #: may still be there, their invocation may still be running and
        #: their directory may still be on disk. Every path that takes a
        #: session away puts it here, and it stays until a release
        #: succeeds — which is what makes cleanup this server's own job
        #: rather than something it needs a client to come back for.
        #: Walked by :func:`release_pending` on every sweep.
        self._release_pending: list[str] = []

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

        The waiting room is swept in the same pass. Admission sweeps it
        too, before every decision, so this is not what makes an expired
        seat expire — it is what keeps a queue nobody is dialling from
        holding its memory until somebody does.
        """
        moment = time.time() if now is None else now
        self.seats.sweep(time.monotonic())
        reaped: list[str] = []
        for session in list(self._sessions.values()):
            over = _lease_over(session, moment) if session.state == STATE_OPEN else None
            if over is None:
                continue
            session.state = STATE_CLOSED
            session.reaped = over
            self.mark_for_release(session.id)
            _discard_if_free(session)
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

        **The containers go first**, and not here:
        :func:`release_every_session` runs before this and is what stops
        the builds. This is the last step of shutdown on purpose — the
        directories are deleted even for a session that would not
        release, because a stopping process is the last thing that could
        ever name them, and credentials left behind are worse than a
        thread that is about to lose its interpreter anyway.
        """
        for session in list(self._sessions.values()):
            if session.state == STATE_OPEN:
                session.state = STATE_CLOSED
            session.discard_context()

    def attach(self, session: Session, connection: Any) -> None:
        """Record that *connection* is speaking for this session.

        Called for ``open-session`` and then by :meth:`require`, so it
        covers every command that names the session — a client that
        reconnected and simply carried on, without ``attach-session``,
        is attached here too. Attachment is not permission and grants
        nothing: the only question it answers is whether a session that
        has gone quiet still has anybody behind it.
        """
        session.connections.add(connection)
        session.disconnected_since = None

    def detach(self, connection: Any, *, now: float | None = None) -> None:
        """Drop a closed socket from every session it was speaking for."""
        moment = time.time() if now is None else now
        for session in self._sessions.values():
            if connection not in session.connections:
                continue
            session.connections.discard(connection)
            if not session.connections:
                session.disconnected_since = moment

    def take_released(self) -> tuple[str, ...]:
        """The sessions this manager took away since the last call.

        Admission runs inside one command and cannot wait for a container
        to be removed, so it marks the session and this hands the id to
        somebody who can do the asynchronous half. Drained by
        ``open-session`` right after admission — including when admission
        then refused it anyway, which is a real case: a slot freed by a
        walk-in belongs to the head of the queue — and by the sweep,
        which is the backstop for every other path.
        """
        released, self._released = tuple(self._released), []
        return released

    def ids(self) -> tuple[str, ...]:
        """Every session this manager holds, in the order they opened."""
        return tuple(self._sessions)

    def find(self, session_id: str) -> Session | None:
        """The session called *session_id*, or ``None``. Never refuses.

        :meth:`require` is the verbs' door and answers a client, with
        every refusal a client has to hear; this is for the teardown
        paths, which are answering nobody and must not raise over a
        session that is already gone.
        """
        return self._sessions.get(session_id)

    def mark_for_release(self, session_id: str) -> None:
        """Record that this session still owes a release. Idempotent.

        Set by every path that takes a session away and by a release
        that did not finish. It is the one place that knows a container,
        an invocation or a directory may still be out there, and the
        sweep is what acts on it.
        """
        if session_id not in self._release_pending:
            self._release_pending.append(session_id)

    def pending_releases(self) -> tuple[str, ...]:
        """The sessions whose release has not finished, oldest first.

        Read rather than drained: an entry goes away when the release
        actually succeeded (:meth:`finish_release`), because a sweep
        that forgot a session it failed to release would be exactly the
        leak this list exists against.
        """
        return tuple(self._release_pending)

    def finish_release(self, session_id: str) -> None:
        """Record that this session's release is over. Idempotent."""
        if session_id in self._release_pending:
            self._release_pending.remove(session_id)

    def _handover_ready(self, session: Session, now: float) -> bool:
        """Whether this session may be taken away for a waiting client.

        Four conditions, and the last two are the promises being kept.
        **Nothing running**: work is not idleness, so a detached build
        keeps its session exactly as the idle timeout does. **Nobody
        attached**: a client on the socket owns its session however long
        it thinks, which is the whole of the dev profile. Then a lease
        that has not run out — a session past it belongs to the sweep,
        which has the right reason for it — and the reconnect grace.
        """
        if session.state != STATE_OPEN:
            return False
        if _lease_over(session, now) is not None:
            return False
        if session.connections or _is_working(session):
            return False
        return now >= _quiet_since(session) + self.reconnect_grace

    def _hand_over(self, wanted: int) -> tuple[str, ...]:
        """Take up to *wanted* unattended sessions away. Longest quiet first.

        Called only from admission and only when the caller would
        otherwise be refused, so an idle session is never taken while the
        server has room for both. The directory goes with it, here and
        now, for the reason :meth:`reap` gives: it holds a device's
        commissioning credentials.
        """
        now = time.time()
        ready = sorted(
            (session for session in self._sessions.values() if self._handover_ready(session, now)),
            key=_quiet_since,
        )
        taken: list[str] = []
        for session in ready[:wanted]:
            session.state = STATE_CLOSED
            session.reaped = GONE_HANDOVER
            self.mark_for_release(session.id)
            # Nothing is in flight here — that is one of the four
            # conditions a handover has — so what decides is whether
            # this session ever got a build environment. One that did
            # keeps its directory until `release_session` has removed
            # the container that mounts it, which `open-session` does
            # before it answers the client this session was taken for.
            _discard_if_free(session)
            self._released.append(session.id)
            taken.append(session.id)
        return tuple(taken)

    def _admit(self, seat: str | None) -> None:
        """Let this caller through, or refuse it with a turn to come back.

        The two refusals are deliberately different promises.
        ``session.limit-exceeded`` hands out a seat and is therefore an
        undertaking to serve this caller in its turn;
        ``session.no-seat`` makes no such promise and says why it did
        not. There has to be a way to refuse without promising, and the
        wire needs it now rather than after the fact: today the only
        reason is a full queue, and the reason that follows it is a
        per-client seat quota — a rule about identity, which this server
        cannot express while one bearer token is one principal. That
        later work adds a reason, not a wire format.

        A token this queue does not hold — never issued, long expired,
        already spent, invented — is not an error. The caller simply has
        no turn, and is treated as the walk-in it effectively is.
        """
        now = time.monotonic()
        self.seats.sweep(now)
        position = self.seats.position(seat)

        free = self.max_open - self.open_count
        # Somebody wants in and there is no room: before refusing, look
        # for a session that nobody is attached to and that has nothing
        # running. Only here, because scarcity is the whole justification
        # — with a free slot there is no client whose wait an idle
        # session is paying for, and taking it would be a lease this
        # server had promised and then broken for nothing.
        short_by = 1 + self.seats.reserved_against(position) - free
        if short_by > 0:
            self._hand_over(short_by)
            free = self.max_open - self.open_count
        if free - self.seats.reserved_against(position) >= 1:
            if position is not None:
                self.seats.release(position)
            return

        if position is not None:
            held = self.seats.reissue(position, now)
        elif self.seats.full:
            raise SessionError(
                "session.no-seat",
                f"This server is holding its limit of {self.seats.max_seats} waiting turns "
                "and issued none for this request. Try again later.",
                reason="queue-full",
                retry_after_seconds=int(self.seats.retry_max_seconds),
            )
        else:
            held = self.seats.issue(now)
        raise SessionError(
            # Stated as a fact rather than as an instruction, because not
            # every client is going to act on it: one told to come back
            # with a seat it has already thrown away — a client asked to
            # fail rather than wait — would be reading a step it cannot
            # take. What is true either way is that the turn is being
            # held, and for how long.
            "session.limit-exceeded",
            f"This server builds at most {self.max_open} at a time and they are all "
            f"running. A turn is being held for this client for the next "
            f"{int(held.retry_after)} seconds.",
            max_open=self.max_open,
            seat=held.id,
            retry_after_seconds=int(held.retry_after),
        )

    def open(
        self,
        *,
        profile: str,
        protocol_version: int,
        context_format: int,
        seat: str | None = None,
    ) -> Session:
        """Admission. Every refusal is typed, at the door.

        Three operands and no fourth: ``open-session`` carries no
        manifest header, so admission decides
        the protocol version, the context-format version and the
        profile, and nothing about the context itself.

        The fourth argument is not an operand and does not negotiate
        anything: *seat* is the token a client was handed when this
        server had no room, and presenting it asks for the turn that
        token stands for. It is checked **after** the three, because a
        request this server cannot serve at all should not be answered
        with a place in a queue for it.
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
        self._admit(seat)
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

    def require(self, session_id: str, connection: Any = None) -> Session:
        """The open session called *session_id*, or a typed refusal.

        *connection* is the socket the command came in on, and passing it
        is what keeps "a client is attached" true for a client that
        reconnected without ``attach-session`` (:meth:`attach`). It is
        optional so that a caller with no socket — a test, or a future
        internal one — can still ask.
        """
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
            # Reaped means reaped: a context nothing is holding goes
            # with the lease rather than at some later sweep. It holds a
            # device's Matter commissioning credentials, and "we will
            # get to it" is not a retention policy for those.
            #
            # A session with a build environment is the sweep's, and so
            # is the environment itself: this method is synchronous — it
            # is answering a client mid-verb — and removing a container
            # and waiting for a supervisor is not something a refusal
            # can stop to do. Before this list existed, that was the
            # whole of it: a session whose lease ran out here never
            # reached `backend.release` at all, so its container and the
            # thread driving it lived until the process did, and the
            # tree was deleted under both.
            self.mark_for_release(session.id)
            _discard_if_free(session)
        if session.reaped is not None:
            raise SessionError(
                "session.expired",
                gone_message(session_id, session.reaped),
                session_id=session_id,
            )
        if session.state != STATE_OPEN:
            raise SessionError(
                "session.closed",
                f'Session "{session_id}" is closed.',
                session_id=session_id,
            )
        if connection is not None:
            self.attach(session, connection)
        session.touch()
        return session

    def close(self, session_id: str) -> Session:
        """Close a session. Closing a closed one is not an error: the
        client asked for a state and that state holds.

        **A busy session is cancelled implicitly**: every running
        invocation gets the stop signal, and then the session is reaped.
        Refusing to close while an invocation runs was rejected because
        connection loss is never abandonment — that is
        ``attach-session``'s reason to exist — so closing must never
        require a live client to first cancel, reattach, or wait; a
        crashed client's session would otherwise hold its resources
        until lease expiry as the *normal* path rather than the
        fallback.

        **The sentinel here is best-effort and nothing more.** "The
        result document is still written" orders the *program's*
        shutdown — write before you die — and promises nobody a
        document: the client gets no result for an implicitly cancelled
        invocation either way, and the directory the document would be
        read from is the one this close deletes. So the sentinel is set
        for a program that happens to be between polls, the container is
        removed, and only then is the tree discarded — which is the one
        ordering in which nothing writes into a directory that is being
        deleted underneath it. The discard is the caller's, because the
        container has to go first and reaping it is asynchronous.
        """
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionError(
                "session.unknown",
                f'This server has no session called "{session_id}".',
                session_id=session_id,
            )
        _mark_cancelling(session)
        session.state = STATE_CLOSED
        self.mark_for_release(session_id)
        return session


# --------------------------------------------------------------------------
# The verbs
# --------------------------------------------------------------------------


def capabilities_payload(state: Any, containers: list[dict[str, Any]]) -> dict[str, Any]:
    """What the ``capabilities`` verb answers — pre-session, cheap.

    It stays the **pre-session query** after the freeze verb landed:
    ahead of a session at all, this is what lets the workbench choose a
    build environment during pin resolution rather than discover the
    mismatch from inside one. It fails fast
    ("this server has no build environment for zephyr-4.4.0-r1") instead
    of dying mid-session, and it is the one verb that carries no session
    id, because there is no session yet to carry.

    ``containers`` is what this host already **has**: every local image
    carrying a build-environment declaration, with its reference, its
    repo digest and the declaration its labels mirror (build environment
    specification §5.2). It is pre-start scheduling data and is answered
    as such — an image is in this list for carrying those labels, and
    whether one of them serves a given context is decided by the package
    set the context pins. Nothing here starts a container, because a
    client asking what this server has is not yet asking any image to
    prove it.

    ``environments`` is the other half and the one a client can act on:
    the repositories this operator allows an environment to come from. A
    context may travel with an image pin, and a pin naming a repository
    outside this list is refused before any registry is asked — so the
    list is announced rather than discovered by being refused.

    An empty ``containers`` is still a truthful answer, and it means what
    it says: this host has no build-environment image yet. So does a host
    whose container runtime is down — the question is which environments
    this server has, and "none" is a fact rather than an error. The
    refusal for a missing runtime belongs to the verb that needs a
    container.

    **``ingress`` is announced rather than discovered.** The five
    caps of the ingress hardening floor exist so that a client can refuse an
    oversized upload before the first byte leaves, and a cap it cannot
    see can only be found by hitting it — after the bytes have been
    sent, which is the one cost the caps exist to avoid. They are
    answered from *this server's configuration* and never from a
    constant, because the config is the policy: an operator who
    lowered a cap has lowered what this block says.

    The sixth number is not one of the five. ``frame_bytes`` is the
    largest WebSocket message the endpoint accepts
    (:data:`~mcuhome.buildserver.protocol.MAX_FRAME_BYTES`) — a bound
    that lives *below* the verbs, whose overrun is a dropped connection
    rather than a typed refusal, and which therefore has to be knowable
    in advance or not at all.

    There is deliberately **no ``quota.work``** and no cost class. Work
    metering and cost classes belong to the hosted
    phase, and v1.0 has neither; a
    field promising a concept the valid layer removed is worse than a
    field that is not there.
    """
    config = state.config
    allowed = frozenset(config.allowed_patch_layers)
    caps = IngressCaps.from_config(config)
    # The four names this server's own layer set fixes, plus any third-party `x-` layer
    # this operator listed. An `x-` name cannot be enumerated — the
    # prefix exists precisely so vendors need no registration — so the
    # only ones this server can name are the ones it was told about.
    layers = list(PATCH_LAYERS) + sorted(allowed - set(PATCH_LAYERS))
    return {
        # This server's own version and uptime. They live here, behind the
        # token, rather than on the unauthenticated `/health`: a liveness
        # probe needs neither, and the one pre-auth response is the wrong
        # place to hand an attacker a version to match against a known
        # weakness. A client that has presented the token may read them.
        "server": {
            "build_server": __version__,
            "uptime_seconds": round(time.monotonic() - state.started_at, 3),
        },
        "protocol": {
            "version": SESSION_PROTOCOL_VERSION,
            "context_format": {"min": CONTEXT_FORMAT_MIN, "max": CONTEXT_FORMAT_MAX},
            "profiles": list(PROFILES),
        },
        "containers": containers,
        # Which repositories an environment may be taken from here. It is
        # the operator's boundary and the one part of image selection a
        # client can act on before it uploads anything.
        "environments": {"allowed": list(config.allowed_environments)},
        # The server's patch configuration IS the policy; unlisted layers
        # are denied by default. Advertised per layer so the
        # workbench refuses a patched context before uploading it.
        "patch_policy": {layer: {"allow": layer in allowed} for layer in layers},
        # What one upload may cost here (the five ingress caps), plus the
        # transport bound under the verbs. Read from the config, so the
        # announcement follows an operator's setting rather than a
        # constant this module could drift from.
        "ingress": {
            "compressed_bytes": caps.compressed_bytes,
            "decompressed_bytes": caps.decompressed_bytes,
            "entries": caps.entries,
            "file_bytes": caps.file_bytes,
            "path_depth": caps.path_depth,
            "frame_bytes": protocol.MAX_FRAME_BYTES,
        },
        "quota": {
            "sessions": {
                "open": state.sessions.open_count,
                "max_open": state.sessions.max_open,
            },
        },
    }


async def capabilities(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``capabilities`` — see :func:`capabilities_payload`."""
    return capabilities_payload(state, await state.backend.inventory())


async def open_session(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``open-session`` — admission, and nothing about the context.

    Payload::

        {"profile": "oneshot",            # oneshot | dev | test
         "protocol_version": 2,           # required; mismatch is typed
         "context_format": 4,             # the format the context will use
         "seat": "seat-…"}                # optional; a turn this server held

    ``seat`` is the token a client was handed when this server had no
    room (``session.limit-exceeded``, whose details carry it together
    with the seconds to wait). Presenting it asks for that turn. It is
    additive and moves no protocol version: a server that does not know
    seats ignores the field, and a client only ever sends a token a
    server gave it. A token this server no longer holds is not an error
    — the caller is simply a walk-in again.

    **There is no manifest operand.** ``open-session`` carries no first
    operand for it: admission negotiates the
    protocol version, the context-format version and the profile, and
    the pins arrive with ``send-context``, in ``context.yaml``. The term
    "manifest header" is retired outright —
    there is no header separate from ``context.yaml``, and
    ``manifest.yaml`` does not exist until ``lock-context`` writes it.

    The response carries what **admission alone** decides::

        {"session": {"id", "profile", "state", "context_state", "created_at"},
         "lease": {"ttl_seconds", "idle_timeout_seconds", "expires_at"},
         "negotiated": {"protocol_version", "context_format", "backend_profile"}}

    The serving build environment's declaration and action set are
    **not** here. With no context at ``open-session`` the backend does
    not yet know *which* image serves the session — the digest
    arrives with the pins — so ``send-context`` answers that half. What
    discovering early was for survives the split intact, because
    ``send-context`` precedes ``lock-context`` and therefore precedes
    every working command.

    ``negotiated.backend_profile`` is the field this response carries
    for it: how this server executes the builds it accepts, and
    the one thing a client learns about which promises are being made to
    it. Today it is always ``container`` — one container per session, no
    network, per-session limits, the session as the trust boundary — and
    it stays on the wire because the answer is not going to stay the only
    one: a machine that builds without a container runtime makes none of
    those promises, and a client that could not see which it got would
    have to infer it from behaviour.

    Patch *policy* is enforced against the files actually present, so it
    runs at ``send-context``/``extend-context`` time, not here.
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
    # were answered `result` — the one thing that
    # must not happen, since version mismatch is a typed rejection at
    # the door, never a downstream failure.
    profile = command.optional_str("profile", "oneshot")
    context_format = command.optional_int("context_format", CONTEXT_FORMAT_MAX)
    try:
        session = state.sessions.open(
            profile="oneshot" if profile is None else profile,
            protocol_version=protocol_version,
            context_format=CONTEXT_FORMAT_MAX if context_format is None else context_format,
            seat=command.optional_str("seat", None),
        )
        # Attached from its first breath, so the grace can never run on a
        # session whose client is right here.
        state.sessions.attach(session, connection)
    finally:
        # Admission may have made room by taking unattended sessions
        # away, and it can only mark them: removing a container is
        # asynchronous and admission is not. In a `finally` because a
        # refused caller can free a slot too — for the head of the queue,
        # which the reservation holds it for.
        for released in state.sessions.take_released():
            # The whole teardown and not only the container: the session
            # this admission took away has a directory too, and the one
            # order that holds is the one `release_session` walks. A
            # release that does not finish stays on the manager's
            # pending list and the sweep tries it again.
            await release_session(state, released)
    return {
        "session": session.to_dict(),
        "lease": session.lease_dict(),
        "negotiated": {
            "protocol_version": SESSION_PROTOCOL_VERSION,
            "context_format": {"min": CONTEXT_FORMAT_MIN, "max": CONTEXT_FORMAT_MAX},
            "backend_profile": state.backend.profile,
        },
    }


def _archive_announcement(command: Command, key: str = "archive") -> tuple[int, str]:
    """The ``{"size", "sha256"}`` object a context upload is announced with.

    **The wire shape is this server's own and nothing in the documents
    fixed it.** The verb set spells ``send-context(archive)`` and that
    single word is the whole wire specification it gives; the product
    owner settled the rest on 2026-08-09. The JSON payload announces the
    archive's compressed size and its SHA-256, the bytes follow as
    WebSocket BINARY frames within the existing frame cap, and the
    result frame of the verb is the acknowledgement.

    Two values and no third. There is deliberately no ``format`` field:
    the format is **tar.zst**, fixed, chosen for family consistency with
    the SDK package this server fetches the same way, and a field whose
    only legal value is the default is a negotiation nobody asked for.
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


def _mark_cancelling(session: Session) -> None:
    """Running becomes *cancelling* for every invocation of *session*.

    The state and nothing else: something has asked the invocation to
    stop and it has not stopped yet. Raising the actual stop signal is
    :func:`_signal_running`'s, one layer up, where the backend that owns
    the step is in reach.
    """
    for invocation_id, found in session.invocations.items():
        if found == INVOCATION_RUNNING:
            session.invocations[invocation_id] = INVOCATION_CANCELLING


def _signal_running(state: Any, session: Session) -> None:
    """Raise the stop signal for every invocation of *session* that runs.

    The first step of every teardown there is, and the reason it is one
    function: ``close-session``, the sweep, a handover and process
    shutdown all take a session away, and a session taken away without
    the signal would have its supervisor sit out the whole
    ``cancel_grace_seconds`` before anything reached it. What follows —
    removing the container and waiting for the supervisor — is bounded
    by the ladder, and the ladder only starts where the signal was
    raised.
    """
    _mark_cancelling(session)
    for invocation_id, found in session.invocations.items():
        if found == INVOCATION_CANCELLING:
            state.backend.signal_cancellation(session.id, invocation_id)


def _discard_if_free(session: Session) -> bool:
    """Delete the session's directory **if nothing can be holding it**.

    The one rule the synchronous teardown paths share, in one place, and
    the whole of what they are still allowed to delete by themselves.

    Two things can be holding the tree, and neither of them can be
    stopped from a synchronous method. A **build environment**: the
    directory is what a session's container mounts, and no session has
    one before ``send-context`` has chosen an image for it, which is
    what :attr:`Session.image` records. **Work in flight**: an
    invocation running or being cancelled, an upload arriving, an image
    being fetched — with a supervisor on a worker thread reading the
    same tree.

    Neither of them: nothing on this machine can name the directory any
    more, so it goes here and now. That is the promise the reaper exists
    for — the credentials in ``keys/`` go with the lease rather than
    with some later sweep — and it is kept for exactly the sessions
    where keeping it is free.

    Either of them: the deletion belongs to :func:`release_session`,
    which does it in the order that holds — signal, remove the
    container, wait for the supervisor, then delete. Every path that
    leaves a session in this state marks it for release first, so the
    directory outlives the lease by one sweep at the most.

    Answers whether the directory was discarded here.
    """
    if session.image is not None or _is_working(session):
        return False
    session.discard_context()
    return True


async def release_session(state: Any, session_id: str, *, wait: float | None = None) -> bool:
    """Take one session's build environment away, then its directory.

    **The single teardown for every path**: ``close-session``, the
    reaper's sweep, the handover admission makes, a lease that ran out
    and process shutdown all end here, because they all mean the same
    four things in the same order.

    1. The stop signal for every invocation still running
       (:func:`_signal_running`) — without it the ladder below has not
       started and the wait in step 3 is a wait on nothing.
    2. The container is removed. That is the kill: a build runs inside
       it, so nothing outside it stops one.
    3. The invocation's supervisor is waited for, bounded by the ladder
       (or by *wait*, for a caller with a deadline of its own).
    4. Only then the directory, with the context and every artifact in
       it.

    Answers whether the session was released. ``False`` leaves it marked
    for release and its directory where it is, and the sweep tries again
    on its next tick — cleanup is this server's own job, and a client
    that never comes back must not be able to leave a container running
    or a device's commissioning credentials on disk.
    """
    session = state.sessions.find(session_id)
    if session is not None:
        _signal_running(state, session)
    reason = None if session is None else session.reaped
    if not await state.backend.release(session_id, reaped=reason, wait=wait):
        state.sessions.mark_for_release(session_id)
        return False
    if session is not None:
        session.discard_context()
    state.sessions.finish_release(session_id)
    return True


async def release_pending(state: Any) -> tuple[str, ...]:
    """Try again for every session whose release has not finished.

    The sweep's second half and the whole of the retry. Four things put
    a session on this list: the reap in the same tick, a handover whose
    drain in ``open-session`` did not finish, a lease that ran out
    inside a verb, and a release that ran out of ladder. Answers the ids
    that are still pending afterwards, for the log.
    """
    for session_id in state.sessions.pending_releases():
        await release_session(state, session_id)
    return state.sessions.pending_releases()


async def release_every_session(state: Any) -> None:
    """Release every session this process holds, for shutdown.

    One budget for the whole loop (:data:`SHUTDOWN_RELEASE_SECONDS`) and
    the reason is in that constant: a stopping server is expected to be
    gone. The containers are what matter and they are removed first for
    every session; the wait that follows is the supervisor noticing, and
    what has not noticed inside the budget is logged rather than waited
    for.

    A session that releases has its directory deleted with it, by
    :func:`release_session` and in the order that holds. What is left
    afterwards is the directory of a session that did **not** release,
    and that one is :meth:`SessionManager.shutdown`'s: it runs after
    this and deletes unconditionally, because a stopping process is the
    last thing that could ever name a session directory.
    """
    deadline = time.monotonic() + SHUTDOWN_RELEASE_SECONDS
    for session_id in tuple(state.sessions.ids()):
        remaining = max(0.0, deadline - time.monotonic())
        if not await release_session(state, session_id, wait=remaining):
            logger.error("session %s did not release before shutdown", session_id)
    # And whatever is left without a session record to name it.
    await state.backend.release_all(deadline=deadline)


async def send_context(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``send-context`` — upload the base context and its pins.

    Payload::

        {"session_id": "s-…",
         "archive": {"size": 4711, "sha256": "<64 hex digits>"},
         "container_image": ":0.1.0-r2"}                # optional

    followed by the tar.zst as BINARY frames (see
    :func:`_archive_announcement`). The result frame is the
    acknowledgement, and it arrives when the declared number of bytes
    has been received, hashed to the declared value, unpacked safely and
    parsed.

    **The image pin travels here and not in the context.** A context
    references packages and never an image (build environment
    specification §4), so a pin inside it would change a context's
    identity without changing a single build input. It belongs to *this
    build*, and this is the message that carries this build's parameters
    — the one at which the environment is chosen, frozen into the
    session and answered back. Four forms are accepted, the same four a
    local build takes: nothing, a bare repository, ``:tag`` or
    ``@sha256:…`` on their own, and the canonical
    ``repository:tag`` / ``repository@sha256:…``. A pin narrows which
    images are looked at and never what is accepted — the labels decide
    — and a pin naming a repository this server does not allow is
    refused before any registry is asked. What never travels is the
    client's own search list: which repositories may be used here is
    this operator's decision and not a client's.

    The base context carries ``context.yaml``: the format version, the
    resolved pins — SDK package sha256, target board — the Zephyr line a
    build environment must carry, and the constraint the SDK pin was
    resolved from. It is **required**, even for the empty context
    that may be locked: two of the three inputs of
    the context ID live in it, so a context without it has no identity to
    freeze. "Empty" means no *content* files, and that is allowed here —
    what a ``build`` needs beyond existence, ``keys/signing.pub`` above
    all, is checked by ``build``.

    **The response carries the serving environment**, which is the half
    of the discovery payload that belongs here: with no
    context at ``open-session`` the backend does not yet know *which*
    image serves the session, and the requirement it answers arrives
    with the pins. The answer is this server's **choice** and
    not an echo — the context named no image — so ``container`` carries
    the image and digest it selected, plus the declaration its labels
    mirror: spec generation, Zephyr version, generator constraint and
    package set, read from the image's own labels rather than from any
    answer it gives at runtime.

    That is also where ``version.builder-unsatisfiable`` becomes real.
    The image is looked for in the repositories this operator allows and
    chosen by the labels found there, and the bytes are fetched by that
    digest unless the operator turned fetching off (``--no-auto-pull``),
    in which case an image that is not already here is refused under the
    same code. So a context whose package set no allowed image declares
    is refused at the moment the pins arrive rather than minutes into a
    build — and before the context is frozen, which is the useful
    moment: the client can go to a server that serves the set, without
    having paid for a lock.

    **The cross-checks, as context format 4 leaves them.** The
    container check is gone as a *comparison* and survives as a
    *construction*: this server picks the image itself, so there is
    nothing left to disagree with, and what used to be checked is now
    true by the way the choice is made. ``mcuhome.package.sha256`` is
    checked against the package bytes when they are fetched and
    unpacked, which is the first working command, because the pin to
    fetch against is the one the *lock* wrote. ``target.board`` and
    ``zephyr`` are compared against the pins the session was admitted on
    by the pre-invocation re-check
    (:func:`~mcuhome.buildserver.contextstore.recheck_locked_context`):
    admission carries no pins since ``open-session`` carries no
    manifest header, so the pins this
    ``send-context`` accepted *are* what the session was admitted on,
    and re-measuring the manifest against them is the only comparison
    that exists to be made.

    On any refusal the whole upload is discarded — the directory is
    deleted and the session goes back to :data:`CONTEXT_NONE`, so the
    client can send a corrected context over the same session. That is
    also the answer for a base context carrying a denied patch layer: it
    fails wholesale rather than partially, because a context is one
    artifact and half of one has no meaning.
    """
    session = state.sessions.require(command.require_str("session_id"), connection)
    image_pin = command.optional_str("container_image")
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
                    "pins into a session — the SDK package hash, the target board and "
                    "the Zephyr line a build environment has to carry — and a context "
                    "without it has no identity to freeze."
                )
            pins = parse_context_yaml(
                entry,
                expected_version=session.context_format,
                max_bytes=state.config.max_context_yaml_bytes,
            )
            recheck_patch_policy(paths.context, frozenset(state.config.allowed_patch_layers))
            context_yaml_sha256 = sha256_file(entry)
            # The environment last, and inside the same guard: an image
            # this host cannot get makes the whole send-context a
            # refusal, so the context goes with it rather than sitting in
            # a session that can never build.
            image = await state.backend.resolve_image(
                pins,
                paths.context,
                image_pin=image_pin,
                on_progress=_pulling(connection, session.id),
            )
        except BaseException:
            session.discard_context()
            raise
    session.pins = pins
    session.context_yaml_sha256 = context_yaml_sha256
    session.image = image
    session.context_state = CONTEXT_UNLOCKED
    return {
        "session_id": session.id,
        "context": {"state": session.context_state, "format": pins.context_version},
        "pins": pins.to_wire(),
        "container": image.to_wire(),
    }


def _pulling(connection: Any, session_id: str) -> Callable[[str], None]:
    """Relay a fetch's progress while ``send-context`` is still in flight.

    A build environment is over a gigabyte, so a fetch is minutes of
    silence on a command frame the client is blocked on. Docker's own
    layer counts and percentages are the progress report — inventing a
    spinner over them would say strictly less — and they go out as
    ``environment.pulling`` events carrying the line verbatim.

    **Offered, not sent.** It is the same rule the build log follows and
    for the same reason: this runs in the middle of reading a pull's
    pipe, so it must not await, and a client too slow to keep up loses
    progress lines rather than stalling the fetch. The event is
    droppable by construction — it is neither an answer nor the verdict
    — and nothing depends on having seen it: the refusal that follows a
    failed pull names the image on its own.

    It is deliberately not numbered and not replayed. The events file is
    an *invocation's* replay buffer, and a fetch belongs to no
    invocation: it happens before the session has a build environment at
    all, which is exactly why it is worth watching.
    """

    def relay(line: str) -> None:
        connection.offer(
            {
                "type": protocol.TYPE_EVENT,
                "event": "environment.pulling",
                "session_id": session_id,
                "line": line,
            }
        )

    return relay


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

    **The flag is also what tells the idle clock this is work** — see
    :func:`_is_working` — and the session is touched on the way out for
    the reason the invocation path states about itself: the idle half
    counts absent *commands*, and the command that started this one was
    sent before it ran. A ``send-context`` that spent a hundred seconds
    fetching a build environment would otherwise be acknowledged into a
    session already a minute past its idle timeout, and the very next
    verb — ``lock-context``, the one that freezes what just arrived —
    refused ``session.expired``. Observed exactly so. **Finishing work
    is activity**, whichever kind of work it was.
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
        session.touch()


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

    This verb gives per-layer **replace semantics** (add /
    overwrite / remove) and names no wire shape for any of the three by
    itself; this server settles it as the same archive mechanics as
    ``send-context`` plus a list of paths, both allowed in one call. An
    extension that
    asks for neither is refused rather than answered "nothing changed":
    a client that sent it meant something.

    **Order within one call is removals first, then the archive**, so a
    path named in both ends up as the archive's version. The archive is
    the positive statement of what the context should contain, and a
    client that says "remove X" and "here is X" means the new X. No
    document settles it; this is the determination.

    **It MUST NOT touch ``context.yaml``** — the pins the session was
    admitted on, and changing them is a new session, not an extension.
    A typed error was needed and no code named it, so
    ``context.pins-immutable`` was added to
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
    actually present** and policy is re-run. There is no cost class to
    re-run with it: v1.0 has none.

    Removing a path that is not in the context is not an error. The
    client asked for a state and that state holds — the rule
    ``close-session`` already follows — and the answer says how many of
    the named paths existed, so a typo is still visible.
    """
    session = state.sessions.require(command.require_str("session_id"), connection)
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

    This verb was added to the set, append-only as it requires, to say
    where the session's lifetime and the
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
    write ``manifest.yaml`` — including the build environment this server
    selected for the context's Zephyr line at ``send-context`` —
    compute the context ID, return it, and from here ``verify`` and
    ``build`` are permitted. The selected image is written into the
    manifest and stays out of the ID, so the identity this verb answers
    is a property of the bytes the client sent and of nothing this
    server chose.

    A second ``lock-context`` is ``context.locked``, because the lock is
    one-way: adding a patch after a ``verify`` is a new session, not an
    extension. A ``lock-context`` on a session that never received a
    base context is ``context.missing``.

    **The wire shape is minimal by explicit product-owner choice**
    against a richer alternative:
    the request carries ``session_id`` and nothing else, the response
    carries the context ID and nothing else. The comparison this design
    relies on — both sides comparing values they computed independently —
    therefore happens **on the client**: the workbench computes the ID
    from the bytes it sent, compares it against this answer, and closes
    the session on a disagreement. The consequence is stated here so
    nobody rediscovers it as a gap: this server never sees the client's
    value, so it can never raise that mismatch, and holding the
    workbench to its comparison duty is a requirement on the session
    client rather than on the protocol.

    An empty context may be locked. It has a well-defined ID, and the
    things a ``build`` needs beyond existence — ``keys/signing.pub``
    above all — are checked by ``build``, which is where they belong,
    not by the lock.

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
    session = state.sessions.require(command.require_str("session_id"), connection)
    session.require_writable_context()
    with _context_work(session):
        paths = _require_paths(session)
        if (
            session.pins is None or session.context_yaml_sha256 is None or session.image is None
        ):  # pragma: no cover
            raise SessionError(
                "context.missing",
                f'Session "{session.id}" holds no pins to freeze against.',
                session_id=session.id,
            )
        identity = freeze_context(
            paths,
            session.pins,
            context_yaml_sha256=session.context_yaml_sha256,
        )
        # Kept, because attribution always uses the id this server
        # computed itself: every working invocation is measured against
        # it before it starts, and the result document's own `context`
        # is compared to it when it comes back.
        session.context_id = identity
        session.context_state = CONTEXT_LOCKED
    return {"context_id": identity}


async def _start_working(
    state: Any, connection: Any, command: Command, *, action: str
) -> dict[str, Any]:
    """The shared body of ``verify`` and ``build``.

    One function because the two differ in exactly one thing — what the
    invocation is asked to do — and everything in front of that is
    identical: the same state-machine gates, the same integrity
    re-check, the same lazily materialized environment, the same
    immediate answer.

    **The context is re-measured before every working invocation**
    rather than trusted from the lock (product-owner decision). Contexts
    are small, and what the re-check buys is the one thing the freeze
    cannot: the manifest and the files are compared *now*, so an
    invocation is never attributed to an identity that moved after it
    was answered. A disagreement is ``context.integrity-mismatch``
    naming every offending path, and it ends nothing but the invocation:
    a step builds in a container that is thrown away, so a client that
    fixes its context is fixing something this session never acted on.

    **The answer is the invocation id and nothing else.** A build
    is minutes to hours; a command frame that waited for it would make
    every client's socket a build timer, and a client that lost the
    socket would lose the result of work that is still running. So the
    verb acknowledges and the completion travels as an
    ``invocation.verdict`` event carrying the status and the artifact
    list — on the channel that survives a reconnect, because the
    invocation continues detached and ``attach-session`` re-joins it.
    The verdict is this server's, and the program's own
    ``invocation.finished`` event — numbered like every program
    event — is a different frame that arrives before it.
    """
    session = state.sessions.require(command.require_str("session_id"), connection)
    session.require_locked_context()
    paths = _require_paths(session)
    if session.pins is None or session.context_id is None:  # pragma: no cover - set together
        raise SessionError(
            "context.missing",
            f'Session "{session.id}" has no frozen context to work on.',
            session_id=session.id,
        )
    recheck_locked_context(paths, session.pins, expected_id=session.context_id)
    record = await state.backend.invoke(
        session,
        connection,
        action=action,
        pins=session.pins,
        context_id=session.context_id,
    )
    return {
        "session_id": session.id,
        "invocation_id": record.id,
        "action": action,
        "context_id": session.context_id,
    }


async def verify(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``verify`` — check the effective context against the lock.

    A working command, so it runs **only from the lock onwards** and
    answers ``context.not-locked`` before it. That gate repairs the verb
    rather than restricting it: with mid-session extension allowed, every
    added file would be reported "present but not in the integrity list"
    and the check would fail by construction. ``lock-context`` gives the
    integrity list a defined moment — after the last extension, before
    the first working action — which is what leaves something to check
    against.

    **This server answers it itself, and starts nothing.** Checking a
    context is not an action a build environment has: the orchestrating
    side creates the context, hashes it and delivers it, and the
    environment is forbidden to modify it — so there is nothing an
    environment could confirm that this side does not already know from
    its own bytes. The measurement is the one made before every working
    invocation
    (:func:`~mcuhome.buildserver.contextstore.recheck_locked_context`),
    and it is this verb's whole content.

    So the answers are two. The context is what its lock says it is, and
    the invocation's verdict says ``success`` with no artifacts — there
    is nothing to deliver, and inventing an empty delivery would be a
    second spelling of the verdict. Or it is not, and the verb is refused
    ``context.integrity-mismatch`` naming every offending path, which
    ends the invocation and nothing else: a step builds in a container
    that is thrown away, so a client that fixes its context is fixing
    something this session never acted on.

    Optional even when real: the fast path skips it, and it is not a
    complete integrity check on its own.
    """
    return await _start_working(state, connection, command, action="verify")


#: The two modes the verb accepts. ``clean`` is the default and the one
#: that is always used — an absent ``mode`` means it, and so does
#: ``incremental`` here — because it is the mode that never silently
#: reuses state and the only one a container that starts empty can be.
#: The only mode this server runs, and what the ``build`` verb answers
#: whatever it was asked for: one fresh container per step has nothing to
#: be incremental against.
MODE_CLEAN = "clean"

BUILD_MODES = (MODE_CLEAN, "incremental")


async def build(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``build [mode]`` — clean or incremental.

    The other working command, and the other half of "only from here":
    before the lock it answers ``context.not-locked``, which is also the
    structural reason the verb set could not stay at nine — a client
    that never locks the context can never reach ``build``.

    Payload::

        {"session_id": "s-…", "mode": "clean"}   # mode optional

    ``mode`` is the one parameter and an unknown value is refused here
    rather than passed on — but **every build this server runs is
    clean**, and the answer says so rather than leaving a client to
    assume otherwise. A step runs in a fresh container that is thrown
    away afterwards, which is what makes the pristine tree free and
    leaves nothing for an incremental build to be incremental against;
    answering a clean build is never wrong — it is what was asked for
    plus time — while honouring the word would be a promise nothing
    behind it keeps.

    Every invocation gets a server-assigned invocation id, and it is
    what ``get-artifact`` and ``cancel`` address. It is never named to
    the environment: the request document carries a session and an
    invocation of its own, and the artifacts of a step are found where
    the tree says they are.
    """
    mode = command.optional_str("mode", "clean") or "clean"
    if mode not in BUILD_MODES:
        raise ProtocolError(
            f'"build" takes mode {" or ".join(BUILD_MODES)}, not "{mode}". clean is the '
            "default and the safe one: it never silently reuses state, and it is what a "
            "release artifact requires.",
            frame_id=command.id,
        )
    answer = await _start_working(state, connection, command, action="build")
    # What this server will actually do, which is the only honest thing
    # to answer: a client that asked for `incremental` gets a clean build
    # and is told so here rather than finding out from a build log.
    answer["mode"] = MODE_CLEAN
    return answer


async def cancel(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``cancel(invocation id)`` — stop one invocation, and keep the session.

    It aborts the running invocation and **the session survives** — that
    is the whole promise, and it is why this handler neither closes the
    session nor touches the context state.

    It is a necessity rather than a convenience, for one mechanical
    reason: **a build runs inside a container, and signalling the client
    that started it reaches nothing.** At the protocol level it is the
    deliberate counterpart to ``attach-session``: a running build
    continues detached across a lost connection, and the idle timeout
    counts absent *commands* rather than absent connections — so a closed
    socket can never mean "stop", and cancellation has to be something a
    client *says*.

    The id it addresses is the **server-assigned** invocation id that
    ``build`` hands out. This verb names the operand and no document
    fixes the payload's field name; ``invocation_id`` is the spelling
    this package already uses for the same value at ``get-artifact``.

    The wire shape is deliberate: the answer means
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
      the same answer as the first. Its verdict then says ``cancelled``:
      a stopped step writes no result document, and reporting that as a
      plain failure would hide that the failure was asked for.

    It is deliberately not gated on the lock: only working commands
    produce invocations, and this one stops work rather than doing any.
    What the
    acknowledgement promises is the backend's
    :meth:`~mcuhome.buildserver.backend.SessionBackend.signal_cancellation`:
    the stop sentinel of the running step is raised, and the liveness
    ladder behind it — SIGTERM, then SIGKILL, then the container's
    removal — is what actually ends a build. A signal to the client that
    started the container never was one: the build runs inside it.
    """
    session = state.sessions.require(command.require_str("session_id"), connection)
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
    state.backend.signal_cancellation(session.id, invocation_id)
    return {
        "session_id": session.id,
        "invocation_id": invocation_id,
        "cancelled": True,
        "already_finished": False,
    }


async def get_artifact(state: Any, connection: Any, command: Command) -> None:
    """``get-artifact(invocation id[, path])`` — an archive, announced then streamed.

    Payload::

        {"session_id": "s-…",
         "invocation_id": "inv-1",
         "path": "firmware.hex"}      # optional; absent means all of them

    **The wire shape mirrors the context upload, and the bytes are a
    ``tar.zst``**: one archive format in both directions. With a
    ``path`` the archive holds exactly that declared artifact, without
    one it holds every declared artifact of the invocation under its
    declared path. The result frame **is** the announcement — the
    archive's size and its SHA-256, plus what is in it — and the BINARY
    frames follow it. There is no acknowledgement frame after them for
    the same reason the upload needs one and this does not: the
    receiving side is the client, and it knows the transfer is complete
    when it has taken the announced number of bytes.

    The announced hash is the **archive's**, computed at egress while
    the bytes are read off disk. Per-file integrity stays the client's
    own check against the result document it already holds, which is
    what keeps this hash a transport check rather than a second
    integrity claim that could disagree with the first.

    What is served is the intersection of declared and verified.
    The verification happened when the invocation finished — every
    declared artifact re-hashed from the bytes on disk, paths normalized
    and contained, links, devices and oversized files refused — and it
    **happens again here**, while the archive is packed: the session's
    tree stays writable until ``close-session``, so "was a regular file
    then" is not "is that file now", and an archive gives a client no
    way to notice a member that was swapped in between. A member that no
    longer is what was verified is ``artifact.integrity-mismatch`` and
    the delivery is refused rather than built around it. A path that was
    never offered is ``artifact.unknown`` with the declared paths in its
    details — a different statement, and one about the request.

    **One download at a time per connection**, held over the whole verb.
    The announcement and the bytes behind it are one indivisible
    sequence on the wire, because a BINARY frame carries no id: two
    interleaved downloads leave a client holding chunks it cannot
    attribute. The spool is named uniquely per request as well, so that
    two deliveries can never share a file even if the guard is ever
    taken away.

    **Inside the session and nowhere else.** The per-session directory —
    the context and every artifact in it — is deleted at
    ``close-session``, so download happens after the build and before
    closing. An earlier draft allowed "a
    bounded grace period after close" together with an undefined bound;
    that was removed: nothing said how long, while the directory it kept alive holds a
    device's Matter commissioning credentials.

    Like ``cancel``, it is deliberately not gated on the lock. The flow
    diagram lists it after ``verify``/``build``, but only those two carry
    the "only from here" qualification, and an invocation id can only
    exist because a working command produced one. After a build that
    failed it is the verb that matters most: that is exactly the moment
    its owner wants what the invocation did produce.
    """
    session = state.sessions.require(command.require_str("session_id"), connection)
    invocation_id = command.require_str("invocation_id")
    if invocation_id not in session.invocations:
        raise SessionError(
            "invocation.unknown",
            f'Session "{session.id}" has no invocation "{invocation_id}".',
            session_id=session.id,
            invocation_id=invocation_id,
            known=sorted(session.invocations),
        )
    record = state.backend.record(session.id, invocation_id)
    available = () if record is None else record.artifacts
    wanted = command.optional_str("path")
    if wanted is not None:
        chosen = tuple(entry for entry in available if entry.path == wanted)
        if not chosen:
            raise SessionError(
                "artifact.unknown",
                f'Invocation "{invocation_id}" declared no artifact at "{wanted}". This '
                "server serves exactly the intersection of what the build declared and "
                "what it could verify from the bytes on disk; the paths it did declare "
                "are in the details.",
                session_id=session.id,
                invocation_id=invocation_id,
                path=wanted,
                declared=[entry.path for entry in available],
            )
    else:
        chosen = available

    paths = _require_paths(session)
    spool = paths.downloads / f"{invocation_id}-{uuid.uuid4().hex}.tar.zst"
    spool.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    async with connection.download_lock:
        try:
            # Off the event loop: this tars and zstd-compresses every
            # artifact of a build and then re-reads the spool to hash
            # it. On the loop it would stall every other session and
            # every other connection for the length of a firmware set.
            delivery = await asyncio.to_thread(
                artifacts.build_archive,
                out=record.out if record is not None else paths.downloads,
                artifacts=chosen,
                spool=spool,
            )
            await connection.send(
                protocol.result_frame(
                    command.id,
                    {
                        "session_id": session.id,
                        "invocation_id": invocation_id,
                        "archive": {"size": delivery.size, "sha256": delivery.sha256},
                        "artifacts": [entry.to_dict() for entry in delivery.members],
                    },
                )
            )
            await connection.send_archive(spool)
        finally:
            # The archive is a rendering of what is already on disk, so
            # it is rebuilt on the next request rather than kept:
            # keeping it would double the footprint of every artifact a
            # client asks for, inside a per-session quota that is there
            # to be bounded.
            spool.unlink(missing_ok=True)
    return None


async def attach_session(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``attach-session`` — connection loss is not abandonment.

    Payload::

        {"session_id": "s-…",
         "invocation_id": "inv-1",     # optional: replay this one's events
         "from_seq": 12}               # optional: from here on, default 1

    Answers the session record and its lease: a reconnecting client
    learns its session survived, and the record says where the context
    stands, which is what tells the client whether it still has to lock.
    Permitted in **any** context state — it is the read-only
    reconnection verb, and no document restricts it to one side of the
    lock.

    **Two things happen beyond the record, and both are what makes the
    verb worth having.** The connection re-joins the session's live
    stream, so an invocation that has been running detached starts
    reaching this socket again. And, if the client names an invocation,
    its events are replayed from the sequence number the client last
    saw — read straight out of the NDJSON file the program wrote, which
    stays on disk for the life of the session and **is** the replay
    buffer. There is no in-memory ring behind it, so there is
    nothing a long reconnect can find already evicted.

    The replayed events go out **before** this verb's own result frame,
    which is what lets a client treat the boundary as a boundary: every
    event frame it sees before the answer is history, and everything
    after it is live.

    **That is an ordering claim, so the replay finishes before the
    connection joins the live stream.** Attaching first and reading
    afterwards put live frames *inside* the region the verb calls
    history — every ``await`` in the replay loop is a turn for the
    supervisor that is relaying an invocation still running, which is
    the exact situation this verb exists for — and delivered an event
    twice when the relay overtook the reader. So: read the file to
    exhaustion, send it, and only then join, telling the backend which
    ``seq`` of which invocation was the last thing already delivered.
    Events at or below that boundary are not relayed to this connection
    a second time; everything after it is live, which is what the client
    was promised.

    Only events replay. The raw log is not written to disk by this
    server and is not replayable — it is a "raw, opaque log stream"
    consumers must not parse for machine decisions, and its own counter
    is what tells a client it missed lines.
    """
    session = state.sessions.require(command.require_str("session_id"), connection)
    replayed = 0
    boundary: tuple[str, int] | None = None
    invocation_id = command.optional_str("invocation_id")
    if invocation_id is not None:
        record = state.backend.record(session.id, invocation_id)
        if record is None:
            raise SessionError(
                "invocation.unknown",
                f'Session "{session.id}" has no invocation "{invocation_id}" to replay.',
                session_id=session.id,
                invocation_id=invocation_id,
                known=sorted(session.invocations),
            )
        from_seq = command.optional_int("from_seq", 1) or 1
        sent_upto = from_seq - 1
        # Bounded passes rather than "until it stops growing": the file
        # of a running invocation may never stop growing, and a verb
        # that replayed until it did would never answer.
        for _ in range(_REPLAY_PASSES):
            fresh = events.replay(record.events, from_seq=sent_upto + 1)
            if not fresh:
                break
            for line in fresh:
                payload = dict(line)
                payload["session_id"] = session.id
                payload["invocation_id"] = invocation_id
                await connection.send(protocol.event_frame(str(line["event"]), payload))
                replayed += 1
            sent_upto = _last_seq(fresh, sent_upto)
        if replayed:
            boundary = (invocation_id, sent_upto)
    state.backend.attach(session.id, connection, boundary=boundary)
    return {
        "session": session.to_dict(),
        "lease": session.lease_dict(),
        "replayed": replayed,
    }


#: How many times ``attach-session`` re-reads the events file before it
#: joins the live stream. More than one because the first pass takes
#: time and a running program appends during it; bounded because a
#: program that appends faster than the file is read would otherwise
#: hold the verb open forever.
_REPLAY_PASSES = 4


def _last_seq(lines: tuple[dict[str, Any], ...], fallback: int) -> int:
    """The highest ``seq`` in *lines*, or *fallback*.

    §8 makes ``seq`` monotonic and nothing more, and an event whose
    ``seq`` is unreadable is relayed rather than dropped — so the
    boundary is the largest number actually seen and never the count of
    lines.
    """
    found = [
        line["seq"]
        for line in lines
        if isinstance(line.get("seq"), int) and not isinstance(line.get("seq"), bool)
    ]
    return max(found) if found else fallback


async def close_session(state: Any, connection: Any, command: Command) -> dict[str, Any]:
    """``close-session`` — release the session and reap its container.

    Four things go, **in this order**, and the order is the whole of
    what this verb guarantees.

    1. The stop signal is set for every running invocation. It is
       best-effort: the supervising loop looks at it on its own
       schedule, and nothing here waits for it to notice.
    2. The container is removed, ``--force``. That is the kill — a build
       runs inside it, so nothing outside it stops one.
    3. The invocation is **waited for**: its supervisor holds a worker
       thread, and that thread is what would otherwise still be reading
       the directory the next step deletes. Removing the container ends
       the program it supervises, so this is a moment in the normal
       case; it is bounded by the liveness ladder for the case where it
       is not.
    4. The per-session directory is deleted, with the context and every
       artifact in it, which is why ``get-artifact`` has to run before
       this.

    Deleting the tree *before* removing the container was the order this
    verb had, and it was wrong in the one way that matters: it pulls the
    mount source out from under a program that is still running in it.
    Deleting it before the supervisor came back was the same mistake one
    layer up — the container was gone, but the thread driving it was
    still there, and the suite met that as a process which passed every
    test and then would not exit.

    **A supervisor that outlives its own ladder is refused, not ignored.**
    If the wait runs out, the session stays closed, its directory is
    kept, and the client is told so instead of being handed an answer
    that says the session's files are gone while a thread is still in
    them. The code is the pre-registry ``internal_error``: nothing in
    the typed registry means "this server could not stop its own build",
    and minting a code for it is a protocol decision rather than an
    implementation choice — the same reason ``build``'s
    one-invocation-at-a-time guard gives for its own pre-registry
    refusal.

    **The retry is this server's own** and the message says so. The
    session stays on the manager's release list and every sweep tries it
    again until it succeeds; no promise is made about *when*, because
    there is none to make — a sweep runs every
    :data:`DEFAULT_REAP_INTERVAL` seconds and each attempt may spend the
    ladder again. What is promised is that it keeps trying, and it has
    to be this server's job: a client cannot be relied on to ask twice —
    the workbench's own session client forgets its session id in a
    ``finally`` as it closes and would have nothing left to name — and a
    container left running on a server nobody asks again is not
    something a client's manners should decide.

    **The client gets no result for an implicitly cancelled invocation,**
    and this verb no longer promises one survives. The guarantee
    that the result document is still written orders the *program's*
    shutdown — it is not a deliverable, and there is nowhere left to
    deliver it to.

    Permitted in any context state; the lock does not gate the way out.
    """
    session_id = command.require_str("session_id")
    session = state.sessions.close(session_id)
    if not await release_session(state, session_id):
        raise ProtocolError(
            f'This server could not stop the build of session "{session_id}" yet and kept '
            "its files instead of deleting them underneath it. Nothing is left for you to "
            "do: this server keeps retrying the cleanup by itself until it succeeds.",
            code=protocol.ERROR_INTERNAL,
            frame_id=command.id,
            session_id=session_id,
        )
    return {"session": session.to_dict()}


#: The verb table. The ``/ws`` command table is derived from this one
#: (``ws.COMMANDS = dict(SESSION_VERBS)``), so an entry here is the
#: whole registration — there is no second list to keep in step.
#: Hyphenated names as in the concept.
#:
#: **Eleven**, the complete verb set as amended on 2026-08-09.
#: ``lock-context`` and ``cancel`` were the two missing, and neither is
#: optional: without ``lock-context`` a client can never reach
#: ``build``, and without ``cancel`` a closed socket would be the only
#: stop signal a client had — which is no stop signal at all, because a
#: build runs inside a container and nothing outside it stops one.
#: The verbs whose body arrives as BINARY frames after the JSON that
#: announced it. The transport needs this and cannot derive it: a
#: binary frame carries no id, so the reader has to know **before** it
#: reads on that the command it just spawned is about to claim the next
#: frames — see :meth:`~mcuhome.buildserver.ws.Connection.await_announcement`.
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
