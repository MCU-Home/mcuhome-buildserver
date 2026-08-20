# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The waiting room in front of admission: seat tokens and whose turn it is.

A client refused for want of capacity is handed a seat token and a time
to come back, presents the token on its next ``open-session``, and is
either admitted or told to wait again with the same token. Two
properties carry the whole design and both are pinned here: **a freed
slot belongs to the head of the queue**, and **the wire never says
where anybody stands**.
"""

from __future__ import annotations

import time
from dataclasses import replace

import pytest

from mcuhome.buildserver import errors, sessions
from mcuhome.buildserver.app import ServerState, create_app
from mcuhome.buildserver.errors import SessionError
from tests.conftest import auth, call


def _open(manager: sessions.SessionManager, seat: str | None = None) -> sessions.Session:
    return manager.open(
        profile="oneshot",
        protocol_version=sessions.SESSION_PROTOCOL_VERSION,
        context_format=sessions.CONTEXT_FORMAT_MAX,
        seat=seat,
    )


def _refused(manager: sessions.SessionManager, seat: str | None = None) -> SessionError:
    with pytest.raises(SessionError) as excinfo:
        _open(manager, seat)
    return excinfo.value


def _slots_free(manager: sessions.SessionManager) -> None:
    """Every sitting session's lease runs out. The reaper notices."""
    manager.reap(now=time.time() + manager.ttl + 1.0)
    assert manager.open_count == 0


def _full(max_open: int = 1, **seat_options: float | int) -> sessions.SessionManager:
    """A manager with every admission slot taken."""
    manager = sessions.SessionManager(
        max_open=max_open,
        seats=sessions.SeatQueue(**seat_options),  # type: ignore[arg-type]
    )
    for _ in range(max_open):
        _open(manager)
    return manager


# --------------------------------------------------------------------------
# The refusal, and what it promises
# --------------------------------------------------------------------------


def test_a_refusal_hands_out_a_seat_and_a_time_to_come_back() -> None:
    refusal = _refused(_full())
    assert refusal.code == "session.limit-exceeded"
    assert errors.REGISTRY["session.limit-exceeded"].retryable is True
    assert refusal.details["seat"].startswith("seat-")
    assert refusal.details["retry_after_seconds"] == 60


def test_the_wire_never_says_where_anybody_stands() -> None:
    """Order is kept, and is not the protocol's to promise.

    Seats are served in arrival order today; a later version with tariff
    tiers admits a paying client ahead of a free one, and a protocol that
    had published "you are second" would have become a lie the moment
    that shipped. What a client can act on is when to come back.
    """
    manager = _full()
    for _ in range(3):
        refusal = _refused(manager)
    assert set(refusal.details) == {"max_open", "seat", "retry_after_seconds"}


def test_the_wait_grows_with_the_position_and_is_capped() -> None:
    manager = _full(retry_seconds=60.0, retry_max_seconds=150.0)
    waits = [_refused(manager).details["retry_after_seconds"] for _ in range(4)]
    assert waits == [60, 120, 150, 150]


# --------------------------------------------------------------------------
# Presenting a seat
# --------------------------------------------------------------------------


def test_a_seat_gets_in_when_a_slot_frees_and_is_spent_doing_so() -> None:
    manager = _full()
    seat = _refused(manager).details["seat"]
    _slots_free(manager)
    admitted = _open(manager, seat)
    assert admitted.state == sessions.STATE_OPEN
    # And that session now holds the only slot, so the very same token
    # presented again is spent: it stood for one turn, not for a standing
    # right to jump the queue.
    replayed = _refused(manager, seat)
    assert replayed.details["seat"] != seat


def test_a_token_this_server_does_not_hold_is_a_walk_in_not_an_error() -> None:
    """Never issued, long expired, already spent, invented — all one answer.

    Telling them apart would let anyone probe which tokens once existed,
    and all four mean the same thing: this caller has no turn.
    """
    manager = _full()
    refusal = _refused(manager, "seat-nothing-like-this-was-ever-issued")
    assert refusal.code == "session.limit-exceeded"
    assert refusal.details["seat"].startswith("seat-")
    assert len(manager.seats) == 1


def test_presenting_a_seat_re_times_it_at_its_current_position() -> None:
    """Promotion corrects an appointment made further back.

    A seat told 180 seconds at position 3 can reach the head with that
    much still to run — which is the idle capacity the head reservation
    costs. It corrects itself at that seat's very next poll.
    """
    manager = _full(retry_seconds=60.0)
    first = _refused(manager).details["seat"]
    second = _refused(manager).details["seat"]
    third = _refused(manager)
    assert third.details["retry_after_seconds"] == 180

    manager.seats.release(manager.seats.position(first) or 0)
    manager.seats.release(manager.seats.position(second) or 0)
    again = _refused(manager, third.details["seat"])
    assert again.details["seat"] == third.details["seat"]
    assert again.details["retry_after_seconds"] == 60


# --------------------------------------------------------------------------
# The head reservation — the guarantee the queue exists for
# --------------------------------------------------------------------------


def test_a_freed_slot_is_held_for_the_head_and_a_walk_in_is_turned_away() -> None:
    """Without this, "you are first" means nothing.

    The client that happens to be dialling in that microsecond wins, and
    a queue that does not decide who gets the next turn is not a queue.
    """
    manager = _full()
    waiting = _refused(manager).details["seat"]
    _slots_free(manager)

    walk_in = _refused(manager)
    assert walk_in.details["seat"] != waiting
    assert _open(manager, waiting).state == sessions.STATE_OPEN


def test_the_reservation_is_one_slot_and_is_not_held_against_the_head() -> None:
    manager = _full(max_open=3)
    head = _refused(manager).details["seat"]
    behind = _refused(manager).details["seat"]
    _slots_free(manager)

    # Two free, one held for the head: a seat further back may still be
    # lucky, and the head is never made to wait for its own reservation.
    assert _open(manager, behind).state == sessions.STATE_OPEN
    assert _open(manager, head).state == sessions.STATE_OPEN


def test_a_seat_that_misses_its_appointment_loses_its_place() -> None:
    manager = _full(retry_seconds=60.0)
    missed = _refused(manager).details["seat"]
    next_in_line = _refused(manager).details["seat"]

    # Its own appointment plus the grace, and one second more.
    manager.seats.sweep(_expiry_of(manager, missed) + 1.0)
    assert manager.seats.position(missed) is None
    assert manager.seats.position(next_in_line) == 1


def _expiry_of(manager: sessions.SessionManager, token: str) -> float:
    position = manager.seats.position(token)
    assert position is not None
    return manager.seats._seats[position - 1].expires_at


# --------------------------------------------------------------------------
# Refusing without promising
# --------------------------------------------------------------------------


def test_a_full_waiting_room_refuses_without_issuing_a_turn() -> None:
    """The counterpart refusal, and the difference is a promise.

    ``session.limit-exceeded`` hands out a seat and is therefore an
    undertaking to serve this caller in its turn; this one makes no such
    undertaking and says why in ``details.reason``. The branch exists
    now so that a per-client seat quota — which needs an identity this
    server does not have — adds a reason and not a wire format.
    """
    manager = _full(max_seats=2)
    _refused(manager)
    _refused(manager)
    refusal = _refused(manager)
    assert refusal.code == "session.no-seat"
    assert errors.REGISTRY["session.no-seat"].retryable is True
    assert refusal.details["reason"] == "queue-full"
    assert "seat" not in refusal.details


def test_a_held_seat_is_re_timed_even_when_the_waiting_room_is_full() -> None:
    """Re-timing does not grow the queue, so it cannot be refused by its size."""
    manager = _full(max_seats=1)
    held = _refused(manager).details["seat"]
    again = _refused(manager, held)
    assert again.code == "session.limit-exceeded"
    assert again.details["seat"] == held


# --------------------------------------------------------------------------
# What a seat is not
# --------------------------------------------------------------------------


def test_a_request_this_server_cannot_serve_gets_no_seat_at_all() -> None:
    """Admission checks the three operands first.

    A place in a queue for a session that would be refused on arrival is
    a turn nobody can use.
    """
    manager = _full()
    with pytest.raises(SessionError) as excinfo:
        manager.open(
            profile="oneshot",
            protocol_version=sessions.SESSION_PROTOCOL_VERSION + 1,
            context_format=sessions.CONTEXT_FORMAT_MAX,
        )
    assert excinfo.value.code == "version.protocol-mismatch"
    assert len(manager.seats) == 0


async def test_the_seat_makes_the_round_trip_over_the_wire(aiohttp_client, config) -> None:
    """Out in the refusal's details, back in the next payload.

    Additive on both ends: a server that does not know seats ignores the
    field, and a client only ever sends a token a server gave it — which
    is why this moves no protocol version and why the refusal keeps the
    code it always had.
    """
    state = ServerState(replace(config, max_sessions=1))
    client = await aiohttp_client(create_app(state))
    payload = {"protocol_version": sessions.SESSION_PROTOCOL_VERSION}

    async with client.ws_connect("/ws", headers=auth()) as ws:
        first = await call(ws, "open-session", payload, frame_id="a")
        assert first["type"] == "result"

        refused = await call(ws, "open-session", payload, frame_id="b")
        assert refused["error"]["code"] == "session.limit-exceeded"
        seat = refused["error"]["details"]["seat"]
        assert refused["error"]["details"]["retry_after_seconds"] > 0

        state.sessions.reap(now=time.time() + state.sessions.ttl + 1.0)
        admitted = await call(ws, "open-session", {**payload, "seat": seat}, frame_id="c")
        assert admitted["type"] == "result"
        assert len(state.sessions.seats) == 0


# --------------------------------------------------------------------------
# The handover: a session nobody is attached to does not outrank a client
# --------------------------------------------------------------------------


def _unattended(manager: sessions.SessionManager, quiet_for: float = 300.0) -> sessions.Session:
    """A session whose client opened it and was never heard from again."""
    session = _open(manager)
    connection = object()
    manager.attach(session, connection)
    session.touch(now=time.time() - quiet_for)
    manager.detach(connection, now=time.time() - quiet_for)
    return session


def test_a_session_nobody_is_attached_to_is_handed_to_a_client_that_is_waiting() -> None:
    """The measured case: with one slot, an abandoned session was the server.

    A client that dies without closing its session holds it for the full
    idle timeout, because connection loss is never abandonment. That
    stays true — with nobody waiting nothing happens here — but it stops
    being unconditional.
    """
    manager = sessions.SessionManager(max_open=1)
    abandoned = _unattended(manager)

    admitted = _open(manager)

    assert admitted.state == sessions.STATE_OPEN
    assert abandoned.state == sessions.STATE_CLOSED
    assert abandoned.reaped == sessions.GONE_HANDOVER
    # And the build environment is handed to whoever can remove it.
    assert manager.take_released() == (abandoned.id,)
    assert manager.take_released() == ()


def test_a_room_with_space_never_takes_an_idle_session() -> None:
    """Scarcity is the whole justification.

    With a free slot there is no client whose wait the idle session is
    paying for, and taking it would break a lease this server gave for
    nothing.
    """
    manager = sessions.SessionManager(max_open=2)
    idle = _unattended(manager)

    assert _open(manager).state == sessions.STATE_OPEN
    assert idle.state == sessions.STATE_OPEN
    assert manager.take_released() == ()


def test_a_client_on_the_socket_keeps_its_session_however_long_it_is_quiet() -> None:
    """Attached is attached. A dev session is allowed to think.

    The idle timeout is out of the way here on purpose: this is the
    handover rule alone, and a session quiet for an hour under the
    default lease is the reaper's business, not admission's.
    """
    manager = sessions.SessionManager(max_open=1, idle_timeout=7200.0)
    session = _open(manager)
    manager.attach(session, object())
    session.touch(now=time.time() - 3600.0)

    assert _refused(manager).code == "session.limit-exceeded"
    assert session.state == sessions.STATE_OPEN


def test_a_build_that_is_running_detached_keeps_its_session() -> None:
    """Work is not idleness — the same rule the idle timeout follows.

    A client that starts a build and drops its socket is the case
    ``attach-session`` exists for, and it must survive a queue forming
    behind it.
    """
    manager = sessions.SessionManager(max_open=1)
    building = _unattended(manager)
    building.invocations["inv-1"] = sessions.INVOCATION_RUNNING

    assert _refused(manager).code == "session.limit-exceeded"
    assert building.state == sessions.STATE_OPEN


def test_a_context_command_in_flight_keeps_its_session_too() -> None:
    """The same rule, for the other long command.

    A ``send-context`` that is fetching the build environment its context
    pinned takes minutes, and the handover would take the *directory* it
    is unpacking into with it — worse than the reaper's version of the
    same mistake, because the work is still arriving.
    """
    manager = sessions.SessionManager(max_open=1)
    fetching = _unattended(manager)
    fetching.context_busy = True

    assert _refused(manager).code == "session.limit-exceeded"
    assert fetching.state == sessions.STATE_OPEN


def test_the_grace_is_the_time_a_client_has_to_come_back() -> None:
    manager = sessions.SessionManager(max_open=1, reconnect_grace=60.0)
    dropped = _unattended(manager, quiet_for=30.0)

    seat = _refused(manager).details["seat"]
    assert dropped.state == sessions.STATE_OPEN

    # A second past it, and the client that is waiting has the better claim.
    dropped.touch(now=time.time() - 61.0)
    dropped.disconnected_since = time.time() - 61.0
    assert _open(manager, seat).state == sessions.STATE_OPEN
    assert dropped.reaped == sessions.GONE_HANDOVER


def test_the_clock_runs_from_whichever_came_last() -> None:
    """Quiet and disconnected are two ways of being unattended.

    A client that goes quiet and *then* loses its socket has not been
    unattended for the length of its silence.
    """
    manager = sessions.SessionManager(max_open=1, idle_timeout=7200.0, reconnect_grace=60.0)
    session = _open(manager)
    connection = object()
    manager.attach(session, connection)
    session.touch(now=time.time() - 3600.0)
    manager.detach(connection, now=time.time() - 10.0)

    assert _refused(manager).code == "session.limit-exceeded"
    assert session.state == sessions.STATE_OPEN


def test_a_client_that_reconnected_without_attach_session_counts_as_attached() -> None:
    """``attach-session`` re-joins the event stream; it is not a check-in.

    A client that reconnects and simply carries on — send-context on a
    fresh socket — is driving its session, and a long upload must not
    look unattended while it runs.
    """
    manager = sessions.SessionManager(max_open=1, reconnect_grace=0.0)
    session = _unattended(manager)
    manager.require(session.id, object())

    assert _refused(manager).code == "session.limit-exceeded"
    assert session.state == sessions.STATE_OPEN


def test_the_longest_unattended_session_goes_first() -> None:
    manager = sessions.SessionManager(max_open=2, idle_timeout=7200.0)
    older = _unattended(manager, quiet_for=900.0)
    newer = _unattended(manager, quiet_for=300.0)

    _open(manager)

    assert older.reaped == sessions.GONE_HANDOVER
    assert newer.state == sessions.STATE_OPEN


def test_the_handover_takes_the_directory_with_it() -> None:
    """It holds a device's commissioning credentials, like every reaping does."""
    manager = sessions.SessionManager(max_open=1)
    abandoned = _unattended(manager)
    abandoned.context_state = sessions.CONTEXT_LOCKED

    _open(manager)

    assert abandoned.context_state == sessions.CONTEXT_NONE


def test_a_handed_over_session_says_so_when_its_client_comes_back() -> None:
    """Different news from a lease that ran out, so a different sentence."""
    manager = sessions.SessionManager(max_open=1)
    abandoned = _unattended(manager)
    _open(manager)

    with pytest.raises(SessionError) as excinfo:
        manager.require(abandoned.id)
    assert excinfo.value.code == "session.expired"
    assert "waiting for a turn" in excinfo.value.message
    assert "outlived" not in excinfo.value.message


def test_a_slot_a_walk_in_frees_still_belongs_to_the_head() -> None:
    """The two rules compose, and the order is: free it, then hold it.

    A walk-in may hand an unattended session over and still be refused,
    which is why the release is drained even when admission says no.
    """
    manager = sessions.SessionManager(max_open=1)
    abandoned = _open(manager)
    connection = object()
    manager.attach(abandoned, connection)
    # The head queues while the session still has its client…
    waiting = _refused(manager).details["seat"]
    # …and that client is gone by the time the next one dials in.
    abandoned.touch(now=time.time() - 300.0)
    manager.detach(connection, now=time.time() - 300.0)

    walk_in = _refused(manager)

    assert walk_in.details["seat"] != waiting
    assert abandoned.reaped == sessions.GONE_HANDOVER
    assert manager.take_released() == (abandoned.id,)
    assert _open(manager, waiting).state == sessions.STATE_OPEN


async def test_the_handover_reaches_the_backend_over_the_wire(aiohttp_client, config) -> None:
    """Marking is admission's; removing the build environment is not.

    Admission runs inside one command and cannot wait for a container to
    go away, so ``open-session`` drains what it marked — and the sweep is
    the backstop behind it.
    """
    state = ServerState(replace(config, max_sessions=1, reconnect_grace_seconds=1))
    released: list[tuple[str, str | None]] = []
    original = state.backend.release

    async def record(session_id: str, *, reaped: str | None = None) -> None:
        released.append((session_id, reaped))
        await original(session_id, reaped=reaped)

    state.backend.release = record  # type: ignore[method-assign]
    client = await aiohttp_client(create_app(state))
    payload = {"protocol_version": sessions.SESSION_PROTOCOL_VERSION}

    async with client.ws_connect("/ws", headers=auth()) as ws:
        first = await call(ws, "open-session", payload, frame_id="a")
        abandoned = first["payload"]["session"]["id"]

    # The socket is gone and the session has been quiet since before the
    # grace, so the next client to ask has the better claim.
    session = state.sessions.require(abandoned)
    session.touch(now=time.time() - 60.0)
    session.disconnected_since = time.time() - 60.0

    async with client.ws_connect("/ws", headers=auth()) as ws:
        second = await call(ws, "open-session", payload, frame_id="b")
        assert second["type"] == "result"

    assert released == [(abandoned, sessions.GONE_HANDOVER)]


def test_waiting_costs_no_lease() -> None:
    """A seat is not a session: the lease begins at admission.

    A client that waited five hours starts with a full one.
    """
    manager = _full()
    seat = _refused(manager).details["seat"]
    _slots_free(manager)
    admitted = _open(manager, seat)
    assert admitted.expires_at - admitted.created_at == pytest.approx(manager.ttl)
