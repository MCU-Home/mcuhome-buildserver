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

from mcuhome_buildserver import errors, sessions
from mcuhome_buildserver.app import ServerState, create_app
from mcuhome_buildserver.errors import SessionError
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


def test_waiting_costs_no_lease() -> None:
    """A seat is not a session: the lease begins at admission.

    A client that waited five hours starts with a full one.
    """
    manager = _full()
    seat = _refused(manager).details["seat"]
    _slots_free(manager)
    admitted = _open(manager, seat)
    assert admitted.expires_at - admitted.created_at == pytest.approx(manager.ttl)
