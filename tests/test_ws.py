# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The ``/ws`` transport itself: the outbox, the refusals, the teardown.

Dashboard ADR 0012 decision 3 carries the transport of ADR 0006 forward
unchanged while replacing its vocabulary, so these properties outlived
the job protocol that used to exercise them: the drop-oldest outbox was
covered only through ``job_output`` events, and the disconnect teardown
only through ``follow_job``. They are asserted directly here instead.
"""

from __future__ import annotations

import asyncio

from mcuhome_buildserver.ws import OUTBOX_LIMIT, Connection
from tests.conftest import auth, call


async def test_the_outbox_drops_the_oldest_frame_rather_than_blocking() -> None:
    """``offer`` never awaits and never raises.

    It is called from the middle of streaming a build's output, so a
    client that stopped reading must not apply backpressure back into
    the thing producing the bytes. The frame that is lost is the oldest
    one, because the newest is the one the client still needs.
    """
    connection = Connection(ws=None)  # type: ignore[arg-type]
    for index in range(OUTBOX_LIMIT + 5):
        connection.offer({"seq": index})

    assert connection.dropped == 5
    first = connection._outbox.get_nowait()
    assert first["seq"] == 5, "the oldest frames go, not the newest"


async def test_a_binary_frame_is_refused_and_the_connection_survives(client) -> None:
    """This endpoint speaks JSON text frames only.

    The refusal is what keeps :data:`~mcuhome_buildserver.protocol.ERROR_BAD_REQUEST`
    load-bearing: the session protocol's error registry has no code for a
    frame that never parsed, so a malformed *frame* is answered in the
    envelope's own vocabulary rather than the session layer's.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await ws.send_bytes(b"\x00\x01\x02")
        frame = await ws.receive_json(timeout=15)
        assert frame["type"] == "error"
        assert frame["error"]["code"] == "bad_request"

        # The connection is still usable: one bad frame is not a session.
        answer = await call(ws, "capabilities")
        assert answer["type"] == "result"


async def test_a_frame_that_is_not_json_is_refused_typed(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await ws.send_str("{not json")
        frame = await ws.receive_json(timeout=15)
    assert frame["error"]["code"] == "bad_request"


async def test_a_closed_connection_is_forgotten(client, state) -> None:
    """Disconnect teardown: the connection leaves the broadcast set.

    The set is what any server-initiated frame iterates, so a connection
    that outlived its socket would be an unbounded leak and a write to a
    closed transport on every push.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        await call(ws, "capabilities")
        assert len(state.connections) == 1

    for _ in range(200):
        if not state.connections:
            break
        await asyncio.sleep(0.01)
    assert state.connections == set()
