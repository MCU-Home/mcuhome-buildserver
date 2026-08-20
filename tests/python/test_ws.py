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
from dataclasses import replace

from aiohttp import WSCloseCode

from mcuhome.buildserver import protocol
from mcuhome.buildserver import ws as ws_module
from mcuhome.buildserver.app import ServerState, create_app
from mcuhome.buildserver.protocol import Command
from mcuhome.buildserver.ws import OUTBOX_LIMIT, Connection
from tests.python.conftest import auth, call


def _log(seq: int) -> dict:
    return protocol.log_frame({"seq": seq, "line": f"line {seq}"})


async def test_the_outbox_drops_the_oldest_frame_rather_than_blocking() -> None:
    """``offer`` never awaits and never raises.

    It is called from the middle of streaming a build's output, so a
    client that stopped reading must not apply backpressure back into
    the thing producing the bytes. The frame that is lost is the oldest
    one, because the newest is the one the client still needs.
    """
    connection = Connection(ws=None)  # type: ignore[arg-type]
    for index in range(OUTBOX_LIMIT + 5):
        connection.offer(_log(index))

    assert connection.dropped == 5
    first = connection._outbox.popleft()
    assert first["payload"]["seq"] == 5, "the oldest frames go, not the newest"


async def test_a_queued_download_chunk_is_never_evicted_by_a_log_line() -> None:
    """The corruption ``send_bytes`` says it avoids, in the one place it
    was still reachable.

    "Dropping a chunk of an archive does not degrade it, it corrupts
    it" — and that governed how a chunk is *enqueued*, not how it is
    *evicted*. A type-blind drop-the-oldest policy took the head of the
    queue whatever it was, so a log line arriving during a download
    silently removed a chunk of somebody's firmware archive and the
    client found out from a hash that did not match.
    """
    connection = Connection(ws=None)  # type: ignore[arg-type]
    for index in range(OUTBOX_LIMIT - 1):
        await connection.send_bytes(f"chunk-{index}".encode())
    connection.offer(_log(1))
    assert len(connection._outbox) == OUTBOX_LIMIT

    connection.offer(_log(2))
    assert connection.dropped == 1
    assert connection._outbox[0] == b"chunk-0", "the chunk at the head survived"
    assert sum(1 for frame in connection._outbox if isinstance(frame, bytes)) == OUTBOX_LIMIT - 1
    assert connection.overloaded is False


async def test_an_outbox_of_nothing_but_undroppable_frames_closes_the_connection() -> None:
    """A client that stopped reading mid-download cannot be served.

    There is no frame to throw away — every one of them is a chunk whose
    loss corrupts the archive — and no honest way to continue, so the
    connection is closed typed instead of quietly delivering an archive
    that will not hash.
    """
    connection = Connection(ws=None)  # type: ignore[arg-type]
    for index in range(OUTBOX_LIMIT):
        await connection.send_bytes(f"chunk-{index}".encode())

    connection.offer(_log(1))
    assert connection.overloaded is True
    assert len(connection._outbox) == OUTBOX_LIMIT
    await connection.close()


async def test_the_verdict_frame_is_not_evicted_to_make_room_for_a_log_line() -> None:
    """E46's one frame with no second way to be learned.

    ``invocation.verdict`` is queued with :meth:`Connection.send` for
    exactly that reason — and being queued said nothing about being
    kept, because the eviction policy looked at the queue rather than at
    the frame. Since E58 it is the *name* the policy protects, and it
    protects only this server's verdict: the program's own
    ``invocation.finished`` is a line in the events file and survives a
    drop, which is what makes every other event droppable.
    """
    connection = Connection(ws=None)  # type: ignore[arg-type]
    await connection.send(protocol.event_frame("invocation.verdict", {"status": "success"}))
    for index in range(OUTBOX_LIMIT - 1):
        connection.offer(_log(index))
    connection.offer(_log(999))

    assert connection.dropped == 1
    assert connection._outbox[0]["event"] == "invocation.verdict"


async def test_a_binary_frame_is_refused_and_the_connection_survives(client) -> None:
    """This endpoint speaks JSON text frames only.

    The refusal is what keeps :data:`~mcuhome.buildserver.protocol.ERROR_BAD_REQUEST`
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


async def test_a_deeply_nested_json_frame_is_refused_and_the_connection_survives(client) -> None:
    """A hostile deep-JSON frame is a typed refusal, not a torn connection.

    ``json.loads`` overruns the interpreter's recursion limit on
    ``[[[[…]]]]`` and raises ``RecursionError`` — which is a
    ``RuntimeError``, not a ``ValueError``, so before the guard was
    broadened it escaped ``decode``, propagated out of the read loop and
    tore the connection down over one frame. Now it becomes the same
    ``bad_request`` any other unparseable frame gets, and the connection
    is still usable afterwards.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        depth = 20000  # far past any default recursion limit; the frame stays tiny
        await ws.send_str("[" * depth + "]" * depth)
        frame = await ws.receive_json(timeout=15)
        assert frame["type"] == "error"
        assert frame["error"]["code"] == "bad_request"

        # One bad frame is not a session: the connection still answers.
        answer = await call(ws, "capabilities")
        assert answer["type"] == "result"


async def test_the_connection_cap_refuses_a_further_upgrade(aiohttp_client, config) -> None:
    """Past ``max_connections`` the upgrade is turned away, not served.

    ``state.connections`` is otherwise unbounded, so a token holder could
    open sockets without limit. Hardening rather than a boundary (the
    token equals shell): the caller past the cap did nothing wrong, so
    the socket is prepared and then closed with TRY_AGAIN_LATER — come
    back — and never joins the broadcast set.
    """
    state = ServerState(replace(config, max_connections=1))
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as first:
        await call(first, "capabilities")
        assert len(state.connections) == 1

        second = await client.ws_connect("/ws", headers=auth())
        # The server prepared the socket and closed it straight away;
        # draining it yields the close and its code.
        await second.receive(timeout=15)
        assert second.close_code == WSCloseCode.TRY_AGAIN_LATER
        # The refused connection never joined the set it was refused for.
        assert len(state.connections) == 1
        await second.close()


async def test_a_connection_bounds_its_in_flight_commands(monkeypatch) -> None:
    """One connection runs at most ``max_inflight`` command handlers at once.

    The bound is held around the handler dispatch, so a flood of TEXT
    frames on one connection cannot accumulate unbounded running handlers.
    A blocking test handler makes the ceiling observable: six commands are
    spawned, only ``max_inflight`` ever run together.
    """
    running = 0
    peak = 0
    gate = asyncio.Event()

    async def slow(state, connection, command):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        try:
            await gate.wait()
            return {"ok": True}
        finally:
            running -= 1

    monkeypatch.setitem(ws_module.COMMANDS, "slow", slow)
    connection = Connection(ws=None, max_inflight=2)  # type: ignore[arg-type]
    tasks = [
        connection.spawn(ws_module._run_command(None, connection, Command(id=str(i), type="slow")))
        for i in range(6)
    ]
    await asyncio.sleep(0.05)
    assert running == 2, "only max_inflight handlers run at once"
    assert peak == 2

    gate.set()
    await asyncio.gather(*tasks)
    assert peak == 2
    await connection.close()


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
