# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The ``/ws`` endpoint and the command loop.

This is the transport that dashboard ADR 0012 decision 3 carries
forward from ADR 0006 while replacing the vocabulary that used to run
over it: WebSocket plus a bearer token, this frame envelope, this
connection handling. The verbs themselves live in
:mod:`mcuhome_buildserver.sessions`.

The connection has the same shape as the dashboard's — one reader, one
writer task, one task per in-flight command — for the same reason:
commands run concurrently, and concurrent tasks writing to one WebSocket
interleave frames. One outbox makes that impossible by construction.

**Two ways to put a frame in the outbox, and the difference matters
here more than it does in the dashboard.** ``send`` awaits, which is
right for a command's answer: a slow client should slow its own
commands down. ``offer`` never awaits and drops the oldest frame when
the outbox is full, which is right for build output: a client that
stopped reading must not apply backpressure through the log reader and
from there into the compiler. What makes the drop safe is that a
progress stream carries resumable offsets, so a client that sees them
jump asks for the gap instead of displaying a log with a silent hole in
it. That property is the one thing ADR 0006's resumable log follow
becomes in the session protocol, and the stream it applies to lands
with the container backend.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from aiohttp import WSMsgType, web

from mcuhome_buildserver import errors, protocol, sessions
from mcuhome_buildserver.protocol import Command, ProtocolError
from mcuhome_buildserver.security import STATE_KEY, check_origin

__all__ = ["COMMANDS", "Connection", "websocket_handler"]

logger = logging.getLogger(__name__)

#: Outbound frames one connection may buffer. Larger than the
#: dashboard's, because build output is the traffic.
OUTBOX_LIMIT = 1024

#: The largest single frame this endpoint accepts, in bytes. A cap on
#: the *frame* and not on a payload: it is the WebSocket's own
#: ``max_msg_size``, which is the only limit that can refuse a message
#: before it has been buffered. The session protocol's context upload
#: is bounded separately and by a different mechanism — a streaming
#: ingress cap answering ``policy.ingress-limit-exceeded``
#: (:mod:`mcuhome_buildserver.errors`) — because a limit that only
#: fires after the bytes arrived is not a limit.
MAX_FRAME_BYTES = 8 * 1024 * 1024


class Connection:
    """One client: its outbox and its in-flight command tasks."""

    def __init__(self, ws: web.WebSocketResponse) -> None:
        self._ws = ws
        self._outbox: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=OUTBOX_LIMIT)
        self._tasks: set[asyncio.Task[None]] = set()
        self._closing = False
        self.dropped = 0

    async def send(self, frame: dict[str, Any]) -> None:
        """Queue a frame, waiting for room. For answers to commands."""
        if not self._closing:
            await self._outbox.put(frame)

    def offer(self, frame: dict[str, Any]) -> None:
        """Queue a frame, dropping the oldest if there is no room.

        Never awaits and never raises: it is called from the middle of
        reading a build's pipe.
        """
        if self._closing:
            return
        try:
            self._outbox.put_nowait(frame)
            return
        except asyncio.QueueFull:
            pass
        with contextlib.suppress(asyncio.QueueEmpty):
            self._outbox.get_nowait()
        self.dropped += 1
        with contextlib.suppress(asyncio.QueueFull):
            self._outbox.put_nowait(frame)

    async def write_loop(self) -> None:
        while True:
            frame = await self._outbox.get()
            try:
                await self._ws.send_str(protocol.encode(frame))
            except (ConnectionResetError, RuntimeError):
                return

    def spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def close(self) -> None:
        self._closing = True
        for task in list(self._tasks):
            task.cancel()
        for task in list(self._tasks):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


#: The command table, **derived** from the verb table rather than
#: written out again: this endpoint's vocabulary *is* the session
#: protocol now that the one-shot job commands are gone, so a verb
#: registered in :data:`sessions.SESSION_VERBS` is registered here by
#: construction and the two can never disagree.
COMMANDS = dict(sessions.SESSION_VERBS)


# --------------------------------------------------------------------------
# The endpoint
# --------------------------------------------------------------------------


async def _run_command(state: Any, connection: Connection, command: Command) -> None:
    handler = COMMANDS.get(command.type)
    if handler is None:
        # An unknown verb is a vocabulary mismatch, and the session
        # protocol's registry has the code that says so — including the
        # known verbs in its details, so a client that guessed learns
        # what it could have asked for. The frame shape is the ordinary
        # error frame; only the error object is the typed envelope.
        await connection.send(
            {
                "id": command.id,
                "type": protocol.TYPE_ERROR,
                "error": errors.envelope(
                    "version.verb-unknown",
                    f'This build server has no verb called "{command.type}".',
                    known=sorted(COMMANDS),
                ),
            }
        )
        return
    try:
        payload = await handler(state, connection, command)
    except ProtocolError as exc:
        await connection.send(protocol.error_frame(command.id, exc.code, exc.message, **exc.detail))
    except errors.SessionError as exc:
        await connection.send(
            {"id": command.id, "type": protocol.TYPE_ERROR, "error": exc.to_envelope()}
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("command %r failed", command.type)
        await connection.send(
            protocol.error_frame(
                command.id,
                protocol.ERROR_INTERNAL,
                f'The command "{command.type}" failed unexpectedly. '
                "The build server's log has the details.",
            )
        )
    else:
        await connection.send(protocol.result_frame(command.id, payload))


async def websocket_handler(request: web.Request) -> web.StreamResponse:
    """Serve ``/ws``. The token was checked by the middleware."""
    state = request.app[STATE_KEY]
    if not check_origin(request, allowed=state.config.allowed_origins):
        logger.warning("refused a WebSocket upgrade from origin %r", request.headers.get("Origin"))
        raise web.HTTPForbidden(text="This origin may not open a WebSocket here.")

    ws = web.WebSocketResponse(heartbeat=30.0, max_msg_size=MAX_FRAME_BYTES)
    await ws.prepare(request)

    connection = Connection(ws)
    state.connections.add(connection)
    writer = asyncio.create_task(connection.write_loop(), name="mcuhome-build-ws-writer")
    try:
        async for message in ws:
            if message.type is not WSMsgType.TEXT:
                if message.type is WSMsgType.BINARY:
                    await connection.send(
                        protocol.error_frame(
                            None,
                            protocol.ERROR_BAD_REQUEST,
                            "This endpoint speaks JSON text frames only.",
                        )
                    )
                continue
            try:
                command = protocol.decode(message.data)
            except ProtocolError as exc:
                await connection.send(protocol.error_frame(exc.frame_id, exc.code, exc.message))
                continue
            connection.spawn(_run_command(state, connection, command))
    finally:
        state.connections.discard(connection)
        await connection.close()
        writer.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await writer
        with contextlib.suppress(Exception):
            await ws.close()
    return ws
