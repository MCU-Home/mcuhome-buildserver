# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The ``/ws`` endpoint and the command loop.

This is the transport that dashboard ADR 0012 decision 3 carries
forward from ADR 0006 while replacing the vocabulary that used to run
over it: WebSocket plus a bearer token, this frame envelope, this
connection handling. The verbs themselves live in
:mod:`mcuhome.buildserver.sessions`.

The connection has the same shape as the dashboard's — one reader, one
writer task, one task per in-flight command — for the same reason:
commands run concurrently, and concurrent tasks writing to one WebSocket
interleave frames. One outbox makes that impossible by construction.

**Two ways to put a frame in the outbox, and the difference matters
here more than it does in the dashboard.** ``send`` awaits, which is
right for a command's answer: a slow client should slow its own
commands down. ``offer`` never awaits and drops the oldest *droppable*
frame when the outbox is full, which is right for build output: a
client that stopped reading must not apply backpressure through the log
reader and from there into the compiler. What makes the drop safe is
that a progress stream carries resumable offsets, so a client that sees
them jump asks for the gap instead of displaying a log with a silent
hole in it. That property is the one thing ADR 0006's resumable log
follow becomes in the session protocol, and the stream it applies to
lands with the container backend.

**Droppable is a property of the frame, not of the queue.** One outbox
carries three kinds of traffic — command answers, the two build streams
and the BINARY chunks of a download — because a BINARY frame carries no
id and belongs to the announcement that went out immediately before it,
which only one ordering can express. A type-blind drop-the-oldest
policy therefore evicts a chunk of somebody's firmware archive to make
room for a log line, and the client finds out from a hash that does not
match at the end of a download it already paid for. So eviction asks
what it is about to throw away: log lines and program events go,
everything else stays, and an outbox that is full of frames none of
which may be dropped is a connection too slow to serve — closed with a
close code rather than served a corrupted archive.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import logging
from pathlib import Path
from typing import Any

from aiohttp import WSCloseCode, WSMsgType, web

from mcuhome.buildserver import errors, protocol, sessions
from mcuhome.buildserver.config import DEFAULT_MAX_INFLIGHT_COMMANDS
from mcuhome.buildserver.ingress import Upload
from mcuhome.buildserver.protocol import MAX_FRAME_BYTES, Command, ProtocolError
from mcuhome.buildserver.security import STATE_KEY, check_origin

__all__ = ["COMMANDS", "VERDICT_EVENT", "Connection", "websocket_handler"]

logger = logging.getLogger(__name__)

#: Outbound frames one connection may buffer. Larger than the
#: dashboard's, because build output is the traffic.
OUTBOX_LIMIT = 1024

#: How much of a download archive goes into one outbound BINARY frame.
#: Well under :data:`~mcuhome.buildserver.protocol.MAX_FRAME_BYTES`,
#: deliberately: that cap is this endpoint's own ``max_msg_size``, which
#: this server announces and a third-party client need not match — a
#: client with a smaller one would drop the connection rather than
#: the frame. A quarter of a megabyte is small enough that no reasonable
#: client refuses it and large enough that a firmware image is a handful
#: of frames.
DOWNLOAD_CHUNK_BYTES = 256 * 1024


class Connection:
    """One client: its outbox, its in-flight commands, and its upload.

    **The upload belongs to the connection and not to the session**, and
    the wire is what decides that: a BINARY frame carries no frame id and
    no session id, so the only thing that can say which archive its bytes
    belong to is *when* they arrive (E41). One announced upload at a time
    per connection is therefore the shape of the transport rather than a
    restriction on it, and a second concurrent announcement is refused
    instead of interleaved into the first.
    """

    def __init__(
        self, ws: web.WebSocketResponse, *, max_inflight: int = DEFAULT_MAX_INFLIGHT_COMMANDS
    ) -> None:
        self._ws = ws
        # A bound on the command tasks running at once on this connection.
        # Hardening, not a boundary (the token equals shell): it keeps one
        # authenticated connection from accumulating unbounded in-flight
        # handler tasks under a flood of TEXT frames. Held around the
        # handler dispatch in `_run_command` rather than acquired in the
        # read loop, so the reader never blocks — an upload verb holds a
        # slot while it awaits its BINARY frames, and blocking the reader
        # on a full semaphore would then stop those very frames from
        # arriving and deadlock the upload.
        self._inflight = asyncio.Semaphore(max_inflight)
        # Text frames as dictionaries, binary frames as bytes, on **one**
        # queue. Two queues would be two orders, and the download's whole
        # correlation rule is order: a BINARY frame carries no id, so the
        # bytes belong to the announcement that went out immediately
        # before them or to nothing at all.
        #
        # A deque rather than an `asyncio.Queue`, because eviction has to
        # be able to skip: the policy is "drop the oldest frame that may
        # be dropped", and a queue can only drop the oldest one there is.
        self._outbox: collections.deque[dict[str, Any] | bytes] = collections.deque()
        self._arrived = asyncio.Event()
        self._room = asyncio.Event()
        self._room.set()
        self._tasks: set[asyncio.Task[None]] = set()
        self._closing = False
        self.dropped = 0
        #: True once the outbox filled with frames none of which may be
        #: dropped and the connection was closed for it.
        self.overloaded = False
        self._overflow: asyncio.Task[None] | None = None
        self.upload: Upload | None = None
        self._announced = asyncio.Event()
        # One download at a time per connection, held across the whole
        # of `get-artifact`: the announcement and the bytes behind it are
        # one indivisible sequence on the wire, and two of them
        # interleaved leave a client unable to say which archive it is
        # holding.
        self._download = asyncio.Lock()

    def begin_upload(self, upload: Upload) -> None:
        """Announce an archive on this connection, or refuse a second one."""
        if self.upload is not None:
            raise ProtocolError(
                "An archive upload is already in progress on this connection. Binary "
                "frames carry no id, so they can only belong to the upload that is "
                "running; wait for it to be acknowledged before announcing another."
            )
        self.upload = upload
        self._announced.set()

    def end_upload(self, upload: Upload) -> None:
        """Release the connection, whatever the upload's outcome was."""
        if self.upload is upload:
            self.upload = None
            self._announced.clear()

    async def await_announcement(self, task: asyncio.Task[None]) -> None:
        """Hold the reader until *task* has announced its upload, or ended.

        **Without this the first frames of an archive are lost, and
        nothing about the loss is visible.** A command runs as its own
        task, and a task does not start until the event loop gets a
        turn; a client that sends its announcement and its first binary
        frame back to back can have both buffered by the transport, so
        the reader would take the second frame off a buffer without ever
        yielding — and answer "this endpoint speaks JSON text frames
        only" to bytes that were correctly announced.

        Waiting on scheduling order instead (a bare ``sleep(0)``) would
        happen to work today and quietly stop working the first time an
        ``await`` appears in a verb ahead of its announcement. This waits
        for the announcement itself, which is the thing that actually
        has to have happened, or for the command to fail before making
        one.
        """
        announced = asyncio.ensure_future(self._announced.wait())
        try:
            await asyncio.wait({announced, task}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            announced.cancel()

    @property
    def inflight(self) -> asyncio.Semaphore:
        """The per-connection in-flight-command bound, as a context manager.

        ``async with connection.inflight:`` around one command's handler
        holds a slot for the length of that handler and releases it when
        the handler returns, whatever its outcome.
        """
        return self._inflight

    @property
    def download_lock(self) -> asyncio.Lock:
        """The one-download-at-a-time guard, held for the whole of one.

        ``send_archive``'s ordering rule — the bytes belong to the
        announcement immediately before them — is a *property of the
        wire* and not something the wire enforces. Two ``get-artifact``
        commands run as two tasks, and nothing in the transport stops
        their frames from interleaving: the client would then see two
        announcements and one undifferentiated stream of chunks, with no
        id anywhere to sort them by. The upload direction has had this
        guard from the start (:meth:`begin_upload`); this is the same
        statement about the other direction.
        """
        return self._download

    async def send(self, frame: dict[str, Any]) -> None:
        """Queue a frame, waiting for room. For answers to commands."""
        await self._put(frame)

    async def send_bytes(self, chunk: bytes) -> None:
        """Queue one BINARY frame, waiting for room.

        Deliberately :meth:`send` and never :meth:`offer`: dropping a
        chunk of an archive does not degrade it, it corrupts it, and the
        client would find out only from a hash that does not match at
        the end of a download it already paid for. A slow client
        therefore slows its own download down, which is what
        backpressure is for and why the drop-the-oldest policy is scoped
        to the log stream, where a gap is visible in a counter.

        That scoping is enforced in :meth:`offer` as well as here: how a
        frame is *enqueued* says nothing about how it may be *evicted*,
        and a chunk queued by this method used to be evictable by the
        next log line that arrived.
        """
        await self._put(chunk)

    async def _put(self, item: dict[str, Any] | bytes) -> None:
        while not self._closing and len(self._outbox) >= OUTBOX_LIMIT:
            await self._room.wait()
        if self._closing:
            return
        self._enqueue(item)

    def _enqueue(self, item: dict[str, Any] | bytes) -> None:
        self._outbox.append(item)
        self._arrived.set()
        if len(self._outbox) >= OUTBOX_LIMIT:
            self._room.clear()

    def offer(self, frame: dict[str, Any]) -> None:
        """Queue a frame, dropping the oldest **droppable** one for room.

        Never awaits and never raises: it is called from the middle of
        reading a build's pipe. What it may throw away is the log and
        the program's event stream, both of which survive a gap — the
        log carries a counter that makes one visible, and the events
        file on disk is the replay buffer ``attach-session`` fetches it
        from. What it may never throw away is a BINARY chunk of a
        download, a command's answer, or the ``invocation.verdict``
        frame a client is waiting on.

        An outbox holding nothing but those is a client that has stopped
        reading in the middle of a download. There is no frame to drop
        and no honest way to continue, so the connection is closed with
        a close code that says to come back.
        """
        if self._closing:
            return
        if len(self._outbox) < OUTBOX_LIMIT:
            self._enqueue(frame)
            return
        for index, queued in enumerate(self._outbox):
            if _droppable(queued):
                del self._outbox[index]
                self.dropped += 1
                self._enqueue(frame)
                return
        self._overload()

    def _overload(self) -> None:
        """Give up on a connection that cannot be served without lying."""
        logger.warning("closing a connection whose outbox filled with undroppable frames")
        self.overloaded = True
        self._closing = True
        # Both waits are released, or every task blocked on room in the
        # outbox stays blocked on a connection that is going away.
        self._room.set()
        self._arrived.set()
        self._overflow = asyncio.ensure_future(self._close_overloaded())

    async def _close_overloaded(self) -> None:
        with contextlib.suppress(Exception):
            await self._ws.close(
                code=WSCloseCode.TRY_AGAIN_LATER,
                message=b"this connection stopped reading during a download",
            )

    async def send_archive(self, path: Path) -> None:
        """Stream a built download archive as BINARY frames.

        Called **after** the result frame that announced its size and
        its SHA-256, and the order is the whole correlation rule: a
        BINARY frame carries no frame id and no session id, so the only
        thing that can say which archive its bytes belong to is *when*
        they arrive (E41, mirrored by E45). One download at a time per
        connection is what makes that rule hold, and it is held by
        :attr:`download_lock` rather than hoped for.
        """
        with path.open("rb") as handle:
            while chunk := handle.read(DOWNLOAD_CHUNK_BYTES):
                await self.send_bytes(chunk)

    async def write_loop(self) -> None:
        while True:
            if not self._outbox:
                self._arrived.clear()
                if not self._outbox:
                    await self._arrived.wait()
                continue
            frame = self._outbox.popleft()
            if len(self._outbox) < OUTBOX_LIMIT:
                self._room.set()
            try:
                if isinstance(frame, bytes):
                    await self._ws.send_bytes(frame)
                else:
                    await self._ws.send_str(protocol.encode(frame))
            except (ConnectionResetError, RuntimeError):
                return

    def spawn(self, coro) -> asyncio.Task[None]:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def close(self) -> None:
        self._closing = True
        # Anything parked on room in the outbox is parked on a
        # connection that will never drain again.
        self._room.set()
        self._arrived.set()
        for task in list(self._tasks):
            task.cancel()
        for task in list(self._tasks):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if self._overflow is not None:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._overflow


#: The one event name that is never evicted even though its frame type
#: is. E46 gives it to this server's own completion frame and E58 gives
#: that frame a name of its own, which is what makes this guarantee
#: exact: the verdict is this server's judgement, it is written to no
#: events file, and a dropped one is lost for good. Everything else on
#: the event stream — the program's ``invocation.finished`` included —
#: can be fetched again from the events file through ``attach-session``.
VERDICT_EVENT = "invocation.verdict"


def _droppable(frame: dict[str, Any] | bytes) -> bool:
    """Whether the outbox may throw *frame* away to make room.

    The two build streams and nothing else. A BINARY chunk is not a
    ``dict`` and never qualifies; a command's ``result`` or ``error``
    answer is what a caller is blocked on; ``invocation.verdict`` is
    the frame E46 exists to deliver.
    """
    if not isinstance(frame, dict):
        return False
    if frame.get("type") == protocol.TYPE_LOG:
        return True
    return frame.get("type") == protocol.TYPE_EVENT and frame.get("event") != VERDICT_EVENT


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
    # One in-flight slot for the whole life of this command, so a flood of
    # TEXT frames on one connection cannot run unbounded handlers at once.
    # The acquire is here rather than in the read loop on purpose (see
    # `Connection.__init__`): the reader must stay free to feed an
    # upload's BINARY frames even while every slot is taken.
    async with connection.inflight:
        await _dispatch(state, connection, command)


async def _dispatch(state: Any, connection: Connection, command: Command) -> None:
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
        # A handler that answers `None` has already put its own result
        # frame on the outbox and written whatever had to follow it.
        # There is exactly one such verb — `get-artifact`, whose result
        # frame announces an archive that the BINARY frames behind it
        # then deliver (E45) — and the ordering is the reason: a frame
        # this loop sent *after* the handler returned would arrive after
        # the bytes it was supposed to announce, and a BINARY frame
        # carries no id to repair that with.
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
        if payload is not None:
            await connection.send(protocol.result_frame(command.id, payload))


async def websocket_handler(request: web.Request) -> web.StreamResponse:
    """Serve ``/ws``. The token was checked by the middleware."""
    state = request.app[STATE_KEY]
    if not check_origin(request, allowed=state.config.allowed_origins):
        logger.warning("refused a WebSocket upgrade from origin %r", request.headers.get("Origin"))
        raise web.HTTPForbidden(text="This origin may not open a WebSocket here.")

    # The connection cap, before the socket joins the broadcast set. It is
    # a bound on `state.connections`, which is otherwise unbounded, and
    # hardening rather than a boundary (the token equals shell). A caller
    # past the cap is a caller to turn away *later*, not one that did
    # anything wrong, so it is closed with TRY_AGAIN_LATER — the same code
    # `_overload` uses for a connection this server cannot serve right now.
    if len(state.connections) >= state.config.max_connections:
        logger.warning(
            "refused a WebSocket upgrade: %d connections already open (max %d)",
            len(state.connections),
            state.config.max_connections,
        )
        full = web.WebSocketResponse()
        await full.prepare(request)
        await full.close(
            code=WSCloseCode.TRY_AGAIN_LATER,
            message=b"this build server is at its connection limit; retry later",
        )
        return full

    ws = web.WebSocketResponse(heartbeat=30.0, max_msg_size=MAX_FRAME_BYTES)
    await ws.prepare(request)

    connection = Connection(ws, max_inflight=state.config.max_inflight_commands)
    state.connections.add(connection)
    writer = asyncio.create_task(connection.write_loop(), name="mcuhome-build-ws-writer")
    try:
        async for message in ws:
            if message.type is WSMsgType.BINARY:
                # Binary frames are the body of an announced context
                # upload and nothing else (E41). The check is the
                # announcement rather than the frame, because a frame
                # cannot say what it is: outside an upload this endpoint
                # still speaks JSON text frames only.
                #
                # `feed` is called here, synchronously, instead of being
                # handed to the waiting handler through a queue. A queue
                # would buffer whatever the client sends faster than the
                # server unpacks it, which is the very thing the ingress
                # caps exist to prevent; doing the work in the reader
                # makes the socket itself the backpressure.
                if connection.upload is None:
                    await connection.send(
                        protocol.error_frame(
                            None,
                            protocol.ERROR_BAD_REQUEST,
                            "This endpoint speaks JSON text frames only, except while a "
                            "context archive is announced. Announce it with send-context "
                            "or extend-context first.",
                        )
                    )
                else:
                    connection.upload.feed(message.data)
                continue
            if message.type is not WSMsgType.TEXT:
                continue
            try:
                command = protocol.decode(message.data)
            except ProtocolError as exc:
                await connection.send(protocol.error_frame(exc.frame_id, exc.code, exc.message))
                continue
            task = connection.spawn(_run_command(state, connection, command))
            if command.type in sessions.UPLOAD_VERBS:
                await connection.await_announcement(task)
    finally:
        state.connections.discard(connection)
        # A closed socket leaves the invocations it was watching running
        # — connection loss is never abandonment — so what goes away
        # here is only this connection's place in their audience, and its
        # place among the clients a session counts as attached. The
        # second is what starts the reconnect grace: a session nobody
        # comes back to may be handed to a client that is waiting.
        state.backend.detach(connection)
        state.sessions.detach(connection)
        await connection.close()
        writer.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await writer
        with contextlib.suppress(Exception):
            await ws.close()
    return ws
