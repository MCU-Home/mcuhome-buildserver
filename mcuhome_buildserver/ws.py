# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The ``/ws`` endpoint and the commands of ADR 0006.

The connection has the same shape as the dashboard's — one reader, one
writer task, one task per in-flight command — for the same reason:
commands run concurrently, and concurrent tasks writing to one WebSocket
interleave frames. One outbox makes that impossible by construction.

**Two ways to put a frame in the outbox, and the difference matters
here more than it does in the dashboard.** ``send`` awaits, which is
right for a command's answer: a slow client should slow its own
commands down. ``offer`` never awaits and drops the oldest frame when
the outbox is full, which is right for build output: a browser that
stopped reading must not apply backpressure through the log writer, into
the pipe reader, and from there into the compiler. ADR 0006 decision 6
is what makes the drop safe — every ``job_output`` carries its byte
offset, so a client that sees the offsets jump asks ``follow_job`` for
the gap instead of displaying a log with a hole in it.

``job_state_changed`` goes to every connection: a queue is shared
information and a second dashboard tab should see the first one's build.
``job_output`` goes only to the connections that asked to follow that
job, because a build log is a lot of bytes to send to someone who is
looking at a device list.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from aiohttp import WSMsgType, web

from mcuhome_buildserver import artifacts as artifact_module
from mcuhome_buildserver import builder, protocol
from mcuhome_buildserver.jobs import Job, JobOptions, JobState
from mcuhome_buildserver.logs import MAX_HISTORY_BYTES
from mcuhome_buildserver.protocol import Command, ProtocolError
from mcuhome_buildserver.security import STATE_KEY, check_origin

__all__ = ["COMMANDS", "Connection", "websocket_handler"]

logger = logging.getLogger(__name__)

#: Outbound frames one connection may buffer. Larger than the
#: dashboard's, because a build log is the traffic.
OUTBOX_LIMIT = 1024

#: The most snippets one job may carry. A device configuration asks for
#: one or two; a hundred is a mistake or an attack on the command line.
MAX_SNIPPETS = 16

#: The largest device model this server accepts, in bytes of JSON. A
#: resolved model is a few kilobytes; a megabyte of one is neither.
MAX_MODEL_BYTES = 4 * 1024 * 1024


class Connection:
    """One client: its outbox, its followed jobs and its tasks."""

    def __init__(self, ws: web.WebSocketResponse) -> None:
        self._ws = ws
        self._outbox: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=OUTBOX_LIMIT)
        self._tasks: set[asyncio.Task[None]] = set()
        self.following: set[str] = set()
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


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def _job_or_refuse(state: Any, command: Command) -> Job:
    job_id = command.require_str("job_id")
    job = state.engine.store.get(job_id)
    if job is None:
        raise ProtocolError(
            f'This build server has no job called "{job_id}". It may have been '
            "removed by the retention policy.",
            code=protocol.ERROR_NOT_FOUND,
            frame_id=command.id,
        )
    return job


def _options(command: Command) -> JobOptions:
    options = command.optional_dict("options")
    snippets = tuple(str(item) for item in (options.get("snippets") or []) if isinstance(item, str))
    if len(snippets) > MAX_SNIPPETS:
        raise ProtocolError(
            f"A job may carry at most {MAX_SNIPPETS} snippets.", frame_id=command.id
        )
    jobs = options.get("jobs")
    if jobs is not None and (isinstance(jobs, bool) or not isinstance(jobs, int) or jobs < 1):
        raise ProtocolError(
            '"options.jobs" is a count of parallel compiler jobs and must be at least 1.',
            frame_id=command.id,
        )
    image = options.get("image")
    if image is not None and not isinstance(image, str):
        raise ProtocolError('"options.image" must be a string.', frame_id=command.id)
    return JobOptions(
        native=bool(options.get("native", False)),
        image=image or None,
        snippets=snippets,
        jobs=jobs,
    )


async def submit_job(state: Any, connection: Connection, command: Command) -> dict[str, Any]:
    """``submit_job`` — queue one build.

    Payload::

        {"model": {...device-model.json...},
         "model_version": 1,
         "public_key": "-----BEGIN PUBLIC KEY-----\\n…",
         "options": {"native": false, "image": null, "snippets": [], "jobs": null}}

    Result: ``{"job_id", "job": {...}}``.

    **There is no ``sign`` option, and ``no_sign`` may only be true.**
    ADR 0007 decision 3 puts the private key on the dashboard's side and
    nowhere else, so this server has nothing to sign with; a payload
    that asks it to is refused rather than quietly built unsigned, which
    would hand back an image the client believes is flashable.
    """
    model = command.require_dict("model")
    public_key = command.require_str("public_key")

    if not command.optional_bool("no_sign", True):
        raise ProtocolError(
            "This build server never signs. The signing key lives where the "
            "dashboard runs (ADR 0007 decision 3), so every build here is "
            "--no-sign and the dashboard applies the signature afterwards.",
            code=protocol.ERROR_UNSUPPORTED,
            frame_id=command.id,
        )

    model_version = command.optional_int("model_version") or int(model.get("model_version", 0))
    if not builder.MODEL_VERSION_MIN <= model_version <= builder.MODEL_VERSION_MAX:
        raise ProtocolError(
            f"This build server speaks device-model versions "
            f"{builder.MODEL_VERSION_MIN}-{builder.MODEL_VERSION_MAX}, and this job "
            f"claims version {model_version}. Neither side may guess: upgrade the "
            "one that is behind.",
            code=protocol.ERROR_UNSUPPORTED,
            frame_id=command.id,
            supported={"min": builder.MODEL_VERSION_MIN, "max": builder.MODEL_VERSION_MAX},
            received=model_version,
        )
    if not state.features.usable:
        raise ProtocolError(
            state.features.refusal(),
            code=protocol.ERROR_UNSUPPORTED,
            frame_id=command.id,
            builder=state.features.to_dict(),
        )
    if len(protocol.encode(model)) > MAX_MODEL_BYTES:
        raise ProtocolError(
            f"This device model is larger than {MAX_MODEL_BYTES // 1024} KiB, "
            "which no resolved model is.",
            frame_id=command.id,
        )
    if "-----BEGIN PUBLIC KEY-----" not in public_key:
        raise ProtocolError(
            "The signing public key must be a PEM public key. The *private* half "
            "must never be sent here — it is what the dashboard signs with, and a "
            "build server that held one would be able to sign firmware for every "
            "device it built.",
            frame_id=command.id,
        )
    if "PRIVATE KEY" in public_key:
        raise ProtocolError(
            "That is a private key. Send the public half (mcuhome public-key); the "
            "private one must never leave the machine that signs (ADR 0007).",
            frame_id=command.id,
        )

    # Not in a thread: `submit` puts the id on an ``asyncio.Queue``, which
    # is not thread-safe, and the files it writes are kilobytes.
    job = state.engine.submit(model=model, public_key=public_key, options=_options(command))
    return {"job_id": job.id, "job": job.to_dict()}


async def cancel_job(state: Any, connection: Connection, command: Command) -> dict[str, Any]:
    """``cancel_job`` — stop one job, queued or running.

    Payload: ``{"job_id"}``. Result: ``{"job": {...}}``.

    Cancelling something already finished is not an error: the client
    asked for a state and that state holds. The record it gets back says
    what actually happened.
    """
    job = _job_or_refuse(state, command)
    state.engine.cancel(job.id)
    return {"job": job.to_dict()}


async def queue_status(state: Any, connection: Connection, command: Command) -> dict[str, Any]:
    """``queue_status`` — the queue, and the jobs this server remembers.

    Payload: ``{"limit": 50}`` (optional). Result: ``{"slots", "queued",
    "running", "jobs"}``, active jobs first and finished ones newest
    first after them.
    """
    limit = command.optional_int("limit", 50) or 50
    return state.engine.status(limit=max(1, min(limit, 500)))


async def follow_job(state: Any, connection: Connection, command: Command) -> dict[str, Any]:
    """``follow_job`` — history-then-live log output (ADR 0006 decision 6).

    Payload: ``{"job_id", "offset": 0}``. Result::

        {"job_id", "offset", "text", "next_offset", "eof", "live", "state"}

    ``eof: false`` means there is more history than one answer carries:
    call again with ``next_offset``. ``live: true`` means this connection
    is now receiving ``job_output`` events from ``next_offset`` onwards.

    The order inside is the whole trick. The follower is registered
    *first*, at the log's current length, and the history below that
    length is read afterwards — so a chunk written while the history is
    being read reaches the client as an event instead of falling between
    the two steps.
    """
    job = _job_or_refuse(state, command)
    offset = max(0, command.optional_int("offset", 0) or 0)
    log = state.engine.log_for(job.id)

    live = not job.state.finished
    if live:
        mark = log.follow(connection, _make_follower(connection, job.id))
        connection.following.add(job.id)
    else:
        # A finished job has nothing more to say, so there is nothing to
        # subscribe to and the client simply pages to the end.
        mark = log.size

    limit = min(MAX_HISTORY_BYTES, max(0, mark - offset))
    text, next_offset, _ = await asyncio.to_thread(log.read, offset, limit)
    return {
        "job_id": job.id,
        "state": str(job.state),
        "offset": offset,
        "text": text,
        "next_offset": next_offset,
        "eof": next_offset >= mark,
        "live": live,
    }


def _make_follower(connection: Connection, job_id: str):
    def follower(offset: int, text: str) -> None:
        connection.offer(protocol.job_output_event(job_id, offset, text))

    return follower


async def download_artifacts(
    state: Any, connection: Connection, command: Command
) -> dict[str, Any]:
    """``download_artifacts`` — the index, then the bytes (ADR 0006 decision 7).

    Without ``path``: ``{"job_id", "manifest", "artifacts": [{"path",
    "size", "sha256", "role"}], "chunk_bytes"}`` — the build manifest and
    every file it names, each with the SHA-256 the *build* computed.

    With ``path`` (and an optional ``offset``): one chunk,
    ``{"path", "offset", "length", "next_offset", "eof", "sha256",
    "data"}``, where ``data`` is base64 and ``sha256`` is of this chunk.
    A client verifies each chunk against that and the assembled file
    against the index — the first says the transfer worked, the second
    says the artifact is the one the build produced.

    Only paths in the index can be named, so there is no traversal to
    defend against.
    """
    job = _job_or_refuse(state, command)
    if job.state is not JobState.SUCCEEDED:
        raise ProtocolError(
            f'Job "{job.id}" is {job.state} and has no artifacts.',
            code=protocol.ERROR_CONFLICT,
            frame_id=command.id,
        )
    build_dir = state.engine.store.build_dir(job.id)
    artifact_set = await asyncio.to_thread(artifact_module.read_artifact_set, build_dir)
    if artifact_set is None:
        raise ProtocolError(
            f'Job "{job.id}" succeeded but its build directory is gone. Retention '
            "removes finished builds; build it again.",
            code=protocol.ERROR_NOT_FOUND,
            frame_id=command.id,
        )

    path = command.optional_str("path")
    if path is None:
        return {"job_id": job.id, **artifact_set.to_dict()}

    target = artifact_set.resolve(path)
    if target is None:
        raise ProtocolError(
            f'"{path}" is not one of this build\'s artifacts.',
            code=protocol.ERROR_NOT_FOUND,
            frame_id=command.id,
            artifacts=[item.path for item in artifact_set.artifacts],
        )
    offset = max(0, command.optional_int("offset", 0) or 0)
    limit = command.optional_int("limit") or artifact_module.DEFAULT_CHUNK_BYTES
    limit = max(1, min(limit, artifact_module.DEFAULT_CHUNK_BYTES))
    chunk = await asyncio.to_thread(artifact_module.read_chunk, target, offset, limit)
    return {"job_id": job.id, "path": path, **chunk}


#: The command table. Adding a name here is the whole registration.
COMMANDS = {
    "submit_job": submit_job,
    "cancel_job": cancel_job,
    "follow_job": follow_job,
    "download_artifacts": download_artifacts,
    "queue_status": queue_status,
}


# --------------------------------------------------------------------------
# The endpoint
# --------------------------------------------------------------------------


async def _run_command(state: Any, connection: Connection, command: Command) -> None:
    handler = COMMANDS.get(command.type)
    if handler is None:
        await connection.send(
            protocol.error_frame(
                command.id,
                protocol.ERROR_UNKNOWN_COMMAND,
                f'This build server has no command called "{command.type}".',
                known=sorted(COMMANDS),
            )
        )
        return
    try:
        payload = await handler(state, connection, command)
    except ProtocolError as exc:
        await connection.send(protocol.error_frame(command.id, exc.code, exc.message, **exc.detail))
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

    ws = web.WebSocketResponse(heartbeat=30.0, max_msg_size=MAX_MODEL_BYTES * 2)
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
        for job_id in list(connection.following):
            state.engine.log_for(job_id).unfollow(connection)
        connection.following.clear()
        await connection.close()
        writer.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await writer
        with contextlib.suppress(Exception):
            await ws.close()
    return ws
