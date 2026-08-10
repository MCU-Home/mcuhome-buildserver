# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared state, the application factory, and the REST surface.

One aiohttp application, unlike the dashboard's two: there is no trust
split to make real here, because there is exactly one way in and it
carries a bearer token.

REST is one endpoint:

``GET /health``
    Liveness for an orchestrator, before anyone has a token. Says what
    is running and nothing about what it holds.

The application also owns the two things that are true for as long as
the process runs rather than for the length of one request: the
**session reaper**, a periodic sweep that closes and deletes sessions
whose lease or idle timeout ran out, and the startup check that the
per-session directories are being created somewhere only this server can
reach.

**Negotiation is not REST here any more.** ``GET /capabilities`` was
ADR 0006's pre-submission handshake; dashboard ADR 0012 decision 3
replaces it with the session protocol's ``capabilities`` verb, which
answers the same question with the vocabulary that can actually
describe the answer — build-container images, patch policy, quota —
over the same authenticated socket a client is about to use anyway.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field

from aiohttp import web

from mcuhome_buildserver import __version__, sessions, ws
from mcuhome_buildserver.backend import ContainerBackend
from mcuhome_buildserver.config import Config
from mcuhome_buildserver.contextstore import prepare_context_root
from mcuhome_buildserver.security import STATE_KEY, auth_middleware

__all__ = ["REAPER_KEY", "ServerState", "create_app"]

logger = logging.getLogger(__name__)

#: The sweep task, so that shutdown can cancel the one it started.
REAPER_KEY: web.AppKey[asyncio.Task[None]] = web.AppKey("reaper")


@dataclass
class ServerState:
    """Everything one build-server process holds."""

    config: Config
    #: Every open WebSocket. Server-initiated frames iterate this set,
    #: and :meth:`ws.Connection.offer` is how they are put on it — a
    #: stalled client must never hold up whatever is reporting.
    connections: set[ws.Connection] = field(default_factory=set)
    started_at: float = field(default_factory=time.monotonic)
    sessions: sessions.SessionManager = field(init=False)
    #: The container backend: image discovery, the session's container,
    #: invocations and their streams. One per process, because the
    #: ``describe`` cache and the container registry are properties of
    #: the host rather than of a session.
    backend: ContainerBackend = field(init=False)

    def __post_init__(self) -> None:
        self.sessions = sessions.SessionManager()
        self.backend = ContainerBackend(self.config)


async def health(request: web.Request) -> web.Response:
    """Liveness, unauthenticated.

    It names this service's own version and nothing else. It used to
    also report the version of the ``mcuhome`` build tool this server
    spawned; there is no such subprocess any more — a build server is an
    orchestrator and never itself the build environment
    (build-container-contract.md §1.2) — and the build environments it
    drives are per-session, so no single version could be named here
    truthfully.
    """
    state = request.app[STATE_KEY]
    return web.json_response(
        {
            "status": "ok",
            "build_server": __version__,
            "uptime_seconds": round(time.monotonic() - state.started_at, 3),
        }
    )


async def _reap_loop(state: ServerState) -> None:
    """Sweep expired sessions for as long as the server runs.

    The task exists because a lease that is only enforced when a client
    presents its session id is not a lease at all: the client that most
    needs reaping is the one that never comes back. Every
    :data:`~mcuhome_buildserver.sessions.DEFAULT_REAP_INTERVAL` seconds
    this closes the sessions whose lease or idle timeout ran out and
    deletes their directories, which is what the README's "deleted at
    lease expiry" has always claimed and what the credentials in
    ``keys/`` require.

    It never dies of a sweep. A reaper that stopped on one exception
    would take the whole server's cleanup with it and say so only in a
    log line nobody reads until the disk is full.
    """
    while True:
        await asyncio.sleep(sessions.DEFAULT_REAP_INTERVAL)
        try:
            reaped = state.sessions.reap()
            # The container goes with the directory, and for the same
            # reason: the directory *is* the container's mounts, so a
            # container left running against a deleted mount source is
            # the one state neither half can recover from.
            for session_id in reaped:
                await state.backend.release(session_id)
        except Exception:  # pragma: no cover - defensive; a sweep is a dict walk
            logger.exception("the session reaper failed a sweep")
        else:
            if reaped:
                logger.info("reaped %d expired session(s): %s", len(reaped), ", ".join(reaped))


async def _start_reaper(app: web.Application) -> None:
    app[REAPER_KEY] = asyncio.create_task(
        _reap_loop(app[STATE_KEY]), name="mcuhome-build-session-reaper"
    )


async def _stop_reaper(app: web.Application) -> None:
    """Stop sweeping, then take the sessions this process still holds.

    A stopping server's sessions are over by definition — they are
    in-memory records bound to this process — so what is left to do is
    delete the directories, not wait for a lease.
    """
    task = app[REAPER_KEY]
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    state = app[STATE_KEY]
    state.sessions.shutdown()
    # And the containers those sessions were running in. A process that
    # is killed outright still leaves them, which is what the
    # ``org.mcuhome.build-server.session`` label on each is for — there
    # is deliberately no startup sweep, for the reason
    # ``SessionManager.shutdown`` gives about the context root.
    await state.backend.release_all()


def create_app(state: ServerState) -> web.Application:
    # Before anything binds: the per-session directories hold a device's
    # commissioning credentials, and a root somebody else can rename is
    # not a place to put them (`prepare_context_root`). It is a startup
    # refusal rather than a per-session one because it is an operator's
    # mistake about a path, and every session would make it again.
    prepare_context_root(state.config.context_root)
    app = web.Application(middlewares=[auth_middleware])
    app[STATE_KEY] = state
    app.router.add_get("/health", health)
    app.router.add_get("/ws", ws.websocket_handler)
    app.on_startup.append(_start_reaper)
    app.on_cleanup.append(_stop_reaper)
    app.on_response_prepare.append(_security_headers)
    return app


async def _security_headers(request: web.Request, response: web.StreamResponse) -> None:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
