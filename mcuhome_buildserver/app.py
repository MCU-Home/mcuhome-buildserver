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

**Negotiation is not REST here any more.** ``GET /capabilities`` was
ADR 0006's pre-submission handshake; dashboard ADR 0012 decision 3
replaces it with the session protocol's ``capabilities`` verb, which
answers the same question with the vocabulary that can actually
describe the answer — builder images, patch policy, quota — over the
same authenticated socket a client is about to use anyway.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from aiohttp import web

from mcuhome_buildserver import __version__, sessions, ws
from mcuhome_buildserver.config import Config
from mcuhome_buildserver.security import STATE_KEY, auth_middleware

__all__ = ["ServerState", "create_app"]

logger = logging.getLogger(__name__)


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

    def __post_init__(self) -> None:
        self.sessions = sessions.SessionManager()


async def health(request: web.Request) -> web.Response:
    """Liveness, unauthenticated.

    It names this service's own version and nothing else. It used to
    also report the version of the ``mcuhome`` builder this server
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


def create_app(state: ServerState) -> web.Application:
    app = web.Application(middlewares=[auth_middleware])
    app[STATE_KEY] = state
    app.router.add_get("/health", health)
    app.router.add_get("/ws", ws.websocket_handler)
    app.on_response_prepare.append(_security_headers)
    return app


async def _security_headers(request: web.Request, response: web.StreamResponse) -> None:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
