# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared state, the application factory, and the REST surface.

One aiohttp application, unlike the dashboard's two: there is no trust
split to make real here, because there is exactly one way in and it
carries a bearer token (ADR 0006 decision 1).

REST is two endpoints, and each exists for a reason a WebSocket cannot
serve:

``GET /health``
    Liveness for an orchestrator, before anyone has a token. Says what
    is running and nothing about what it holds.

``GET /capabilities``
    ADR 0006 decision 4: **negotiation before a job exists.** The
    dashboard asks what this server is before it submits, so a mismatch
    is a refusal naming both sides' versions rather than a failure ten
    minutes into a compile. Token-gated, because the answer names the
    builder version, the image tag and the workspace — an inventory of
    the machine, and not something to hand to an unauthenticated caller.
"""

from __future__ import annotations

import logging
import platform
import time
from dataclasses import dataclass, field
from typing import Any

from aiohttp import web

from mcuhome_buildserver import __version__, builder, protocol, ws
from mcuhome_buildserver.config import Config
from mcuhome_buildserver.jobs import EngineSettings, Job, JobEngine, JobStore
from mcuhome_buildserver.security import STATE_KEY, auth_middleware

__all__ = ["ServerState", "capabilities", "create_app"]

logger = logging.getLogger(__name__)


@dataclass
class ServerState:
    """Everything one build-server process holds."""

    config: Config
    features: builder.BuilderFeatures | None = None
    connections: set[ws.Connection] = field(default_factory=set)
    started_at: float = field(default_factory=time.monotonic)
    store: JobStore = field(init=False)
    engine: JobEngine = field(init=False)

    def __post_init__(self) -> None:
        self.store = JobStore(
            self.config.jobs_root,
            keep=self.config.keep_jobs,
            ttl_days=self.config.ttl_days,
        )
        if self.features is None:
            # Replaced by the real probe in `start`; a pessimistic
            # placeholder so that nothing can accidentally run a build
            # against an unexamined builder.
            self.features = builder.BuilderFeatures(
                present=False,
                model_input=False,
                detached_signing=False,
                json_output=False,
                problem="the builder has not been probed yet",
            )
        self.engine = JobEngine(
            self.store,
            EngineSettings(
                slots=self.config.slots,
                workspace=self.config.workspace,
                build_jobs=self.config.build_jobs,
                native=self.config.native,
                image=self.config.image,
                timeout=self.config.job_timeout,
                command=self.config.builder_command,
            ),
            self.features,
            on_state_change=self.broadcast_state,
        )

    async def start(self, *, probe: bool = True) -> None:
        if probe:
            self.features = await builder.probe_features(self.config.builder_command)
            self.engine.features = self.features
        await self.engine.start()

    async def stop(self) -> None:
        await self.engine.stop()

    def broadcast_state(self, job: Job) -> None:
        """Push one job record to every connection.

        A queue is shared information: a second dashboard tab, or a
        second person, should see the build that the first one started.
        Offered rather than sent, so that one stalled client cannot hold
        up the engine that is reporting to all of them.
        """
        frame = protocol.job_state_event(job.to_dict())
        for connection in list(self.connections):
            connection.offer(frame)


def capabilities(state: ServerState) -> dict[str, Any]:
    """What ``GET /capabilities`` answers — ADR 0006 decision 4.

    Every field here exists because something on the other side has to
    decide with it, not because it was available:

    ``mcuhome`` / ``builder``
        the version range check of ADR 0011 decision 2, and whether this
        builder can take a model at all (see
        :mod:`mcuhome_buildserver.builder`).
    ``model_version``
        the handshake of ADR 0007 decision 4.
    ``arch``
        ADR 0003 decision 5 ships the build server amd64-first; a client
        should be able to see what it is talking to.
    ``jobs``
        how long the queue is before submitting to it.
    ``image`` / ``workspace``
        which toolchain and which west workspace will do the work.
    """
    features = state.features or state.engine.features
    status = state.engine.status(limit=0)
    workspace = state.config.workspace
    return {
        "server": {
            "name": "mcuhome-build-server",
            "version": __version__,
            "uptime_seconds": round(time.monotonic() - state.started_at, 3),
        },
        "protocol_version": protocol.PROTOCOL_VERSION,
        "commands": sorted(ws.COMMANDS),
        "mcuhome": {"version": builder.VERSION},
        "builder": features.to_dict(),
        "model_version": {
            "min": builder.MODEL_VERSION_MIN,
            "max": builder.MODEL_VERSION_MAX,
        },
        "arch": platform.machine(),
        "platform": platform.system().lower(),
        "jobs": {
            "slots": status["slots"],
            "queued": len(status["queued"]),
            "running": len(status["running"]),
        },
        "build": {
            # None means "whatever the builder's own default is" — this
            # server does not import the builder's private constant to
            # restate it, because a wrong answer here is worse than none.
            "image": state.config.image,
            "native": state.config.native,
            "parallel_jobs": state.config.build_jobs,
        },
        "workspace": {
            "path": str(workspace) if workspace else None,
            "present": bool(workspace and workspace.is_dir()),
        },
        "signing": {
            # Not a capability so much as a promise, and the dashboard
            # checks it: this server never signs (ADR 0007 decision 3).
            "detached_only": True
        },
    }


async def health(request: web.Request) -> web.Response:
    state = request.app[STATE_KEY]
    return web.json_response(
        {
            "status": "ok",
            "build_server": __version__,
            "mcuhome": builder.VERSION,
            "uptime_seconds": round(time.monotonic() - state.started_at, 3),
        }
    )


async def capabilities_handler(request: web.Request) -> web.Response:
    return web.json_response(capabilities(request.app[STATE_KEY]))


def create_app(state: ServerState) -> web.Application:
    app = web.Application(middlewares=[auth_middleware])
    app[STATE_KEY] = state
    app.router.add_get("/health", health)
    app.router.add_get("/capabilities", capabilities_handler)
    app.router.add_get("/ws", ws.websocket_handler)
    app.on_response_prepare.append(_security_headers)
    return app


async def _security_headers(request: web.Request, response: web.StreamResponse) -> None:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
