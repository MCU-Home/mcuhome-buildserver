# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared state, the application factory, and the REST surface.

One aiohttp application, unlike the dashboard's two: there is no trust
split to make real here, because there is exactly one way in and it
carries a bearer token.

REST is one endpoint:

``GET /health``
    Liveness for an orchestrator, before anyone has a token. Says only
    that the process is up — not its version and nothing about what it
    holds. Version and uptime are behind the token, in ``capabilities``.

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

from mcuhome_buildserver import sessions, ws
from mcuhome_buildserver.backend import ContainerBackend, SessionBackend
from mcuhome_buildserver.config import Config
from mcuhome_buildserver.contextstore import prepare_context_root
from mcuhome_buildserver.security import STATE_KEY, AuthThrottle, auth_middleware
from mcuhome_buildserver.subprocessbackend import SubprocessBackend

__all__ = ["BACKENDS", "REAPER_KEY", "ServerState", "create_app", "make_backend"]

logger = logging.getLogger(__name__)

#: The two profiles of build-container contract §1.2, by the name the
#: config carries and ``open-session`` answers. The table lives here
#: rather than in :mod:`~mcuhome_buildserver.backend` because the two
#: backends must not import each other — the subprocess backend stands
#: on the container backend's base class, and a factory in that module
#: would close the circle.
BACKENDS: dict[str, type[SessionBackend]] = {
    ContainerBackend.profile: ContainerBackend,
    SubprocessBackend.profile: SubprocessBackend,
}


def make_backend(config: Config) -> SessionBackend:
    """The backend an operator asked for.

    The profile is validated in :func:`~mcuhome_buildserver.config.load_config`,
    so an unknown one has already been refused with the list of the
    known ones by the time this runs; the lookup here is deliberately
    not lenient about it, because a server that fell back to a profile
    nobody asked for would be making the promises of one profile while
    behaving like the other.
    """
    return BACKENDS[config.backend_profile](config)


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
    #: The brute-force backstop in front of the bearer check. One per
    #: process, so the failed-attempt history is shared across every
    #: request the middleware sees.
    auth_throttle: AuthThrottle = field(default_factory=AuthThrottle)
    sessions: sessions.SessionManager = field(init=False)
    #: The backend of the profile this server was configured for:
    #: build-environment discovery, the session's runtime, invocations
    #: and their streams. One per process, because the ``describe``
    #: cache and the runtime registry are properties of the host rather
    #: than of a session.
    backend: SessionBackend = field(init=False)

    def __post_init__(self) -> None:
        # The lease has to be able to hold what this server allows one
        # invocation to take (sessions.ttl_for).
        self.sessions = sessions.SessionManager(
            ttl=sessions.ttl_for(self.config.build_deadline_seconds),
            idle_timeout=self.config.session_idle_timeout_seconds,
        )
        self.backend = make_backend(self.config)


async def health(request: web.Request) -> web.Response:
    """Liveness, unauthenticated. It says the process is up and no more.

    An orchestrator's liveness probe needs to know the server answers,
    not which version it runs — and this is the one response served
    before a token, so it is the wrong place to disclose a version an
    attacker could match to a known weakness. Version and uptime moved
    behind the token gate: the authenticated ``capabilities`` verb
    carries them in its ``server`` block, to a client that has already
    presented the token.
    """
    return web.json_response({"status": "ok"})


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
            # The build environment goes with the directory, and for the
            # same reason: the directory is what it works in — the
            # container's mounts in one profile, a child process's own
            # paths in the other — so anything left running against a
            # deleted tree is the one state neither half can recover
            # from.
            for session_id in reaped:
                # The half of the lease that ran out travels with it: a
                # client still listening is owed the reason its build
                # stopped, and this is the only place that knows it.
                await state.backend.release(
                    session_id, reaped=state.sessions.reaped_reason(session_id)
                )
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
    # And the build environments those sessions were running in. A
    # process that is killed outright still leaves the container-profile
    # ones, which is what the ``org.mcuhome.build-server.session`` label
    # on each is for — there is deliberately no startup sweep, for the
    # reason ``SessionManager.shutdown`` gives about the context root.
    # The subprocess profile has no such leftovers to find: its build
    # environments are children of this process.
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
