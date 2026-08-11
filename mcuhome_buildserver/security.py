# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The bearer token, where it comes from, and where it is left (ADR 0006).

ADR 0006 decision 1 chose WebSocket plus a bearer token over ESPHome's
Noise handshake, for one reason recorded as the product owner's: **a
WebSocket over HTTPS traverses firewalls, NAT and reverse proxies
naturally**, and a build server outside the home network is the expected
case rather than the exotic one. The cost of that choice is stated
rather than hidden — a build server reachable from the internet **must**
sit behind TLS, because a bearer token on a plaintext connection is a
token that has been given away.

The threat model is ESPHome's, verbatim and unchanged: **a compromised
authenticated session is equivalent to shell access.** A build runs a
compiler over data the session supplied, on this machine. There is no
sandbox here that would make a leaked token less than that, which is why
the token is always required and never optional.

Three places a token can come from, in the order they are consulted:
the command line, the environment, a file. A deployment that configures
none gets one generated at startup and logged once — the code-server
pattern the dashboard already uses for its password, and the reason a
fresh container is usable in one step without ever being open.

**Same-host pairing** (ADR 0006 decision 8): when both Apps run on one
Home Assistant instance they share a ``/share`` mount, so the token is
written to a file there and the dashboard finds it. It is written only
when the directory already exists, which is exactly the condition "we
are inside Home Assistant" — a standalone build server does not litter
somebody's filesystem to advertise a pairing that cannot happen.
"""

from __future__ import annotations

import contextlib
import logging
import math
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from aiohttp import web

__all__ = [
    "DEFAULT_AUTH_BASE_DELAY",
    "DEFAULT_AUTH_FREE_ATTEMPTS",
    "DEFAULT_AUTH_GLOBAL_LOCK",
    "DEFAULT_AUTH_GLOBAL_THRESHOLD",
    "DEFAULT_AUTH_MAX_DELAY",
    "DEFAULT_AUTH_MAX_TRACKED",
    "DEFAULT_AUTH_RESET_AFTER",
    "DEFAULT_PAIR_FILE",
    "STATE_KEY",
    "TOKEN_HEADER",
    "AuthThrottle",
    "auth_middleware",
    "check_origin",
    "is_authorized",
    "publish_pairing_token",
    "read_token_file",
]

logger = logging.getLogger(__name__)

TOKEN_HEADER = "Authorization"

#: Where a Home Assistant App pair meets (ADR 0006 decision 8).
DEFAULT_PAIR_FILE = Path("/share/mcuhome/build-server.token")

#: Application key holding the server state.
STATE_KEY: web.AppKey[Any] = web.AppKey("mcuhome_buildserver_state")

#: Paths served without a token. ``/health`` says what is running and
#: nothing about what it holds, which is what an orchestrator's liveness
#: probe needs and all it may have. Everything else is gated — which
#: today means ``/ws``, and with it every answer about what this server
#: can build: the ``capabilities`` verb names build-container images and
#: patch policy, an inventory of the machine and not something to hand
#: to an unauthenticated caller.
OPEN_PATHS = frozenset({"/health"})


def read_token_file(path: Path) -> str | None:
    """The token in *path*, stripped, or ``None`` when there is no file."""
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return token or None


def publish_pairing_token(token: str, path: Path) -> bool:
    """Write *token* where the dashboard looks for a same-host pair.

    Returns whether it did. Refuses to create the parent directory: its
    existence is the signal that this is a Home Assistant deployment
    with a ``/share`` mount, and creating it would turn "no pair here"
    into "a token file on a machine nobody will ever read it from".
    """
    if not path.parent.is_dir():
        logger.debug("no %s directory; not publishing a pairing token", path.parent)
        return False
    try:
        path.write_text(token + "\n", encoding="utf-8")
        with contextlib.suppress(OSError):
            path.chmod(0o600)
    except OSError as error:
        logger.warning("could not write the pairing token to %s: %s", path, error)
        return False
    logger.info("published the pairing token to %s for the dashboard App to find", path)
    return True


def _presented(request: web.Request) -> str | None:
    """The token this request carries, from the header or the query.

    The query parameter exists for one reason: a browser's ``WebSocket``
    constructor cannot set a request header. It is the same escape hatch
    every WebSocket API ends up with, and it is why the documentation
    says a build server on a network must be behind TLS — a token in a
    URL is a token in an access log.
    """
    header = request.headers.get(TOKEN_HEADER, "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()
    query = request.query.get("token")
    return query.strip() if query and query.strip() else None


def is_authorized(request: web.Request, *, token: str) -> bool:
    """Constant-time comparison of the presented token against *token*."""
    presented = _presented(request)
    if presented is None:
        return False
    return secrets.compare_digest(presented, token)


def check_origin(request: web.Request, *, allowed: tuple[str, ...] = ()) -> bool:
    """Origin check for the WebSocket upgrade.

    A missing ``Origin`` is allowed: the expected client is the
    dashboard's own aiohttp session, which sends none, and a browser
    always sends one — so absence cannot be a browser sneaking past. A
    browser that *does* reach this server is not the design, and it may
    only do so from an origin the operator named.
    """
    origin = request.headers.get("Origin")
    if not origin:
        return True
    if origin in allowed:
        return True
    parts = urlsplit(origin)
    if not parts.scheme or not parts.netloc:
        return False
    host = request.headers.get("Host")
    return bool(host) and parts.netloc == host


# --------------------------------------------------------------------------
# Brute-force resistance for the bearer check
# --------------------------------------------------------------------------

#: Failed authentications from one source before any backoff begins.
#: Small, but not one: a legitimate client that fat-fingers a token, or a
#: dashboard configured with a stale one, should get a plain 401 a few
#: times rather than a lockout on the first mistake.
DEFAULT_AUTH_FREE_ATTEMPTS = 5
#: The first lockout past the free attempts, in seconds, doubling with
#: every further failed round up to :data:`DEFAULT_AUTH_MAX_DELAY`.
DEFAULT_AUTH_BASE_DELAY = 1.0
DEFAULT_AUTH_MAX_DELAY = 300.0
#: Idle-forgiveness: a source that has not failed for this long is
#: forgotten, so an old mistake does not haunt a client that returns much
#: later, and the per-source table does not keep the dead forever.
DEFAULT_AUTH_RESET_AFTER = 900.0
#: The global backstop. Per-source backoff does nothing against an
#: attacker who forges a fresh source address per attempt, so once this
#: many failures have landed across *all* sources within one reset
#: window, the gate closes for everyone for
#: :data:`DEFAULT_AUTH_GLOBAL_LOCK` seconds. Conservative on purpose: it
#: is a floor against a distributed grind, not a per-request throttle, so
#: it sits well above any believable burst of honest misconfiguration.
DEFAULT_AUTH_GLOBAL_THRESHOLD = 100
DEFAULT_AUTH_GLOBAL_LOCK = 30.0
#: How many source addresses the table holds before it evicts the
#: longest-idle one. A bound on memory under a spoofed-source flood; the
#: global backstop above is what actually blunts such a flood.
DEFAULT_AUTH_MAX_TRACKED = 4096


@dataclass
class _Attempts:
    """One source address's recent failed-auth history."""

    failures: int = 0
    locked_until: float = 0.0
    last_seen: float = 0.0


@dataclass
class AuthThrottle:
    """Failed-bearer-auth backoff, keyed on source address, with a backstop.

    The token equals shell access (see the module docstring), and a
    generated token is 256 bits — infeasible to guess. This is not for
    that token: it is for an operator's own weak one, which without a
    throttle can be ground down over the network at line rate. So a
    handful of failures from a source are free, and past that the source
    is locked out for a window that doubles each round; a correct token
    clears the source's history at once, so a legitimate client is never
    held to an attacker's backoff. A conservative global counter is the
    backstop against a grind that forges a fresh source address per try.

    Hardening, not a boundary, and deliberately proportionate: the
    numbers are a security floor rather than an operator policy, so they
    are constants here rather than configuration.
    """

    free_attempts: int = DEFAULT_AUTH_FREE_ATTEMPTS
    base_delay: float = DEFAULT_AUTH_BASE_DELAY
    max_delay: float = DEFAULT_AUTH_MAX_DELAY
    reset_after: float = DEFAULT_AUTH_RESET_AFTER
    global_threshold: int = DEFAULT_AUTH_GLOBAL_THRESHOLD
    global_lock: float = DEFAULT_AUTH_GLOBAL_LOCK
    max_tracked: int = DEFAULT_AUTH_MAX_TRACKED
    #: Injected so tests drive time instead of sleeping through it.
    clock: Callable[[], float] = time.monotonic
    _by_source: dict[str, _Attempts] = field(default_factory=dict)
    _global_failures: int = 0
    _global_window_start: float = 0.0
    _global_locked_until: float = 0.0

    def retry_after(self, source: str) -> float | None:
        """Seconds a caller from *source* must wait, or ``None`` to proceed."""
        now = self.clock()
        if now < self._global_locked_until:
            return self._global_locked_until - now
        state = self._by_source.get(source)
        if state is None:
            return None
        if state.last_seen and now - state.last_seen > self.reset_after:
            del self._by_source[source]
            return None
        if now < state.locked_until:
            return state.locked_until - now
        return None

    def record_failure(self, source: str) -> None:
        """Count one failed authentication and set the next lockout."""
        now = self.clock()
        self._note_global(now)
        state = self._by_source.get(source)
        if state is None:
            self._evict_if_full()
            state = self._by_source.setdefault(source, _Attempts())
        state.failures += 1
        state.last_seen = now
        if state.failures > self.free_attempts:
            step = state.failures - self.free_attempts  # 1, 2, 3, …
            delay = min(self.base_delay * (2 ** (step - 1)), self.max_delay)
            state.locked_until = now + delay

    def record_success(self, source: str) -> None:
        """Forget a source's failures: a correct token proves it is honest."""
        self._by_source.pop(source, None)

    def _note_global(self, now: float) -> None:
        if now - self._global_window_start > self.reset_after:
            self._global_window_start = now
            self._global_failures = 0
        self._global_failures += 1
        if self._global_failures > self.global_threshold:
            self._global_locked_until = now + self.global_lock

    def _evict_if_full(self) -> None:
        if len(self._by_source) < self.max_tracked:
            return
        oldest = min(self._by_source, key=lambda key: self._by_source[key].last_seen)
        del self._by_source[oldest]


@web.middleware
async def auth_middleware(request: web.Request, handler: Any) -> web.StreamResponse:
    """Refuse everything that is not ``/health`` without the token.

    A brute-force backstop sits in front of the token comparison: a
    source that has failed too many times recently is answered ``429``
    with ``Retry-After`` before the comparison runs at all, so the gate
    cannot be ground at line rate. It is checked first because a locked
    source is turned away whatever it presents, and cleared on success so
    the throttle never touches a client with the right token.
    """
    if request.path in OPEN_PATHS:
        return await handler(request)

    state = request.app[STATE_KEY]
    throttle: AuthThrottle = state.auth_throttle
    source = request.remote or "unknown"
    wait = throttle.retry_after(source)
    if wait is not None:
        logger.warning(
            "locked out %s %s from %s for %.0fs (too many failed authentications)",
            request.method,
            request.path,
            source,
            wait,
        )
        raise web.HTTPTooManyRequests(
            text=(
                "Too many failed authentication attempts from this address. Wait for "
                "the interval named in Retry-After and try again."
            ),
            headers={"Retry-After": str(max(1, math.ceil(wait)))},
        )

    if not is_authorized(request, token=state.config.token):
        throttle.record_failure(source)
        logger.warning(
            "refused an unauthenticated %s %s from %s",
            request.method,
            request.path,
            source,
        )
        raise web.HTTPUnauthorized(
            text=(
                "This build server needs its bearer token. The dashboard is "
                "configured with the build server's URL and token; a same-host "
                "Home Assistant pair reads it from /share/mcuhome/."
            ),
            headers={"WWW-Authenticate": 'Bearer realm="MCUHome Build Server"'},
        )
    throttle.record_success(source)
    return await handler(request)
