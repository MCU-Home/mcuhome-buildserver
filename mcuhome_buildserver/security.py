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
authenticated session is equivalent to shell access.** A job runs a
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
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from aiohttp import web

__all__ = [
    "DEFAULT_PAIR_FILE",
    "STATE_KEY",
    "TOKEN_HEADER",
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
#: probe needs and all it may have. Everything else — ``/capabilities``
#: included, because it names versions and an image tag — is gated.
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


@web.middleware
async def auth_middleware(request: web.Request, handler: Any) -> web.StreamResponse:
    """Refuse everything that is not ``/health`` without the token."""
    if request.path in OPEN_PATHS:
        return await handler(request)

    state = request.app[STATE_KEY]
    if not is_authorized(request, token=state.config.token):
        logger.warning(
            "refused an unauthenticated %s %s from %s",
            request.method,
            request.path,
            request.remote,
        )
        raise web.HTTPUnauthorized(
            text=(
                "This build server needs its bearer token. The dashboard is "
                "configured with the build server's URL and token; a same-host "
                "Home Assistant pair reads it from /share/mcuhome/."
            ),
            headers={"WWW-Authenticate": 'Bearer realm="MCUHome Build Server"'},
        )
    return await handler(request)
