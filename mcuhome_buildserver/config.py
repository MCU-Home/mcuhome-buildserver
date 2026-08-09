# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Runtime configuration: command line, environment, defaults.

Every option has an environment form prefixed ``MCUHOME_BUILDSERVER_``
and the command line wins, which is the same rule the dashboard follows:
the environment is what an App's ``run`` script and a ``docker run``
use, the command line is what a person uses.

Two defaults are decisions rather than conveniences.

**The bind address is ``0.0.0.0``.** The dashboard defaults to loopback
because a dashboard on loopback is still a dashboard; a build server on
loopback is a build server nobody can open a session against. ADR 0003
makes it a separate machine by construction — that is the whole
topology — so the useful default is the one that works, and the safety
comes from the other decision below rather than from the binding.

**A token is not optional.** There is no configuration in which this
server listens without one. Configure it and it is used; do not, and one
is generated at startup, logged once, and written to the pairing file if
this is a Home Assistant App pair. What there is no way to ask for is a
build server with authentication switched off.
"""

from __future__ import annotations

import argparse
import os
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from mcuhome_buildserver.security import DEFAULT_PAIR_FILE, read_token_file
from mcuhome_buildserver.sessions import PATCH_LAYERS

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "ENV_PREFIX",
    "Config",
    "build_parser",
    "load_config",
    "resolve_token",
]

ENV_PREFIX = "MCUHOME_BUILDSERVER_"

#: One past the dashboard's 8099, so both Apps can run on one host with
#: no configuration at all.
DEFAULT_PORT = 8100
DEFAULT_HOST = "0.0.0.0"  # noqa: S104 - see the module docstring


@dataclass(frozen=True)
class Config:
    """Everything the server needs before it binds a socket."""

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    #: Never ``None``: :func:`load_config` generates one when it must.
    token: str = ""
    #: Where the token is published for a same-host App pair, or ``None``.
    pair_file: Path | None = DEFAULT_PAIR_FILE

    allowed_origins: tuple[str, ...] = ()
    log_level: str = "INFO"

    #: Session protocol v2: the patch layers a build context may carry
    #: patches for. **The config is the policy** — empty by default, and
    #: unlisted layers are denied; there is no permissive mode to
    #: forget to switch off.
    allowed_patch_layers: tuple[str, ...] = ()

    #: True when :func:`load_config` had to invent the token, so that
    #: startup can print it exactly once.
    token_generated: bool = field(default=False, compare=False)

    def site_summary(self) -> str:
        return f"http://{self.host}:{self.port} (bearer token required)"


def _env_int(env: Mapping[str, str], name: str) -> int | None:
    raw = env.get(ENV_PREFIX + name)
    if raw is None or not raw.strip():
        return None
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"{ENV_PREFIX + name} must be a whole number, not {raw!r}.") from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcuhome-build-server",
        description=(
            "Headless MCUHome build service. Drives build environments over the "
            "session protocol and is never one itself; never stores a configuration "
            "tree and never holds a signing key."
        ),
    )
    parser.add_argument("--host", metavar="ADDRESS", help=f"bind address (default {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, metavar="PORT", help=f"port (default {DEFAULT_PORT})")
    parser.add_argument(
        "--token",
        metavar="TOKEN",
        help=(
            "bearer token clients must present; prefer the environment variable or "
            "--token-file, since a command line is visible to every process on the machine"
        ),
    )
    parser.add_argument(
        "--token-file", type=Path, metavar="PATH", help="read the bearer token from this file"
    )
    parser.add_argument(
        "--pair-file",
        type=Path,
        metavar="PATH",
        help=(
            "publish the token here for a same-host dashboard to find "
            f"(default {DEFAULT_PAIR_FILE}, written only if its directory exists)"
        ),
    )
    parser.add_argument(
        "--no-pair-file",
        dest="pair_file",
        action="store_const",
        const=Path("-"),
        help="never publish the token to a file",
    )
    parser.add_argument(
        "--allowed-origin",
        action="append",
        metavar="ORIGIN",
        dest="allowed_origins",
        help="accepted browser origin for the WebSocket upgrade (repeatable)",
    )
    parser.add_argument(
        "--allow-patch-layer",
        action="append",
        metavar="LAYER",
        dest="allowed_patch_layers",
        choices=sorted(PATCH_LAYERS),
        help=(
            "session protocol v2: allow build contexts to carry patches for this "
            f"layer ({', '.join(PATCH_LAYERS)}; repeatable). Unlisted layers are "
            "denied — the config is the policy"
        ),
    )
    parser.add_argument(
        "--log-level",
        metavar="LEVEL",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="logging verbosity (default INFO)",
    )
    return parser


def resolve_token(
    configured: str | None, token_file: Path | None, env: Mapping[str, str]
) -> tuple[str, bool]:
    """Find the bearer token, or make one. Returns ``(token, generated)``.

    A generated token is returned rather than logged, because logging it
    must happen exactly once and at a level the operator actually sees —
    which is the caller's decision, not this function's.
    """
    if configured:
        return configured, False
    from_env = env.get(ENV_PREFIX + "TOKEN")
    if from_env and from_env.strip():
        return from_env.strip(), False
    candidates = [token_file] if token_file else []
    env_file = env.get(ENV_PREFIX + "TOKEN_FILE")
    if env_file:
        candidates.append(Path(env_file))
    for path in candidates:
        existing = read_token_file(path)
        if existing:
            return existing, False
    return secrets.token_urlsafe(32), True


def load_config(
    argv: Sequence[str] | None = None, *, env: Mapping[str, str] | None = None
) -> Config:
    """Build a :class:`Config` from the command line and the environment."""
    env = os.environ if env is None else env
    args = build_parser().parse_args(list(argv) if argv is not None else None)

    def path_option(value: Path | None, name: str) -> Path | None:
        if value is not None:
            return value
        raw = env.get(ENV_PREFIX + name)
        return Path(raw) if raw else None

    pair_file = path_option(args.pair_file, "PAIR_FILE")
    if pair_file is None:
        pair_file = DEFAULT_PAIR_FILE
    elif str(pair_file) == "-":
        pair_file = None

    origins = list(args.allowed_origins or ())
    if env.get(ENV_PREFIX + "ALLOWED_ORIGINS"):
        origins += [
            item.strip() for item in env[ENV_PREFIX + "ALLOWED_ORIGINS"].split(",") if item.strip()
        ]

    patch_layers = list(args.allowed_patch_layers or ())
    if env.get(ENV_PREFIX + "ALLOW_PATCH_LAYERS"):
        patch_layers += [
            item.strip()
            for item in env[ENV_PREFIX + "ALLOW_PATCH_LAYERS"].split(",")
            if item.strip()
        ]
    unknown_layers = sorted(set(patch_layers) - set(PATCH_LAYERS))
    if unknown_layers:
        raise SystemExit(
            f"{', '.join(unknown_layers)}: not a patch layer this server knows "
            f"(known: {', '.join(PATCH_LAYERS)})."
        )

    config = Config(
        host=args.host or env.get(ENV_PREFIX + "HOST") or DEFAULT_HOST,
        port=args.port or _env_int(env, "PORT") or DEFAULT_PORT,
        pair_file=pair_file,
        allowed_origins=tuple(dict.fromkeys(origins)),
        log_level=args.log_level or env.get(ENV_PREFIX + "LOG_LEVEL") or "INFO",
        allowed_patch_layers=tuple(dict.fromkeys(patch_layers)),
    )

    token, generated = resolve_token(args.token, args.token_file, env)
    return replace(config, token=token, token_generated=generated)
