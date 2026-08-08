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
loopback is a build server nobody can submit to. ADR 0003 makes it a
separate machine by construction — that is the whole topology — so the
useful default is the one that works, and the safety comes from the
other decision below rather than from the binding.

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

from mcuhome_buildserver import builder
from mcuhome_buildserver.security import DEFAULT_PAIR_FILE, read_token_file
from mcuhome_buildserver.sessions import PATCH_LAYERS

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_JOB_TIMEOUT",
    "DEFAULT_KEEP_JOBS",
    "DEFAULT_PORT",
    "DEFAULT_SLOTS",
    "DEFAULT_TTL_DAYS",
    "ENV_PREFIX",
    "Config",
    "build_parser",
    "default_jobs_root",
    "load_config",
    "resolve_token",
]

ENV_PREFIX = "MCUHOME_BUILDSERVER_"

#: One past the dashboard's 8099, so both Apps can run on one host with
#: no configuration at all.
DEFAULT_PORT = 8100
DEFAULT_HOST = "0.0.0.0"  # noqa: S104 - see the module docstring

#: ADR 0006 decision 5: compile lane = 1, as a hard default.
DEFAULT_SLOTS = 1

#: ADR 0008 decision 4: a cap and a time-to-live, both on by default.
DEFAULT_KEEP_JOBS = 20
DEFAULT_TTL_DAYS = 14.0

#: A cold Zephyr+Matter build is 13:38 on a slow machine. An hour is a
#: budget that never fires for a healthy build and always fires for a
#: hung one.
DEFAULT_JOB_TIMEOUT = 3600.0


def default_jobs_root(env: Mapping[str, str] | None = None) -> Path:
    """Where jobs live when nobody said.

    ``/data`` is a Home Assistant App's private volume (ADR 0008) and is
    the right answer whenever it exists. Outside one, a state directory
    under the user's home is the answer that does not need root and does
    not surprise anyone by appearing in the current directory.
    """
    env = os.environ if env is None else env
    if Path("/data").is_dir():
        return Path("/data/jobs")
    base = env.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "mcuhome-build-server" / "jobs"


@dataclass(frozen=True)
class Config:
    """Everything the server needs before it binds a socket."""

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    #: Never ``None``: :func:`load_config` generates one when it must.
    token: str = ""
    #: Where the token is published for a same-host App pair, or ``None``.
    pair_file: Path | None = DEFAULT_PAIR_FILE

    jobs_root: Path = field(default_factory=default_jobs_root)
    #: West workspace top directory — the builder's working directory.
    #: ``None`` lets the builder discover it (ADR 0003 bakes it into the
    #: image, so in the shipped container this is set and present).
    workspace: Path | None = None

    slots: int = DEFAULT_SLOTS
    #: ``MCUHOME_JOBS`` for the child process.
    build_jobs: int | None = None
    native: bool = False
    image: str | None = None
    job_timeout: float = DEFAULT_JOB_TIMEOUT

    keep_jobs: int = DEFAULT_KEEP_JOBS
    ttl_days: float = DEFAULT_TTL_DAYS

    builder_command: tuple[str, ...] = builder.BUILDER_COMMAND
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


def _env_float(env: Mapping[str, str], name: str) -> float | None:
    raw = env.get(ENV_PREFIX + name)
    if raw is None or not raw.strip():
        return None
    try:
        return float(raw)
    except ValueError:
        raise SystemExit(f"{ENV_PREFIX + name} must be a number, not {raw!r}.") from None


def _env_flag(raw: str | None) -> bool | None:
    if raw is None:
        return None
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcuhome-build-server",
        description=(
            "Headless MCUHome build service. Takes a resolved device model over the "
            "MCUHome build protocol and compiles it; never stores a configuration "
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
        "--jobs-root",
        type=Path,
        metavar="PATH",
        help="directory holding one sub-directory per job (default /data/jobs inside an App)",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        metavar="PATH",
        help=(
            "west workspace top directory the builder compiles in (default: let the "
            "builder discover it)"
        ),
    )
    parser.add_argument(
        "--slots",
        type=int,
        metavar="N",
        help=(
            f"concurrent compiles (default {DEFAULT_SLOTS}; raising it trades every "
            "job's latency for almost no throughput)"
        ),
    )
    parser.add_argument(
        "--build-jobs",
        type=int,
        metavar="N",
        help=(
            "parallel compiler jobs inside one build (MCUHOME_JOBS for the builder; "
            "default: the builder's own detection)"
        ),
    )
    parser.add_argument(
        "--native",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "compile on this machine's own toolchain instead of in the builder "
            "container (a development escape hatch; the container is the build "
            "environment)"
        ),
    )
    parser.add_argument("--image", metavar="REF", help="builder container image tag to compile in")
    parser.add_argument(
        "--job-timeout",
        type=float,
        metavar="SECONDS",
        help=f"kill a build that runs longer than this (default {DEFAULT_JOB_TIMEOUT:.0f})",
    )
    parser.add_argument(
        "--keep-jobs",
        type=int,
        metavar="N",
        help=f"how many finished jobs to keep on disk (default {DEFAULT_KEEP_JOBS})",
    )
    parser.add_argument(
        "--job-ttl-days",
        type=float,
        metavar="DAYS",
        help=f"delete finished jobs older than this (default {DEFAULT_TTL_DAYS:.0f})",
    )
    parser.add_argument(
        "--builder-command",
        metavar="PROGRAM",
        help="the builder executable to spawn (default mcuhome)",
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

    jobs_root = path_option(args.jobs_root, "JOBS_ROOT") or default_jobs_root(env)
    workspace = path_option(args.workspace, "WORKSPACE")

    pair_file = path_option(args.pair_file, "PAIR_FILE")
    if pair_file is None:
        pair_file = DEFAULT_PAIR_FILE
    elif str(pair_file) == "-":
        pair_file = None

    native = args.native
    if native is None:
        native = _env_flag(env.get(ENV_PREFIX + "NATIVE"))
    if native is None:
        native = False

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

    command = args.builder_command or env.get(ENV_PREFIX + "BUILDER_COMMAND")

    def number(cli: float | None, name: str, fallback: float) -> float:
        if cli is not None:
            return cli
        from_env = _env_float(env, name)
        return fallback if from_env is None else from_env

    def whole(cli: int | None, name: str, fallback: int) -> int:
        """Explicitly ``None``-checked: ``0`` is a value, not an absence."""
        if cli is not None:
            return cli
        from_env = _env_int(env, name)
        return fallback if from_env is None else from_env

    keep_jobs = whole(args.keep_jobs, "KEEP_JOBS", DEFAULT_KEEP_JOBS)
    slots = whole(args.slots, "SLOTS", DEFAULT_SLOTS)
    build_jobs = args.build_jobs if args.build_jobs is not None else _env_int(env, "BUILD_JOBS")

    config = Config(
        host=args.host or env.get(ENV_PREFIX + "HOST") or DEFAULT_HOST,
        port=args.port or _env_int(env, "PORT") or DEFAULT_PORT,
        pair_file=pair_file,
        jobs_root=jobs_root.expanduser(),
        workspace=workspace.expanduser().resolve() if workspace else None,
        slots=slots,
        build_jobs=build_jobs,
        native=native,
        image=args.image or env.get(ENV_PREFIX + "IMAGE") or None,
        job_timeout=number(args.job_timeout, "JOB_TIMEOUT", DEFAULT_JOB_TIMEOUT),
        keep_jobs=keep_jobs,
        ttl_days=number(args.job_ttl_days, "JOB_TTL_DAYS", DEFAULT_TTL_DAYS),
        builder_command=(command,) if command else builder.BUILDER_COMMAND,
        allowed_origins=tuple(dict.fromkeys(origins)),
        log_level=args.log_level or env.get(ENV_PREFIX + "LOG_LEVEL") or "INFO",
        allowed_patch_layers=tuple(dict.fromkeys(patch_layers)),
    )

    token, generated = resolve_token(args.token, args.token_file, env)
    if config.slots < 1:
        raise SystemExit("--slots must be at least 1; a build server with no lane builds nothing.")
    return replace(config, token=token, token_generated=generated)
