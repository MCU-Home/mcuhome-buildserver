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

**The ingress caps and the per-session disk quota are options here for
one reason: the config is the policy** (ADR 0019 decision 7, product
owner 2026-08-09/E44). ADR 0019 decision 8 requires five ingress caps
enforced streaming and a per-session disk quota answered typed, and
names no number for any of them; the numbers below are this server's
defaults and an operator's to change. They are deliberately *not*
constants in the module that enforces them — a limit an operator cannot
move is a limit they will work around by other means. The bound on
``context.yaml`` is a sixth cap that no ADR asks for, and it is here
rather than beside its enforcement for exactly that reason: it was a
constant in :mod:`mcuhome_buildserver.contextstore` while the README
advertised its value to operators who had no way to move it.
"""

from __future__ import annotations

import argparse
import os
import secrets
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from mcuhome_buildserver.security import DEFAULT_PAIR_FILE, read_token_file
from mcuhome_buildserver.sessions import PATCH_LAYERS, is_patch_layer_name

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_MAX_COMPRESSED_BYTES",
    "DEFAULT_MAX_CONTEXT_YAML_BYTES",
    "DEFAULT_MAX_DECOMPRESSED_BYTES",
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_PATH_DEPTH",
    "DEFAULT_PORT",
    "DEFAULT_SESSION_QUOTA_BYTES",
    "ENV_PREFIX",
    "Config",
    "build_parser",
    "default_context_root",
    "load_config",
    "resolve_token",
]

ENV_PREFIX = "MCUHOME_BUILDSERVER_"

#: One past the dashboard's 8099, so both Apps can run on one host with
#: no configuration at all.
DEFAULT_PORT = 8100
DEFAULT_HOST = "0.0.0.0"  # noqa: S104 - see the module docstring

#: The five ingress caps of ADR 0019 decision 8, in the order that ADR
#: lists them, and the per-session disk quota of the same decision. Every
#: number is a product-owner choice of 2026-08-09 (E44); no document
#: derives them, so they are stated here once and cited nowhere as if
#: they were normative.
#:
#: They are generous against a real context and mean against a bomb. A
#: device model is kilobytes, a signing public key is under a hundred
#: bytes and a patch is rarely more than a few hundred kilobytes, so a
#: context that approaches 64 MiB compressed is already not a context in
#: the sense the format means.
DEFAULT_MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_ENTRIES = 4096
DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_PATH_DEPTH = 16
DEFAULT_SESSION_QUOTA_BYTES = 2 * 1024 * 1024 * 1024

#: The sixth ingress cap, and the one ADR 0019 decision 8 does not list:
#: how large ``context.yaml`` may be. It exists because a YAML parser is
#: the single place in this server where a small input buys unbounded
#: work, so the pin document gets a bound of its own instead of sharing
#: the per-file cap with a multi-megabyte patch. It is here, next to the
#: other six numbers, for the reason the module docstring gives for all
#: of them — a cap that is advertised to operators and unreachable by
#: them is the worst of both. Product-owner decision of 2026-08-09,
#: together with safe-load, no duplicate keys and no anchors; the number
#: is this server's default and an operator's to change.
DEFAULT_MAX_CONTEXT_YAML_BYTES = 64 * 1024


def default_context_root(env: Mapping[str, str]) -> Path:
    """Where per-session context directories live when nobody says.

    A build server holds a context only for the life of a session — it
    is deleted at ``close-session`` together with every artifact
    (ADR 0019's amendment) — so this is *state*, not data to preserve,
    and the XDG state directory is where state belongs.

    The last fallback is the temporary directory rather than the account
    database, for the reason :mod:`mcuhome.model.userpaths` records
    against ``Path.home()``: a server started by systemd runs with no
    ``HOME`` at all, and answering that from ``/etc/passwd`` picks a
    directory the operator did not ask for. Here the consequence would
    be a session tree appearing under somebody's home when the operator
    thought they were running a system service, so the fallback is a
    location that is obviously ephemeral instead of one that looks
    deliberate. ``--context-root`` is how an operator says.
    """
    state = env.get("XDG_STATE_HOME")
    if state and state.strip():
        base = Path(state.strip())
    elif env.get("HOME", "").strip():
        base = Path(env["HOME"].strip()) / ".local" / "state"
    else:
        base = Path(tempfile.gettempdir())
    return base / "mcuhome-build-server" / "sessions"


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

    #: Where the per-session directories are created. One directory per
    #: session, named by session id, holding the context the session
    #: received; deleted at ``close-session``, at lease expiry, and on a
    #: refused upload. Resolved from the environment only when nobody
    #: configured one — see :func:`default_context_root`.
    context_root: Path = field(default_factory=lambda: default_context_root(os.environ))

    #: The five ingress caps of ADR 0019 decision 8. All five are
    #: enforced *while bytes are arriving*, never after buffering them;
    #: the first three count **cumulatively across the base context and
    #: every extension** (E44), because a session's footprint is what
    #: they bound, not one archive's.
    max_compressed_bytes: int = DEFAULT_MAX_COMPRESSED_BYTES
    max_decompressed_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES
    max_entries: int = DEFAULT_MAX_ENTRIES
    #: Per file, so one entry cannot spend the whole cumulative budget.
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    #: Path segments, ``patches/zephyr/0001-fix.patch`` being three.
    max_path_depth: int = DEFAULT_MAX_PATH_DEPTH
    #: The sixth cap: how large ``context.yaml`` may be before it is
    #: parsed at all. Not one of ADR 0019 decision 8's five, and here for
    #: the same reason they are.
    max_context_yaml_bytes: int = DEFAULT_MAX_CONTEXT_YAML_BYTES

    #: The per-session disk quota of the same decision — "typed
    #: quota-exceeded instead of host exhaustion". Today only the
    #: context spends it; ``/out`` joins when there are build outputs.
    session_quota_bytes: int = DEFAULT_SESSION_QUOTA_BYTES

    #: True when :func:`load_config` had to invent the token, so that
    #: startup can print it exactly once.
    token_generated: bool = field(default=False, compare=False)

    def site_summary(self) -> str:
        return f"http://{self.host}:{self.port} (bearer token required)"


#: The six ingress caps, as ``(option, attribute, default, help)``. One
#: table drives the command line, the environment and the defaults, so a
#: cap cannot exist in one of the three and not the others — which is
#: also why ``--max-context-yaml-bytes`` is an entry here rather than a
#: constant in the module that enforces it.
_CAP_OPTIONS: tuple[tuple[str, str, int, str], ...] = (
    (
        "--max-compressed-bytes",
        "max_compressed_bytes",
        DEFAULT_MAX_COMPRESSED_BYTES,
        "the archive bytes a session may upload in total",
    ),
    (
        "--max-decompressed-bytes",
        "max_decompressed_bytes",
        DEFAULT_MAX_DECOMPRESSED_BYTES,
        "the cumulative unpacked bytes a session may produce",
    ),
    (
        "--max-entries",
        "max_entries",
        DEFAULT_MAX_ENTRIES,
        "the archive entries a session may deliver in total",
    ),
    ("--max-file-bytes", "max_file_bytes", DEFAULT_MAX_FILE_BYTES, "the size of one context file"),
    (
        "--max-path-depth",
        "max_path_depth",
        DEFAULT_MAX_PATH_DEPTH,
        "the path segments one context entry may have",
    ),
    (
        "--max-context-yaml-bytes",
        "max_context_yaml_bytes",
        DEFAULT_MAX_CONTEXT_YAML_BYTES,
        "the size of the context.yaml pin document, bounded before it is parsed",
    ),
)

_LIMIT_ATTRIBUTES: tuple[str, ...] = tuple(entry[1] for entry in _CAP_OPTIONS) + (
    "session_quota_bytes",
)


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
        # Deliberately no `choices=`: contract v1 fixes four layer names
        # and reserves the `x-` prefix for third-party ones, so the set
        # of *nameable* layers is open while the set of *allowed* ones
        # stays this option's answer. Validation is in `load_config`,
        # which can say why an `x-` name is fine and `kernel` is not.
        help=(
            "session protocol v2: allow build contexts to carry patches for this "
            f"layer ({', '.join(PATCH_LAYERS)}, or a third-party x-* name; "
            "repeatable). Unlisted layers are denied — the config is the policy"
        ),
    )
    parser.add_argument(
        "--context-root",
        type=Path,
        metavar="PATH",
        help=(
            "directory the per-session context directories are created in "
            "(default: the XDG state directory)"
        ),
    )
    for option, attribute, default, what in _CAP_OPTIONS:
        parser.add_argument(
            option,
            type=int,
            metavar="N",
            dest=attribute,
            help=f"ingress cap: {what} (default {default})",
        )
    parser.add_argument(
        "--session-quota-bytes",
        type=int,
        metavar="N",
        dest="session_quota_bytes",
        help=(
            "per-session disk quota in bytes, answered typed rather than by host "
            f"exhaustion (default {DEFAULT_SESSION_QUOTA_BYTES})"
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
    unknown_layers = sorted(name for name in patch_layers if not is_patch_layer_name(name))
    if unknown_layers:
        raise SystemExit(
            f"{', '.join(unknown_layers)}: not a patch layer this server knows "
            f"(known: {', '.join(PATCH_LAYERS)}; a third-party layer name must "
            "carry the x- prefix the contract reserves for it)."
        )

    context_root = path_option(args.context_root, "CONTEXT_ROOT")
    if context_root is None:
        context_root = default_context_root(env)

    limits: dict[str, int] = {}
    for attribute in _LIMIT_ATTRIBUTES:
        value = getattr(args, attribute, None)
        if value is None:
            value = _env_int(env, attribute.upper())
        if value is None:
            continue
        if value <= 0:
            raise SystemExit(f"--{attribute.replace('_', '-')} must be a positive number of bytes.")
        limits[attribute] = value

    config = Config(
        host=args.host or env.get(ENV_PREFIX + "HOST") or DEFAULT_HOST,
        port=args.port or _env_int(env, "PORT") or DEFAULT_PORT,
        pair_file=pair_file,
        allowed_origins=tuple(dict.fromkeys(origins)),
        log_level=args.log_level or env.get(ENV_PREFIX + "LOG_LEVEL") or "INFO",
        allowed_patch_layers=tuple(dict.fromkeys(patch_layers)),
        context_root=context_root,
        **limits,
    )

    token, generated = resolve_token(args.token, args.token_file, env)
    return replace(config, token=token, token_generated=generated)
