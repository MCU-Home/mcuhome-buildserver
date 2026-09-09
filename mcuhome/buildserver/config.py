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
loopback is a build server nobody can open a session against. The
two-App topology makes it a separate machine by construction — that is the whole
topology — so the useful default is the one that works, and the safety
comes from the other decision below rather than from the binding.

**A token is not optional.** There is no configuration in which this
server listens without one. Configure it and it is used; do not, and one
is generated at startup, logged once, and written to the pairing file if
this is a Home Assistant App pair. What there is no way to ask for is a
build server with authentication switched off.

**The ingress caps and the per-session disk quota are options here for
one reason: the config is the policy** (product owner, 2026-08-09). The
hardening floor for shared servers requires five ingress caps enforced
streaming and a per-session disk quota answered typed, and names no
number for any of them; the numbers below are this server's defaults
and an operator's to change. They are deliberately *not* constants in
the module that enforces them — a limit an operator cannot move is a
limit they will work around by other means. The bound on
``context.yaml`` is a sixth cap that nothing else asks for, and it is
here rather than beside its enforcement for exactly that reason: it was
a constant in :mod:`mcuhome.buildserver.contextstore` while the README
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

from mcuhome.model.buildenvironment import ENVIRONMENT_IMAGE_REPOSITORY

from mcuhome.buildserver.environments import repository_of
from mcuhome.buildserver.security import DEFAULT_PAIR_FILE, read_token_file
from mcuhome.buildserver.sessions import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_MAX_OPEN_SESSIONS,
    DEFAULT_MAX_SEATS,
    DEFAULT_RECONNECT_GRACE,
    DEFAULT_SEAT_RETRY_MAX_SECONDS,
    DEFAULT_SEAT_RETRY_SECONDS,
    PATCH_LAYERS,
    is_patch_layer_name,
)

__all__ = [
    "DEFAULT_BUILD_DEADLINE_SECONDS",
    "DEFAULT_CANCEL_GRACE_SECONDS",
    "DEFAULT_CONTAINER_MEMORY",
    "DEFAULT_CONTAINER_PIDS",
    "DEFAULT_DOCKER",
    "DEFAULT_HOST",
    "DEFAULT_MAX_ARTIFACT_BYTES",
    "DEFAULT_MAX_COMPRESSED_BYTES",
    "DEFAULT_MAX_CONNECTIONS",
    "DEFAULT_MAX_CONTEXT_YAML_BYTES",
    "DEFAULT_MAX_DECOMPRESSED_BYTES",
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_INFLIGHT_COMMANDS",
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

#: The five ingress caps of the hardening floor for shared servers, in
#: the order they are usually listed, and the per-session disk quota
#: alongside them. Every number is a product-owner choice of
#: 2026-08-09; no document derives them, so they are stated here once
#: and cited nowhere as if they were normative.
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

#: The sixth ingress cap, and one the hardening floor above does not
#: list: how large ``context.yaml`` may be. It exists because a YAML parser is
#: the single place in this server where a small input buys unbounded
#: work, so the pin document gets a bound of its own instead of sharing
#: the per-file cap with a multi-megabyte patch. It is here, next to the
#: other six numbers, for the reason the module docstring gives for all
#: of them — a cap that is advertised to operators and unreachable by
#: them is the worst of both. Product-owner decision of 2026-08-09,
#: together with safe-load, no duplicate keys and no anchors; the number
#: is this server's default and an operator's to change.
DEFAULT_MAX_CONTEXT_YAML_BYTES = 64 * 1024

#: The container runtime this server drives. A name rather than a path,
#: looked up on the server's own ``PATH``: an operator who wants
#: ``podman`` says so, and an operator who wants a wrapper script names
#: it here rather than shadowing ``docker`` for the whole account.
DEFAULT_DOCKER = "docker"

#: ``limits.deadline_seconds`` — relative to program start, advisory to
#: the program and **enforced here**. Ninety minutes: generous
#: against a cold Matter build, mean against one that is not going to
#: end. A program that honours the advisory value stops itself and says
#: ``error.deadline.exceeded``; one that does not gets the liveness
#: ladder of :mod:`mcuhome.buildserver.backend`.
DEFAULT_BUILD_DEADLINE_SECONDS = 5400

#: ``limits.cancel_grace_seconds`` — how long a cooperative program has
#: to notice the cancel sentinel and write a ``cancelled`` result before
#: the hard path starts. Sixty seconds, which is long enough to finish
#: writing an artifact and short enough that a client waiting on a
#: cancel is not left guessing.
DEFAULT_CANCEL_GRACE_SECONDS = 60

#: The egress size cap, per artifact, applied during
#: enumeration, from the bytes on disk — an artifact entry declares no
#: size. Separate from the ingress caps because it bounds the opposite
#: direction: what the least trusted component in the system may put on
#: the wire towards other people's machines.
DEFAULT_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024

#: The memory one build step of a session may use, in ``docker run
#: --memory`` spelling. It is **both halves of the budget**: the number
#: is written into the request document as the recommendation the build
#: environment sizes itself from (build environment specification §6.1)
#: and set on the container as the hard limit the runtime holds it to.
#: There is a number here rather than a hope because without one a
#: single build's linker takes the host down and every other session
#: with it. Eight gibibytes is generous against a cold Matter build and
#: mean against a runaway; the empty string is an operator saying this
#: host is not to be bounded by memory.
DEFAULT_CONTAINER_MEMORY = "8g"

#: ``docker run --pids-limit`` for the same container. A build legitimately
#: spawns hundreds of short-lived children — which is why ``--init`` is
#: there at all — and a fork bomb spawns them faster; four thousand is
#: past any real toolchain and short of a host that stops scheduling.
#: It is the one limit that is only ever hard: no document asks an
#: environment how many processes it means to have.
DEFAULT_CONTAINER_PIDS = 4096

#: Concurrent ``/ws`` connections this server accepts, and in-flight
#: command tasks one connection may run at once. Both are **hardening,
#: not a trust boundary**: the bearer token already equals shell access
#: (security.py), so a token holder can do worse than open sockets — the
#: point is only that an authenticated flood cannot grow the connection
#: set or the per-connection task set without bound. The numbers are
#: generous against a real client (a single principal opens a handful of
#: connections and pipelines a few commands on each) and mean against a
#: flood, and they are options for the same reason every other limit here
#: is: the config is the policy.
DEFAULT_MAX_CONNECTIONS = 64
DEFAULT_MAX_INFLIGHT_COMMANDS = 32


def default_context_root(env: Mapping[str, str]) -> Path:
    """Where per-session context directories live when nobody says.

    A build server holds a context only for the life of a session — it
    is deleted at ``close-session`` together with every artifact
    — so this is *state*, not data to preserve,
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
    return base / "mcuhome-buildserver" / "sessions"


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

    #: The ``/ws`` connection and per-connection concurrency caps. See the
    #: module-level defaults: hardening against an authenticated flood,
    #: not a trust boundary, since the token already equals shell.
    max_connections: int = DEFAULT_MAX_CONNECTIONS
    max_inflight_commands: int = DEFAULT_MAX_INFLIGHT_COMMANDS

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

    #: The five ingress caps of the hardening floor for shared servers.
    #: All five are enforced *while bytes are arriving*, never after
    #: buffering them; the first three count **cumulatively across the
    #: base context and every extension**, because a session's footprint
    #: is what they bound, not one archive's.
    max_compressed_bytes: int = DEFAULT_MAX_COMPRESSED_BYTES
    max_decompressed_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES
    max_entries: int = DEFAULT_MAX_ENTRIES
    #: Per file, so one entry cannot spend the whole cumulative budget.
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    #: Path segments, ``patches/zephyr/0001-fix.patch`` being three.
    max_path_depth: int = DEFAULT_MAX_PATH_DEPTH
    #: The sixth cap: how large ``context.yaml`` may be before it is
    #: parsed at all. Not one of the hardening floor's five, and here for
    #: the same reason they are.
    max_context_yaml_bytes: int = DEFAULT_MAX_CONTEXT_YAML_BYTES

    #: The per-session disk quota alongside them — "typed
    #: quota-exceeded instead of host exhaustion". It meters what a
    #: **client** put on this host: the context, and the SDK package
    #: deliberately not (that one is the operator's own file, and
    #: charging it would let a package's size decide whether a context
    #: fits). What a build writes into ``out`` is bounded by
    #: :attr:`max_artifact_bytes` per artifact at egress instead, which
    #: is where the cap belongs — the only place a number
    #: can be measured from the bytes on disk.
    session_quota_bytes: int = DEFAULT_SESSION_QUOTA_BYTES

    #: The container runtime, and the numbers that bound one invocation.
    #: All of them are configuration for the same reason the ingress caps
    #: are — the config is the policy, and a number an operator cannot
    #: move is a number they will work around.
    docker: str = DEFAULT_DOCKER
    build_deadline_seconds: int = DEFAULT_BUILD_DEADLINE_SECONDS
    cancel_grace_seconds: int = DEFAULT_CANCEL_GRACE_SECONDS
    #: The idle half of the session lease (:data:`_SESSION_OPTIONS`). The
    #: hard half is not here: it is derived from the build deadline.
    session_idle_timeout_seconds: int = int(DEFAULT_IDLE_TIMEOUT)
    #: How many sessions may be open at once, and how a client that finds
    #: them all taken is made to wait (:data:`_ADMISSION_OPTIONS`).
    max_sessions: int = DEFAULT_MAX_OPEN_SESSIONS
    seat_retry_seconds: int = int(DEFAULT_SEAT_RETRY_SECONDS)
    seat_retry_max_seconds: int = int(DEFAULT_SEAT_RETRY_MAX_SECONDS)
    max_seats: int = DEFAULT_MAX_SEATS
    reconnect_grace_seconds: int = int(DEFAULT_RECONNECT_GRACE)
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES

    #: What one build step of a session is given, and held to. The CPU
    #: and memory figures are **both** halves of the budget: they travel
    #: in the request document as the recommendation the environment
    #: sizes itself from and are set on the container as the hard limits
    #: the runtime enforces, because an environment cannot be trusted to
    #: stay inside a recommendation — it may have a bug and run amok.
    #: ``container_cpus`` unset means this host's CPU count
    #: (:func:`~mcuhome.buildserver.backend.session_limits`), which is
    #: what a build gets when nobody said otherwise.
    container_memory: str | None = DEFAULT_CONTAINER_MEMORY
    container_cpus: str | None = None
    container_pids: int | None = DEFAULT_CONTAINER_PIDS

    #: The build environments this server is willing to run, as
    #: repositories — no tag, no digest. It is **two things at once** and
    #: both are always enforced: the search list an environment is looked
    #: for in when a context brings no pin, walked in order, and the
    #: boundary a pin that names a repository has to be inside. Without
    #: it a client's pin would decide which of this host's images gets
    #: started with a session's mounts under it.
    #: Defaults to MCUHome's own build environment, which is what this
    #: server exists to run; stating the option at all replaces that
    #: default rather than adding to it, because an operator who lists
    #: their own images must also be able to stop serving ours.
    allowed_environments: tuple[str, ...] = (ENVIRONMENT_IMAGE_REPOSITORY,)

    #: Fetch an allowed build environment this host does not have yet.
    #: On by default: the environment is pinned to a digest and its
    #: repository is on the list above, so there is exactly one set of
    #: bytes that answers and fetching it is a convenience rather than a
    #: decision. ``False`` is the server whose images an operator places
    #: deliberately — an air-gapped one, or one that will not spend a
    #: gigabyte of transfer on a client's say-so.
    auto_pull: bool = True

    #: The operator's own **mirror** of the packages a session needs, in
    #: search order: directories holding ``mcuhome-sdk-<version>.tar.zst``
    #: and the package index beside it. Searched first, and a server that
    #: holds what its sessions pin never opens a socket for them.
    #:
    #: Empty by default, and that is not the same as having no source:
    #: behind these directories is MCUHome's own package registry,
    #: checked against the trust anchor the workbench ships and against
    #: nothing else. There is deliberately no option for that registry —
    #: no second domain, no other anchor — because a build server is an
    #: operator's machine and not a project, and a trust root that could
    #: be pointed elsewhere by a flag would be a trust decision made
    #: where nobody looks.
    sdk_sources: tuple[Path, ...] = ()

    #: An optional shared ccache, offered to every invocation
    #: **read-only** for untrusted work. There is deliberately no
    #: way to ask for a writable one: cache warming is a deliberate
    #: operator invocation with a writable cache and trusted contexts
    #: only, which is a verb this server does not have, and an option
    #: that made an untrusted build's cache writable would be the one
    #: setting that turns a shared cache into a shared attack surface.
    ccache_dir: Path | None = None

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

#: The backend's own numbers, as ``(option, attribute, default, help)``.
#: Same table shape as the caps and for the same reason: one table
#: drives the command line, the environment and the defaults, so a knob
#: cannot exist in one of the three and not the others.
_BACKEND_OPTIONS: tuple[tuple[str, str, int, str], ...] = (
    (
        "--build-deadline-seconds",
        "build_deadline_seconds",
        DEFAULT_BUILD_DEADLINE_SECONDS,
        "how long one invocation may run before this server stops it",
    ),
    (
        "--cancel-grace-seconds",
        "cancel_grace_seconds",
        DEFAULT_CANCEL_GRACE_SECONDS,
        "how long a cancelled invocation has to stop itself before the hard path",
    ),
    (
        "--max-artifact-bytes",
        "max_artifact_bytes",
        DEFAULT_MAX_ARTIFACT_BYTES,
        "egress cap: the size of one artifact this server will serve",
    ),
    (
        "--container-pids",
        "container_pids",
        DEFAULT_CONTAINER_PIDS,
        "docker run --pids-limit for the session container",
    ),
)

#: The session lease's own numbers, same table shape and same reason.
#: Only the idle timeout is here: the hard lease follows the build
#: deadline (:func:`mcuhome.buildserver.sessions.ttl_for`), so it is
#: derived rather than configured, and a knob that could contradict the
#: deadline is a knob that can end a build that is still running.
#:
#: The idle timeout cannot be derived that way, because it measures
#: something else: how long a session may sit with nothing happening.
#: What "nothing" means is the operator's judgement — a workshop machine
#: wants minutes, a shared server wants less — and a test wants seconds,
#: which is the case that made this configurable: the defects that cost
#: this project a build were lease-versus-time defects, and reproducing
#: one must not require a build long enough to outlast ten minutes.
_SESSION_OPTIONS: tuple[tuple[str, str, int, str], ...] = (
    (
        "--session-idle-timeout-seconds",
        "session_idle_timeout_seconds",
        int(DEFAULT_IDLE_TIMEOUT),
        "how long a session may sit idle — no command, no running invocation — before it is closed",
    ),
)

#: Admission: how many turns there are, and how a client that finds none
#: free is made to wait. Same table shape and same reason again.
#:
#: The cap was a constant with no option in front of it, which made four
#: concurrent sessions — four containers at ``--container-memory`` each —
#: a number an operator could not lower on a machine that cannot feed
#: them. Sizing it
#: from real load is a later version's job; a static number is what an
#: operator can reason about, and a dynamic one that guessed wrong would
#: be a build killed for arithmetic.
#:
#: The two seat times are the operator's judgement in the same way the
#: idle timeout is: a private server sets the base high, because a queue
#: there is rare and a chatty client buys nothing, and a public one sets
#: it low. The grace on top of an appointment is *not* here — it absorbs
#: jitter around a time this server itself named, and the base is the
#: knob for wanting a longer leash.
_ADMISSION_OPTIONS: tuple[tuple[str, str, int, str], ...] = (
    (
        "--max-sessions",
        "max_sessions",
        DEFAULT_MAX_OPEN_SESSIONS,
        "how many sessions may be open at once",
    ),
    (
        "--seat-retry-seconds",
        "seat_retry_seconds",
        int(DEFAULT_SEAT_RETRY_SECONDS),
        "base wait a refused client is told to keep before presenting its seat again",
    ),
    (
        "--seat-retry-max-seconds",
        "seat_retry_max_seconds",
        int(DEFAULT_SEAT_RETRY_MAX_SECONDS),
        "ceiling on that wait, however deep the queue is",
    ),
    (
        "--max-seats",
        "max_seats",
        DEFAULT_MAX_SEATS,
        "how many waiting turns this server holds before it stops issuing them",
    ),
    (
        "--reconnect-grace-seconds",
        "reconnect_grace_seconds",
        int(DEFAULT_RECONNECT_GRACE),
        "how long a session whose client is gone is kept before a waiting one may have it",
    ),
)

_LIMIT_ATTRIBUTES: tuple[str, ...] = (
    tuple(entry[1] for entry in _CAP_OPTIONS)
    + ("session_quota_bytes", "max_connections", "max_inflight_commands")
    + tuple(entry[1] for entry in _BACKEND_OPTIONS)
    + tuple(entry[1] for entry in _SESSION_OPTIONS)
    + tuple(entry[1] for entry in _ADMISSION_OPTIONS)
)


def _text_option(
    configured: str | None, env: Mapping[str, str], name: str, default: str | None
) -> str | None:
    """A string option in which ``""`` is a value and absence is not.

    ``--container-memory ""`` means "no ceiling", so the empty string
    cannot ride on the ``or`` chain the other string options use: there,
    absence and emptiness are the same thing and both take the default,
    which would silently keep a limit an operator asked to remove.
    """
    found = configured
    if found is None:
        found = env.get(ENV_PREFIX + name)
    if found is None:
        found = default
    return (found or "").strip() or None


def _env_int(env: Mapping[str, str], name: str) -> int | None:
    raw = env.get(ENV_PREFIX + name)
    if raw is None or not raw.strip():
        return None
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"{ENV_PREFIX + name} must be a whole number, not {raw!r}.") from None


def _env_flag(env: Mapping[str, str], name: str) -> bool | None:
    """A yes/no environment variable, or ``None`` when it is not set."""
    raw = env.get(ENV_PREFIX + name)
    if raw is None or not raw.strip():
        return None
    value = raw.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise SystemExit(f"{ENV_PREFIX + name} must be yes or no, not {raw!r}.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcuhome-buildserver",
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
        # Deliberately no `choices=`: this server's own layer names are
        # the four above, and the `x-` prefix is reserved for
        # third-party ones, so the set of *nameable* layers is open
        # while the set of *allowed* ones stays this option's answer.
        # Validation is in `load_config`,
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
        "--max-connections",
        type=int,
        metavar="N",
        dest="max_connections",
        help=(
            "concurrent /ws connections this server accepts before it refuses the "
            f"upgrade (default {DEFAULT_MAX_CONNECTIONS}); hardening, not a trust boundary"
        ),
    )
    parser.add_argument(
        "--max-inflight-commands",
        type=int,
        metavar="N",
        dest="max_inflight_commands",
        help=(
            "in-flight command tasks one /ws connection may run at once "
            f"(default {DEFAULT_MAX_INFLIGHT_COMMANDS})"
        ),
    )
    parser.add_argument(
        "--docker",
        metavar="PROGRAM",
        help=f"container runtime to drive (default {DEFAULT_DOCKER})",
    )
    parser.add_argument(
        "--sdk-source",
        action="append",
        type=Path,
        metavar="PATH",
        dest="sdk_sources",
        help=(
            "directory holding mcuhome-sdk-<version>.tar.zst packages; repeatable and "
            "searched in the order given, before MCUHome's own package registry. The url "
            "in a context is a hint and is never fetched: a package is found by name and "
            "accepted by the hash the context pins"
        ),
    )
    parser.add_argument(
        "--allow-environment",
        action="append",
        metavar="REPOSITORY",
        dest="allowed_environments",
        help=(
            "build-environment repository this server may run, without tag or digest "
            "(repeatable, searched in the order given). Stating it replaces the default, "
            f"which is MCUHome's own build environment ({ENVIRONMENT_IMAGE_REPOSITORY}). "
            "A build pinning any other repository is refused before any registry is asked"
        ),
    )
    parser.add_argument(
        "--no-auto-pull",
        action="store_false",
        dest="auto_pull",
        default=None,
        help=(
            "never fetch a build environment; serve only images already on this host. "
            "The allowlist above applies either way"
        ),
    )
    parser.add_argument(
        "--ccache-dir",
        type=Path,
        metavar="PATH",
        help=(
            "shared compiler cache, offered to every invocation read-only "
            "(there is no writable mode: cache warming is not a verb this server has)"
        ),
    )
    parser.add_argument(
        "--container-memory",
        metavar="SIZE",
        help=(
            "how much memory one build step may use, in docker's own spelling "
            f"(default {DEFAULT_CONTAINER_MEMORY}). Told to the build environment in its "
            "request document and enforced as docker run --memory; the empty string "
            "removes the limit"
        ),
    )
    parser.add_argument(
        "--container-cpus",
        metavar="N",
        help=(
            "how much CPU one build step may use, as a number of cores (fractions "
            "allowed). Told to the build environment in its request document and "
            "enforced as docker run --cpus; default: every CPU of this host"
        ),
    )
    for option, attribute, default, what in (
        *_BACKEND_OPTIONS,
        *_SESSION_OPTIONS,
        *_ADMISSION_OPTIONS,
    ):
        parser.add_argument(
            option,
            type=int,
            metavar="N",
            dest=attribute,
            help=f"{what} (default {default})",
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
            "carry the x- prefix reserved for it)."
        )

    context_root = path_option(args.context_root, "CONTEXT_ROOT")
    if context_root is None:
        context_root = default_context_root(env)

    sdk_sources = [Path(entry) for entry in (args.sdk_sources or ())]
    if env.get(ENV_PREFIX + "SDK_SOURCES"):
        sdk_sources += [
            Path(item.strip())
            for item in env[ENV_PREFIX + "SDK_SOURCES"].split(",")
            if item.strip()
        ]

    environments = list(args.allowed_environments or ())
    if env.get(ENV_PREFIX + "ALLOW_ENVIRONMENTS"):
        environments += [
            item.strip()
            for item in env[ENV_PREFIX + "ALLOW_ENVIRONMENTS"].split(",")
            if item.strip()
        ]
    # An empty list is the operator asking this server to run nothing,
    # which is a configuration mistake rather than a hardening step —
    # every build would refuse and the message would name an empty
    # allowlist. Saying so at startup beats saying it once per client.
    for entry in environments:
        repository = repository_of(entry)
        if entry.startswith(repository) and entry != repository:
            raise SystemExit(
                f"--allow-environment takes a repository, not {entry!r}: no tag and no "
                "digest. A tag moves and a digest would have to be relisted on every "
                f"release — write {repository!r} instead."
            )
        if repository != entry:
            # Docker's own shorthand for its own registry. Spelled out
            # here rather than accepted quietly, so that the list an
            # operator reads back is the list this server compares.
            raise SystemExit(
                f"--allow-environment wants the registry named too: write {repository!r} "
                f"rather than {entry!r}."
            )
    allowed_environments = tuple(dict.fromkeys(environments)) or (ENVIRONMENT_IMAGE_REPOSITORY,)

    auto_pull = args.auto_pull
    if auto_pull is None:
        auto_pull = _env_flag(env, "AUTO_PULL")
    if auto_pull is None:
        auto_pull = True

    limits: dict[str, int] = {}
    for attribute in _LIMIT_ATTRIBUTES:
        value = getattr(args, attribute, None)
        if value is None:
            value = _env_int(env, attribute.upper())
        if value is None:
            continue
        if value <= 0:
            raise SystemExit(f"--{attribute.replace('_', '-')} must be a positive number.")
        limits[attribute] = value

    container_memory = _text_option(
        args.container_memory, env, "CONTAINER_MEMORY", DEFAULT_CONTAINER_MEMORY
    )
    container_cpus = _text_option(args.container_cpus, env, "CONTAINER_CPUS", None)

    config = Config(
        host=args.host or env.get(ENV_PREFIX + "HOST") or DEFAULT_HOST,
        port=args.port or _env_int(env, "PORT") or DEFAULT_PORT,
        pair_file=pair_file,
        allowed_origins=tuple(dict.fromkeys(origins)),
        log_level=args.log_level or env.get(ENV_PREFIX + "LOG_LEVEL") or "INFO",
        allowed_patch_layers=tuple(dict.fromkeys(patch_layers)),
        allowed_environments=allowed_environments,
        auto_pull=auto_pull,
        context_root=context_root,
        docker=args.docker or env.get(ENV_PREFIX + "DOCKER") or DEFAULT_DOCKER,
        # Order-preserving de-duplication: the search order is fixed
        # and a directory listed twice must not move the one behind
        # it.
        sdk_sources=tuple(dict.fromkeys(sdk_sources)),
        ccache_dir=path_option(args.ccache_dir, "CCACHE_DIR"),
        container_memory=container_memory,
        container_cpus=container_cpus,
        **limits,
    )

    token, generated = resolve_token(args.token, args.token_file, env)
    return replace(config, token=token, token_generated=generated)
