# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The options this server owns, declared the way every MCUHome option is.

A build server is not a second kind of program with a configuration
grammar of its own. What it needs for its own operation — where it
binds, how many sessions it admits, what a client may upload, which
build environments it will run — is the area ``server``, declared with
the workbench's :class:`~mcuhome.workbench.api.Option` type. Key,
environment variable and command-line flag all derive from that one
declaration, so ``server.max_sessions`` is ``MCUHOME_SERVER_MAX_SESSIONS``
and ``--server-max-sessions`` without anything here saying so.

Everything this server shares with a build on a workstation keeps the
shared key and gets no server-side synonym: the container program is
``build.container_program``, the budgets are ``build.cpus`` /
``build.memory`` / ``build.pids``, the operator's package directories are
``build.sdk_sources`` / ``build.workspace_sources`` /
``build.tools_sources``, the shared compiler cache is
``build.cache_shared``, and the package registries are ``registry.*``.
Those are the workbench's own options and are read out of the same
resolution (:func:`~mcuhome.workbench.api.resolve_build_options`).

**One key this server declares for itself and the workbench does not**:
``server.allowed_container_repositories``. The workbench's
``build.container_repositories`` is a search list — where an image may
be looked for. This server's list is that *and* the boundary a pinned
repository has to be inside: a build naming any other repository is
refused before any registry is asked. A policy that refuses is not a
search list, so it is a key of its own, and the search list this server
hands the workbench is derived from it.

**The memory budget is stated in the program layer.** A workstation with
no memory ceiling builds with whatever is free; a build server that let
one session's linker take the host down would take every other session
with it. Eight gibibytes is this program's own default for
``build.memory`` — directly above the declared default and below every
file, so it carries the origin ``program`` and an operator's
configuration still wins.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from typing import Any

from mcuhome.model.buildenvironment import ENVIRONMENT_IMAGE_REPOSITORY
from mcuhome.workbench import api

from mcuhome.buildserver.security import DEFAULT_PAIR_FILE
from mcuhome.buildserver.sessions import (
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_MAX_OPEN_SESSIONS,
    DEFAULT_MAX_SEATS,
    DEFAULT_RECONNECT_GRACE,
    DEFAULT_SEAT_RETRY_MAX_SECONDS,
    DEFAULT_SEAT_RETRY_SECONDS,
    PATCH_LAYERS,
)

__all__ = [
    "BUILD_KEYS",
    "DECLARED_OPTIONS",
    "DEFAULT_BUILD_DEADLINE_SECONDS",
    "DEFAULT_CANCEL_GRACE_SECONDS",
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
    "DEFAULT_MEMORY",
    "DEFAULT_PORT",
    "DEFAULT_SESSION_QUOTA_BYTES",
    "PROGRAM_DEFAULTS",
    "PROGRAM_NAME",
    "CLOSED_VARIABLES",
    "RETIRED_FLAGS",
    "RETIRED_VARIABLES",
    "SERVER_OPTIONS",
    "add_option_flags",
    "arguments",
    "offered_options",
    "refuse_unread_spellings",
]

#: How this program names itself where a resolved value has to say who
#: chose it — the source of every value the program layer states.
PROGRAM_NAME = "mcuhome-buildserver"

#: One past the dashboard's 8099, so both Apps can run on one host with
#: no configuration at all.
DEFAULT_PORT = 8100

#: The bind address. The dashboard defaults to loopback because a
#: dashboard on loopback is still a dashboard; a build server on loopback
#: is a build server nobody can open a session against. The two-App
#: topology makes it a separate machine by construction, so the useful
#: default is the one that works, and the safety comes from the bearer
#: token rather than from the binding.
DEFAULT_HOST = "0.0.0.0"  # noqa: S104 - see the comment above

#: The five ingress caps of the hardening floor for shared servers, in
#: the order they are usually listed, and the per-session disk quota
#: alongside them. Every number is a chosen default rather than a derived
#: one: no document fixes them, so they are stated here once and cited
#: nowhere as if they were normative.
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
#: list: how large ``context.yaml`` may be. It exists because a YAML
#: parser is the single place in this server where a small input buys
#: unbounded work, so the pin document gets a bound of its own instead of
#: sharing the per-file cap with a multi-megabyte patch.
DEFAULT_MAX_CONTEXT_YAML_BYTES = 64 * 1024

#: The egress size cap, per artifact, applied during enumeration, from
#: the bytes on disk — an artifact entry declares no size. Separate from
#: the ingress caps because it bounds the opposite direction: what the
#: least trusted component in the system may put on the wire towards
#: other people's machines.
DEFAULT_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024

#: ``limits.deadline_seconds`` — relative to program start, advisory to
#: the program and **enforced here**. Ninety minutes: generous against a
#: cold Matter build, mean against one that is not going to end.
DEFAULT_BUILD_DEADLINE_SECONDS = 5400

#: ``limits.cancel_grace_seconds`` — how long a cooperative program has
#: to notice the cancel sentinel and write a ``cancelled`` result before
#: the hard path starts. Sixty seconds, which is long enough to finish
#: writing an artifact and short enough that a client waiting on a cancel
#: is not left guessing.
DEFAULT_CANCEL_GRACE_SECONDS = 60

#: Concurrent ``/ws`` connections this server accepts, and in-flight
#: command tasks one connection may run at once. Both are **hardening,
#: not a trust boundary**: the bearer token already equals shell access,
#: so a token holder can do worse than open sockets — the point is only
#: that an authenticated flood cannot grow the connection set or the
#: per-connection task set without bound.
DEFAULT_MAX_CONNECTIONS = 64
DEFAULT_MAX_INFLIGHT_COMMANDS = 32

#: What this program states for ``build.memory`` in the program layer.
#: The number is written into the request document as the recommendation
#: the build environment sizes itself from and set on the container as
#: the hard limit the runtime holds it to. Eight gibibytes is generous
#: against a cold Matter build and mean against a runaway.
DEFAULT_MEMORY = "8g"

#: The ``build`` keys this server offers on its own command line: what it
#: actually reads out of that section. Every other build key keeps its
#: file and environment channels — the configuration files are shared
#: with every other MCUHome program — and simply has no flag here.
BUILD_KEYS: tuple[str, ...] = (
    "build.container_program",
    "build.cpus",
    "build.memory",
    "build.pids",
    "build.cache_shared",
    "build.sdk_sources",
    "build.workspace_sources",
    "build.tools_sources",
)

SERVER_OPTIONS: tuple[api.Option, ...] = (
    api.Option(
        "server.host",
        kind="string",
        default=DEFAULT_HOST,
        help="the address this server binds",
    ),
    api.Option(
        "server.port",
        kind="integer",
        default=DEFAULT_PORT,
        minimum=1,
        help="the port this server binds",
    ),
    api.Option(
        "server.allowed_origins",
        kind="strings",
        default=(),
        help="browser origins accepted for the WebSocket upgrade",
    ),
    api.Option(
        "server.log_level",
        kind="string",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="logging verbosity",
    ),
    api.Option(
        "server.token_file",
        kind="path",
        help="the file holding the bearer token clients must present",
    ),
    api.Option(
        "server.pair_file",
        kind="path",
        default=DEFAULT_PAIR_FILE,
        help="where the bearer token is published for a same-host App pair",
    ),
    # The two booleans below declare no environment channel: the
    # configuration layer has no spelling for a boolean in a variable
    # yet, and a channel that cannot be read is worse than one that was
    # never offered. Both are set in a configuration file or with their
    # own flags.
    api.Option(
        "server.publish_pair_file",
        kind="boolean",
        default=True,
        environment=False,
        help="publish the bearer token to the pair file at all",
    ),
    api.Option(
        "server.context_root",
        kind="path",
        help="the directory the per-session directories are created in",
    ),
    api.Option(
        "server.session_idle_timeout_seconds",
        kind="integer",
        default=int(DEFAULT_IDLE_TIMEOUT),
        minimum=1,
        help="how long a session may sit idle before it is closed",
    ),
    api.Option(
        "server.max_sessions",
        kind="integer",
        default=DEFAULT_MAX_OPEN_SESSIONS,
        minimum=1,
        help="how many sessions may be open at once",
    ),
    api.Option(
        "server.seat_retry_seconds",
        kind="integer",
        default=int(DEFAULT_SEAT_RETRY_SECONDS),
        minimum=1,
        help="base wait a refused client is told to keep before presenting its seat again",
    ),
    api.Option(
        "server.seat_retry_max_seconds",
        kind="integer",
        default=int(DEFAULT_SEAT_RETRY_MAX_SECONDS),
        minimum=1,
        help="ceiling on that wait, however deep the queue is",
    ),
    api.Option(
        "server.max_seats",
        kind="integer",
        default=DEFAULT_MAX_SEATS,
        minimum=1,
        help="how many waiting turns this server holds before it stops issuing them",
    ),
    api.Option(
        "server.reconnect_grace_seconds",
        kind="integer",
        default=int(DEFAULT_RECONNECT_GRACE),
        minimum=1,
        help="how long a session whose client is gone is kept before a waiting one may have it",
    ),
    api.Option(
        "server.max_connections",
        kind="integer",
        default=DEFAULT_MAX_CONNECTIONS,
        minimum=1,
        help="concurrent /ws connections this server accepts before it refuses the upgrade",
    ),
    api.Option(
        "server.max_inflight_commands",
        kind="integer",
        default=DEFAULT_MAX_INFLIGHT_COMMANDS,
        minimum=1,
        help="in-flight command tasks one /ws connection may run at once",
    ),
    api.Option(
        "server.build_deadline_seconds",
        kind="integer",
        default=DEFAULT_BUILD_DEADLINE_SECONDS,
        minimum=1,
        help="how long one invocation may run before this server stops it",
    ),
    api.Option(
        "server.cancel_grace_seconds",
        kind="integer",
        default=DEFAULT_CANCEL_GRACE_SECONDS,
        minimum=1,
        help="how long a cancelled invocation has to stop itself before the hard path",
    ),
    api.Option(
        "server.allowed_container_repositories",
        kind="strings",
        default=(ENVIRONMENT_IMAGE_REPOSITORY,),
        help=(
            "build-environment repository this server may run, without tag or digest; "
            "searched in the order given and enforced as the boundary a pinned "
            "repository has to be inside"
        ),
    ),
    api.Option(
        "server.auto_pull",
        kind="boolean",
        default=True,
        environment=False,
        help="fetch an allowed build environment this host does not have yet",
    ),
    api.Option(
        "server.allowed_patch_layers",
        kind="strings",
        default=(),
        help=(
            "build-context patch layer this server accepts "
            f"({', '.join(PATCH_LAYERS)}, or a third-party x-* name); "
            "unlisted layers are denied"
        ),
    ),
    api.Option(
        "server.max_compressed_bytes",
        kind="integer",
        default=DEFAULT_MAX_COMPRESSED_BYTES,
        minimum=1,
        help="ingress cap: the archive bytes a session may upload in total",
    ),
    api.Option(
        "server.max_decompressed_bytes",
        kind="integer",
        default=DEFAULT_MAX_DECOMPRESSED_BYTES,
        minimum=1,
        help="ingress cap: the cumulative unpacked bytes a session may produce",
    ),
    api.Option(
        "server.max_entries",
        kind="integer",
        default=DEFAULT_MAX_ENTRIES,
        minimum=1,
        help="ingress cap: the archive entries a session may deliver in total",
    ),
    api.Option(
        "server.max_file_bytes",
        kind="integer",
        default=DEFAULT_MAX_FILE_BYTES,
        minimum=1,
        help="ingress cap: the size of one context file",
    ),
    api.Option(
        "server.max_path_depth",
        kind="integer",
        default=DEFAULT_MAX_PATH_DEPTH,
        minimum=1,
        help="ingress cap: the path segments one context entry may have",
    ),
    api.Option(
        "server.max_context_yaml_bytes",
        kind="integer",
        default=DEFAULT_MAX_CONTEXT_YAML_BYTES,
        minimum=1,
        help="ingress cap: the size of the context.yaml pin document, bounded before it is parsed",
    ),
    api.Option(
        "server.session_quota_bytes",
        kind="integer",
        default=DEFAULT_SESSION_QUOTA_BYTES,
        minimum=1,
        help="per-session disk quota in bytes, answered typed rather than by host exhaustion",
    ),
    api.Option(
        "server.max_artifact_bytes",
        kind="integer",
        default=DEFAULT_MAX_ARTIFACT_BYTES,
        minimum=1,
        help="egress cap: the size of one artifact this server will serve",
    ),
)

#: Every option this server resolves: the platform's registry and its
#: own. The platform's whole registry is declared, not the subset this
#: program reads, because the system and user files are shared with every
#: other MCUHome program and a key one of them owns is not an error here.
DECLARED_OPTIONS: tuple[api.Option, ...] = api.OPTIONS + SERVER_OPTIONS

#: What this program states for shared keys, directly above the declared
#: defaults and below every file.
PROGRAM_DEFAULTS = api.ProgramDefaults(name=PROGRAM_NAME, values={"build.memory": DEFAULT_MEMORY})


def offered_options() -> tuple[api.Option, ...]:
    """The options this server offers a flag for, in declaration order."""
    build = tuple(api.option(name, DECLARED_OPTIONS) for name in BUILD_KEYS)
    return build + tuple(option for option in SERVER_OPTIONS if option.arguments)


# ---------------------------------------------------------------------
# Spellings this server used to have
# ---------------------------------------------------------------------

#: The command-line flags this server used to have, and the option each
#: one is today. A value that names a declared key renders as that key
#: with the spellings it derives; anything else is the sentence itself.
#:
#: One thing has one spelling. A flag that was renamed is **refused by
#: name** with its successor in the message, never accepted quietly as an
#: alias: two spellings for one thing is what makes a surface
#: unlearnable, and a refusal that names the successor teaches it once.
RETIRED_FLAGS: dict[str, str] = {
    "--host": "server.host",
    "--port": "server.port",
    "--allowed-origin": "server.allowed_origins",
    "--log-level": "server.log_level",
    "--token": (
        "It is --server-token now, which also takes `-` to read the token from "
        "standard input; server.token_file names the file that holds it."
    ),
    "--token-file": "server.token_file",
    "--pair-file": "server.pair_file",
    "--no-pair-file": (
        "It is --no-server-publish-pair-file now, the boolean server.publish_pair_file."
    ),
    "--context-root": "server.context_root",
    "--session-idle-timeout-seconds": "server.session_idle_timeout_seconds",
    "--max-sessions": "server.max_sessions",
    "--seat-retry-seconds": "server.seat_retry_seconds",
    "--seat-retry-max-seconds": "server.seat_retry_max_seconds",
    "--max-seats": "server.max_seats",
    "--reconnect-grace-seconds": "server.reconnect_grace_seconds",
    "--max-connections": "server.max_connections",
    "--max-inflight-commands": "server.max_inflight_commands",
    "--build-deadline-seconds": "server.build_deadline_seconds",
    "--cancel-grace-seconds": "server.cancel_grace_seconds",
    "--max-compressed-bytes": "server.max_compressed_bytes",
    "--max-decompressed-bytes": "server.max_decompressed_bytes",
    "--max-entries": "server.max_entries",
    "--max-file-bytes": "server.max_file_bytes",
    "--max-path-depth": "server.max_path_depth",
    "--max-context-yaml-bytes": "server.max_context_yaml_bytes",
    "--session-quota-bytes": "server.session_quota_bytes",
    "--max-artifact-bytes": "server.max_artifact_bytes",
    "--allow-environment": "server.allowed_container_repositories",
    "--no-auto-pull": "It is --no-server-auto-pull now, the boolean server.auto_pull.",
    "--allow-patch-layer": "server.allowed_patch_layers",
    "--docker": "build.container_program",
    "--container-memory": "build.memory",
    "--container-cpus": "build.cpus",
    "--container-pids": "build.pids",
    "--ccache-dir": "build.cache_shared",
    "--sdk-source": (
        "It is build.sdk_sources now, with the two kinds beside it — "
        "build.workspace_sources and build.tools_sources. A directory that holds "
        "packages of all three kinds is named in all three keys."
    ),
}

#: The environment variables this server used to read. The whole
#: ``MCUHOME_BUILDSERVER_`` family is gone: an option's variable derives
#: from its key, and these keys belong to the areas ``server`` and
#: ``build``.
#:
#: They are **refused**, not warned about, which is where this differs
#: from a command line a person types. The workbench warns about a
#: retired variable because a stale one exported in a shell profile would
#: refuse every command including the one that fixes it. A build server
#: is started once, deliberately, from a unit file or a container
#: definition — and a variable that was silently ignored would be an
#: operator's token, allowlist or cache quietly not in effect.
RETIRED_VARIABLES: dict[str, str] = {
    "MCUHOME_BUILDSERVER_HOST": "server.host",
    "MCUHOME_BUILDSERVER_PORT": "server.port",
    "MCUHOME_BUILDSERVER_ALLOWED_ORIGINS": "server.allowed_origins",
    "MCUHOME_BUILDSERVER_LOG_LEVEL": "server.log_level",
    "MCUHOME_BUILDSERVER_TOKEN": (
        "There is no environment variable for the token any more: a secret in a "
        "variable is in the environment of every child process this server starts. "
        "Pipe it in with `--server-token -`, or name the file that holds it with "
        "server.token_file."
    ),
    "MCUHOME_BUILDSERVER_TOKEN_FILE": "server.token_file",
    "MCUHOME_BUILDSERVER_PAIR_FILE": "server.pair_file",
    "MCUHOME_BUILDSERVER_CONTEXT_ROOT": "server.context_root",
    "MCUHOME_BUILDSERVER_SESSION_IDLE_TIMEOUT_SECONDS": "server.session_idle_timeout_seconds",
    "MCUHOME_BUILDSERVER_MAX_SESSIONS": "server.max_sessions",
    "MCUHOME_BUILDSERVER_SEAT_RETRY_SECONDS": "server.seat_retry_seconds",
    "MCUHOME_BUILDSERVER_SEAT_RETRY_MAX_SECONDS": "server.seat_retry_max_seconds",
    "MCUHOME_BUILDSERVER_MAX_SEATS": "server.max_seats",
    "MCUHOME_BUILDSERVER_RECONNECT_GRACE_SECONDS": "server.reconnect_grace_seconds",
    "MCUHOME_BUILDSERVER_MAX_CONNECTIONS": "server.max_connections",
    "MCUHOME_BUILDSERVER_MAX_INFLIGHT_COMMANDS": "server.max_inflight_commands",
    "MCUHOME_BUILDSERVER_BUILD_DEADLINE_SECONDS": "server.build_deadline_seconds",
    "MCUHOME_BUILDSERVER_CANCEL_GRACE_SECONDS": "server.cancel_grace_seconds",
    "MCUHOME_BUILDSERVER_MAX_COMPRESSED_BYTES": "server.max_compressed_bytes",
    "MCUHOME_BUILDSERVER_MAX_DECOMPRESSED_BYTES": "server.max_decompressed_bytes",
    "MCUHOME_BUILDSERVER_MAX_ENTRIES": "server.max_entries",
    "MCUHOME_BUILDSERVER_MAX_FILE_BYTES": "server.max_file_bytes",
    "MCUHOME_BUILDSERVER_MAX_PATH_DEPTH": "server.max_path_depth",
    "MCUHOME_BUILDSERVER_MAX_CONTEXT_YAML_BYTES": "server.max_context_yaml_bytes",
    "MCUHOME_BUILDSERVER_SESSION_QUOTA_BYTES": "server.session_quota_bytes",
    "MCUHOME_BUILDSERVER_MAX_ARTIFACT_BYTES": "server.max_artifact_bytes",
    "MCUHOME_BUILDSERVER_ALLOW_ENVIRONMENTS": "server.allowed_container_repositories",
    "MCUHOME_BUILDSERVER_AUTO_PULL": (
        "It is the boolean server.auto_pull now, in a configuration file or as "
        "--server-auto-pull / --no-server-auto-pull."
    ),
    "MCUHOME_BUILDSERVER_ALLOW_PATCH_LAYERS": "server.allowed_patch_layers",
    "MCUHOME_BUILDSERVER_DOCKER": "build.container_program",
    "MCUHOME_BUILDSERVER_CONTAINER_MEMORY": "build.memory",
    "MCUHOME_BUILDSERVER_CONTAINER_CPUS": "build.cpus",
    "MCUHOME_BUILDSERVER_CONTAINER_PIDS": "build.pids",
    "MCUHOME_BUILDSERVER_CCACHE_DIR": "build.cache_shared",
    "MCUHOME_BUILDSERVER_SDK_SOURCES": (
        "It is build.sdk_sources now, with the two kinds beside it — "
        "build.workspace_sources and build.tools_sources. A directory that holds "
        "packages of all three kinds is named in all three keys."
    ),
}

#: Variables a key of this server *derives* and nothing reads. They are
#: refused by name for the reason the retired ones are: a ``MCUHOME_*``
#: name an operator exports and this server ignores is a policy that
#: quietly did not take effect, and nobody finds that out until a build
#: does something nobody asked for.
#:
#: Two reasons a name lands here, and they are different. The token's is
#: permanent: a secret in a variable is in the environment of every
#: child process this server starts, so the option does not exist and the
#: variable never will. The two booleans' is not: the configuration layer
#: has no spelling for a boolean in a variable yet, so their environment
#: channel is closed and these two entries come out the day it opens.
CLOSED_VARIABLES: dict[str, str] = {
    "MCUHOME_SERVER_TOKEN": (
        "There is no environment variable for the token, and there will not be: a "
        "secret in a variable is in the environment of every child process this "
        "server starts. Pipe it in with `--server-token -`, or name the file that "
        "holds it with server.token_file."
    ),
    "MCUHOME_SERVER_AUTO_PULL": (
        "server.auto_pull is a boolean, and a boolean cannot be read out of a "
        "variable yet. Set it in a configuration file, or use --server-auto-pull / "
        "--no-server-auto-pull."
    ),
    "MCUHOME_SERVER_PUBLISH_PAIR_FILE": (
        "server.publish_pair_file is a boolean, and a boolean cannot be read out of "
        "a variable yet. Set it in a configuration file, or use "
        "--server-publish-pair-file / --no-server-publish-pair-file."
    ),
}


def successor(stated: str) -> str:
    """How a refusal names what *stated* is today.

    A value that is a declared key renders with the spellings that key
    derives, so the table above says the key once and the message offers
    the flag and the variable without either being written down twice.
    """
    option = next((one for one in DECLARED_OPTIONS if one.name == stated), None)
    if option is None:
        # Not a key: the table wrote the whole sentence, because what
        # replaced this spelling is more than one key or is no key at all.
        return stated
    channels = [f"{option.flag} on the command line" if option.flag else ""]
    channels.append(f"{option.env_var} in the environment" if option.env_var else "")
    offered = ", or ".join(channel for channel in channels if channel)
    where = f": {offered}" if offered else ""
    return f"It is {stated!r} now{where}."


def refuse_unread_spellings(tokens: Sequence[str], env: Mapping[str, str]) -> None:
    """Refuse a spelling this server does not read, naming what it does.

    Three of them: a flag that was renamed, a variable that was renamed,
    and a variable a key derives that no channel reads
    (:data:`CLOSED_VARIABLES`). All three are checked before anything is
    parsed, so a retired flag is answered with the name it has today
    rather than with ``unrecognized arguments``. A flag written with its
    value attached (``--docker=podman``) is the same spelling and is
    refused the same way.
    """
    written = {token.partition("=")[0] for token in tokens if token.startswith("--")}
    for spelling in RETIRED_FLAGS:
        if spelling in written:
            raise api.ConfigError(
                f"{spelling} is not a flag of this server any more.",
                hint=successor(RETIRED_FLAGS[spelling]),
            )
    for variable in RETIRED_VARIABLES:
        if env.get(variable, "").strip():
            raise api.ConfigError(
                f"{variable} is set, and this server does not read it any more.",
                hint=successor(RETIRED_VARIABLES[variable]) + _unset(variable),
            )
    for variable, why in CLOSED_VARIABLES.items():
        if env.get(variable, "").strip():
            raise api.ConfigError(
                f"{variable} is set, and this server does not read it.",
                hint=why + _unset(variable),
            )


def _unset(variable: str) -> str:
    """The second half of every variable refusal: take the name away."""
    return (
        f" Unset {variable} so it cannot mislead the next person who reads this "
        "server's environment."
    )


# ---------------------------------------------------------------------
# The options as command-line flags
# ---------------------------------------------------------------------

#: What a flag's value is called in the help, by the option's kind. The
#: two list kinds carry the singular: one use of the flag is one entry.
_METAVARS = {
    "string": "VALUE",
    "path": "PATH",
    "paths": "PATH",
    "strings": "NAME",
    "integer": "N",
    "number": "N",
}


def _dest(option: api.Option) -> str:
    """Where argparse keeps the text — the key, reversibly."""
    return option.name.replace(".", "_")


def add_option_flags(parser: argparse.ArgumentParser, options: Sequence[api.Option]) -> None:
    """Add one flag per option of *options*, in the spelling it derives.

    A list option is repeatable and each use appends, because the flag
    *is* the key and the repetition already says "another one"; a boolean
    derives both ``--x`` and ``--no-x``, because "not used" and "turned
    off" are different statements.
    """
    for option in options:
        if option.kind == "boolean":
            parser.add_argument(
                option.flag,
                dest=_dest(option),
                action="store_true",
                default=None,
                help=_help(option),
            )
            parser.add_argument(
                f"--no-{option.flag[2:]}",
                dest=_dest(option),
                action="store_false",
                help=f"{option.name} turned off",
            )
            continue
        parser.add_argument(
            option.flag,
            dest=_dest(option),
            action="append" if option.kind in ("paths", "strings") else "store",
            default=None,
            metavar=_METAVARS[option.kind],
            choices=list(option.choices) or None,
            help=_help(option),
        )


def _help(option: api.Option) -> str:
    """What the flag does, and which key and variable it is."""
    spellings = option.name
    if option.env_var:
        spellings += f", {option.env_var}"
    default = "" if option.default in (None, ()) else f" (default {_stated(option.default)})"
    return f"{option.help}{default} [{spellings}]"


def _stated(default: Any) -> str:
    if isinstance(default, tuple):
        return ", ".join(str(item) for item in default)
    return str(default)


def arguments(
    namespace: argparse.Namespace, options: Sequence[api.Option], *, env: Mapping[str, str]
) -> tuple[api.Argument, ...]:
    """The option values this invocation actually carried, parsed.

    An unused flag is **absent** from the answer rather than ``None``:
    "the flag was not used" and "the flag was used to clear the value"
    are different statements, and only the command line can tell them
    apart. Each answer names the spelling it arrived in, so a refusal
    from the configuration layer quotes what was typed.
    """
    answered: list[api.Argument] = []
    for option in options:
        raw = getattr(namespace, _dest(option), None)
        if raw is None:
            continue
        spelled = (
            f"--no-{option.flag[2:]}" if raw is False and option.kind == "boolean" else option.flag
        )
        answered.append(
            api.Argument(name=option.name, value=_parse(option, raw, env=env), flag=spelled)
        )
    return tuple(answered)


def _parse(option: api.Option, raw: object, *, env: Mapping[str, str]) -> object:
    """*raw* in the option's own type, or a refusal naming the flag.

    A value a flag carries is parsed before the server starts, through
    the declaration that owns it, so a figure nobody can read is a
    refusal at startup and not an internal error on the first build.
    """
    if option.kind == "boolean":
        return bool(raw)
    items = [str(item) for item in raw] if isinstance(raw, list) else [str(raw)]
    if option.kind == "paths":
        return tuple(api.expand_user_path(item, env=env) for item in items)
    if option.kind == "strings":
        return tuple(items)
    text = str(raw)
    if option.kind == "path":
        return api.expand_user_path(text, env=env)
    if option.kind in ("integer", "number"):
        return _number(option, text)
    if option.name == "build.memory":
        # The one string option whose shape can be checked before the
        # run: a memory limit that was misread would either strangle
        # every build or bound nothing at all. A figure with no whole
        # number behind it (`inf`) arrives as an arithmetic error from
        # the conversion and means the same thing to an operator.
        try:
            api.parse_memory(text, key=option.flag)
        except (ArithmeticError, ValueError) as unreadable:
            raise api.ConfigError(
                f"{option.flag} takes an amount of memory, not {text!r}.",
                hint=(
                    "a byte count or a number with a unit — 512m, 8g, 2048k — the way "
                    "a container runtime spells it"
                ),
            ) from unreadable
    return text


def _number(option: api.Option, text: str) -> int | float:
    whole = option.kind == "integer"
    try:
        number: int | float = int(text) if whole else float(text)
    except ValueError:
        raise api.ConfigError(
            f"{option.flag} takes a {'whole number' if whole else 'number'}, not {text!r}.",
            hint=option.help or None,
        ) from None
    if option.minimum is None:
        return number
    if whole and number < option.minimum:
        raise api.ConfigError(
            f"{option.flag} takes at least {option.minimum}, not {number}.",
            hint=option.help or None,
        )
    if not whole and number <= option.minimum:
        raise api.ConfigError(
            f"{option.flag} takes a number greater than {option.minimum}, not {number:g}.",
            hint=option.help or None,
        )
    return number
