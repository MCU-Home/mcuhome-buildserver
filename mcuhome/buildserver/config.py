# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Runtime configuration: one ladder, the same one every MCUHome program reads.

The options themselves are declared in
:mod:`mcuhome.buildserver.options`; this module resolves them and turns
the answer into the :class:`Config` the server runs on. The layers are
the workbench's, ascending — later wins — and every value carries the
one it came from:

``default`` → ``program`` → system file → user file → this server's own
configuration file → environment → arguments.

``program`` is what this server states for a shared key before any file
is read (the memory budget); the two system-wide files are the ones every
MCUHome program on this host reads, so a machine configures its package
directories, its container program and its registries once; and the file
``--server-config`` names stands where a project's file stands for a
workstation — a build server has no project, and this is the nearest
thing it has to one.

Three defaults are decisions rather than conveniences, and they are
stated where the options are declared: the bind address is ``0.0.0.0``,
the memory budget is ``8g`` in the program layer, and the ingress caps
and the per-session disk quota are options because **the config is the
policy** — a limit an operator cannot move is a limit they will work
around by other means.

**A token is not optional.** There is no configuration in which this
server listens without one. Configure it and it is used; do not, and one
is generated at startup, logged once, and written to the pairing file if
this is a Home Assistant App pair. What there is no way to ask for is a
build server with authentication switched off. There is deliberately no
environment variable for it either: a secret in a variable is in the
environment of every child process this server starts, so the channels
are ``--server-token`` (which takes ``-`` to read it from standard
input) and ``server.token_file``.
"""

from __future__ import annotations

import argparse
import math
import os
import secrets
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, TextIO

from mcuhome.model.buildenvironment import ENVIRONMENT_IMAGE_REPOSITORY
from mcuhome.workbench import api

from mcuhome.buildserver import options as declared
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
    "FROM_STDIN",
    "Config",
    "build_parser",
    "config_document",
    "default_context_root",
    "load_config",
    "resolve_token",
]

#: What a flag writes to mean "the value is on standard input".
FROM_STDIN = "-"


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
    deliberate. ``server.context_root`` is how an operator says.
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

    host: str = declared.DEFAULT_HOST
    port: int = declared.DEFAULT_PORT
    #: Never ``None``: :func:`load_config` generates one when it must.
    token: str = ""
    #: Where the token is published for a same-host App pair, or ``None``
    #: where ``server.publish_pair_file`` is off.
    pair_file: Path | None = DEFAULT_PAIR_FILE

    allowed_origins: tuple[str, ...] = ()
    log_level: str = "INFO"

    #: The ``/ws`` connection and per-connection concurrency caps. See the
    #: declarations: hardening against an authenticated flood, not a
    #: trust boundary, since the token already equals shell.
    max_connections: int = declared.DEFAULT_MAX_CONNECTIONS
    max_inflight_commands: int = declared.DEFAULT_MAX_INFLIGHT_COMMANDS

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
    max_compressed_bytes: int = declared.DEFAULT_MAX_COMPRESSED_BYTES
    max_decompressed_bytes: int = declared.DEFAULT_MAX_DECOMPRESSED_BYTES
    max_entries: int = declared.DEFAULT_MAX_ENTRIES
    #: Per file, so one entry cannot spend the whole cumulative budget.
    max_file_bytes: int = declared.DEFAULT_MAX_FILE_BYTES
    #: Path segments, ``patches/zephyr/0001-fix.patch`` being three.
    max_path_depth: int = declared.DEFAULT_MAX_PATH_DEPTH
    #: The sixth cap: how large ``context.yaml`` may be before it is
    #: parsed at all. Not one of the hardening floor's five, and here for
    #: the same reason they are.
    max_context_yaml_bytes: int = declared.DEFAULT_MAX_CONTEXT_YAML_BYTES

    #: The per-session disk quota alongside them — "typed
    #: quota-exceeded instead of host exhaustion". It meters what a
    #: **client** put on this host: the context, and the SDK package
    #: deliberately not (that one is the operator's own file, and
    #: charging it would let a package's size decide whether a context
    #: fits). What a build writes into ``out`` is bounded by
    #: :attr:`max_artifact_bytes` per artifact at egress instead, which
    #: is where the cap belongs — the only place a number
    #: can be measured from the bytes on disk.
    session_quota_bytes: int = declared.DEFAULT_SESSION_QUOTA_BYTES

    #: The numbers that bound one invocation. All of them are
    #: configuration for the same reason the ingress caps are — the
    #: config is the policy, and a number an operator cannot move is a
    #: number they will work around.
    build_deadline_seconds: int = declared.DEFAULT_BUILD_DEADLINE_SECONDS
    cancel_grace_seconds: int = declared.DEFAULT_CANCEL_GRACE_SECONDS
    #: The idle half of the session lease. The hard half is not here: it
    #: is derived from the build deadline.
    session_idle_timeout_seconds: int = int(DEFAULT_IDLE_TIMEOUT)
    #: How many sessions may be open at once, and how a client that finds
    #: them all taken is made to wait.
    max_sessions: int = DEFAULT_MAX_OPEN_SESSIONS
    seat_retry_seconds: int = int(DEFAULT_SEAT_RETRY_SECONDS)
    seat_retry_max_seconds: int = int(DEFAULT_SEAT_RETRY_MAX_SECONDS)
    max_seats: int = DEFAULT_MAX_SEATS
    reconnect_grace_seconds: int = int(DEFAULT_RECONNECT_GRACE)
    max_artifact_bytes: int = declared.DEFAULT_MAX_ARTIFACT_BYTES

    #: The build environments this server is willing to run, as
    #: repositories — no tag, no digest. It is **two things at once** and
    #: both are always enforced: the search list an environment is looked
    #: for in when a context brings no pin, walked in order, and the
    #: boundary a pin that names a repository has to be inside. Without
    #: it a client's pin would decide which of this host's images gets
    #: started with a session's mounts under it. That is why it is
    #: ``server.allowed_container_repositories`` and not the workbench's
    #: ``build.container_repositories``, which is a search list and
    #: refuses nothing; the search list this server hands the workbench
    #: is this one.
    allowed_container_repositories: tuple[str, ...] = (ENVIRONMENT_IMAGE_REPOSITORY,)

    #: Fetch an allowed build environment this host does not have yet.
    #: On by default: the environment is pinned to a digest and its
    #: repository is on the list above, so there is exactly one set of
    #: bytes that answers and fetching it is a convenience rather than a
    #: decision. ``False`` is the server whose images an operator places
    #: deliberately — an air-gapped one, or one that will not spend a
    #: gigabyte of transfer on a client's say-so.
    auto_pull: bool = True

    #: The ``build`` section of the same resolution: the container
    #: program, the budgets one step is held to, the operator's package
    #: directories per package kind, and the shared compiler cache. Every
    #: one of them is the key a workstation uses for the same thing.
    build: api.BuildOptions = field(default_factory=api.BuildOptions)

    #: What the configuration says about package registries, by base
    #: domain: their mirrors, their trust anchor, whether an unsigned
    #: source is accepted. A server has no project, so this map is where
    #: the answers a project keeps in its own file come from.
    registries: tuple[api.RegistrySettings, ...] = ()

    #: The file ``--server-config`` named, if any. Its directory is this
    #: server's project-light root: where ``secrets/trust-anchor/`` is
    #: looked up for a registry the map does not give an anchor for.
    config_file: Path | None = None

    #: The whole resolution, for the document ``--print-config`` answers.
    #: ``None`` for a configuration built in code rather than resolved.
    settings: api.Settings | None = field(default=None, compare=False, repr=False)

    #: True when :func:`load_config` had to invent the token, so that
    #: startup can print it exactly once.
    token_generated: bool = field(default=False, compare=False)

    #: What the invocation asked for rather than what it configured:
    #: print the resolved configuration and exit.
    print_config: bool = field(default=False, compare=False)

    @property
    def project_root(self) -> Path:
        """Where this server's own trust anchors are looked for.

        The directory its configuration file lies in — the one place a
        server has that answers what a project's root answers for a
        workstation. Without such a file there is nothing to point at
        and the context root stands in: it is the directory this server
        was given to own.
        """
        return self.context_root if self.config_file is None else self.config_file.parent

    def site_summary(self) -> str:
        return f"http://{self.host}:{self.port} (bearer token required)"


def build_parser() -> argparse.ArgumentParser:
    """Every flag this server takes, one per declared option plus its own."""
    parser = argparse.ArgumentParser(
        prog=declared.PROGRAM_NAME,
        description=(
            "Headless MCUHome build service. Drives build environments over the "
            "session protocol and is never one itself; never stores a configuration "
            "tree and never holds a signing key."
        ),
    )
    parser.add_argument(
        "--server-config",
        type=Path,
        metavar="FILE",
        dest="server_config",
        help=(
            f"this server's own configuration file, an {api.PROJECT_CONFIG_FILE} read "
            "where a project's file is read: after the system and user files, and "
            "below the environment and the flags"
        ),
    )
    parser.add_argument(
        "--server-token",
        metavar="TOKEN",
        dest="server_token",
        help=(
            "the bearer token clients must present; `-` reads it from standard input, "
            "which is how a token stays out of the process list of every other user "
            "on the machine"
        ),
    )
    parser.add_argument(
        "--print-config",
        action="store_true",
        dest="print_config",
        help="print the resolved configuration, with the layer every value came from, and exit",
    )
    declared.add_option_flags(parser, declared.offered_options())
    return parser


def resolve_token(
    stated: str | None, token_file: Path | None, *, stdin: TextIO | None = None
) -> tuple[str, bool]:
    """Find the bearer token, or make one. Returns ``(token, generated)``.

    Two channels and no third: what ``--server-token`` carried, and the
    file ``server.token_file`` names. A generated token is returned
    rather than logged, because logging it must happen exactly once and
    at a level the operator actually sees — which is the caller's
    decision, not this function's.
    """
    value = _stated_or_piped(stated, stdin=stdin)
    if value:
        return value, False
    if token_file is not None:
        existing = read_token_file(token_file)
        if existing:
            return existing, False
    return secrets.token_urlsafe(32), True


def _stated_or_piped(stated: str | None, *, stdin: TextIO | None = None) -> str:
    """What ``--server-token`` carried, reading ``-`` from standard input.

    The value is read whole, the line ending a shell added is dropped,
    and an empty read is refused rather than passed on as an empty
    secret. A run that would sit waiting for a value nobody is going to
    type is a run that looks like it hung, so a terminal is refused too.
    """
    if stated is None:
        return ""
    if stated != FROM_STDIN:
        return stated.strip()
    source = sys.stdin if stdin is None else stdin
    if source is None or source.isatty():
        raise api.ConfigError(
            "--server-token - reads the token from standard input, and nothing is piped in.",
            hint='pipe it:\n    printf %s "$TOKEN" | mcuhome-buildserver --server-token -',
        )
    value = source.read().rstrip("\r\n")
    if not value:
        raise api.ConfigError(
            "--server-token - read an empty token from standard input.",
            hint="the token has to arrive on standard input, without a trailing newline",
        )
    return value


def config_document(config: Config) -> dict[str, Any]:
    """What ``--print-config`` answers: every option, its value, its layer."""
    return {"ok": True, "config": {} if config.settings is None else config.settings.to_dict()}


def load_config(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    stdin: TextIO | None = None,
    on_warning: Callable[[api.Diagnostic], None] | None = None,
) -> Config:
    """Resolve the ladder and answer the configuration this server runs on.

    Raises :class:`~mcuhome.workbench.api.ConfigError` for anything an
    operator has to fix — a retired spelling, a value that does not fit
    its declaration, an allowlist entry that is not a repository. The
    refusal names the file and line where a file supplied the value.
    """
    env = os.environ if env is None else env
    tokens = list(sys.argv[1:] if argv is None else argv)
    # Before the parse, so a retired spelling is answered with the name
    # it has today rather than with `unrecognized arguments`.
    declared.refuse_retired_spellings(tokens, env)
    args = build_parser().parse_args(tokens)

    project = _project_light(args.server_config)
    offered = declared.offered_options()
    settings = api.resolve_settings(
        project=project,
        env=env,
        args=declared.arguments(args, offered, env=env),
        program=declared.PROGRAM_DEFAULTS,
        declared_options=declared.DECLARED_OPTIONS,
        on_warning=on_warning,
    )
    build = api.resolve_build_options(settings)
    _check_budget(build)

    def value(leaf: str) -> Any:
        return settings.value(f"server.{leaf}")

    context_root = value("context_root")
    pair_file = value("pair_file") if value("publish_pair_file") else None
    config = Config(
        host=value("host"),
        port=value("port"),
        pair_file=pair_file,
        allowed_origins=tuple(dict.fromkeys(value("allowed_origins"))),
        log_level=value("log_level"),
        max_connections=value("max_connections"),
        max_inflight_commands=value("max_inflight_commands"),
        allowed_patch_layers=_patch_layers(value("allowed_patch_layers")),
        context_root=Path(context_root) if context_root else default_context_root(env),
        max_compressed_bytes=value("max_compressed_bytes"),
        max_decompressed_bytes=value("max_decompressed_bytes"),
        max_entries=value("max_entries"),
        max_file_bytes=value("max_file_bytes"),
        max_path_depth=value("max_path_depth"),
        max_context_yaml_bytes=value("max_context_yaml_bytes"),
        session_quota_bytes=value("session_quota_bytes"),
        build_deadline_seconds=value("build_deadline_seconds"),
        cancel_grace_seconds=value("cancel_grace_seconds"),
        session_idle_timeout_seconds=value("session_idle_timeout_seconds"),
        max_sessions=value("max_sessions"),
        seat_retry_seconds=value("seat_retry_seconds"),
        seat_retry_max_seconds=value("seat_retry_max_seconds"),
        max_seats=value("max_seats"),
        reconnect_grace_seconds=value("reconnect_grace_seconds"),
        max_artifact_bytes=value("max_artifact_bytes"),
        allowed_container_repositories=_repositories(settings),
        auto_pull=value("auto_pull"),
        build=build,
        registries=_registries(settings),
        config_file=None if project is None else project.config_file,
        settings=settings,
        print_config=bool(args.print_config),
    )
    token, generated = resolve_token(args.server_token, value("token_file"), stdin=stdin)
    return replace(config, token=token, token_generated=generated)


def _project_light(stated: Path | None) -> api.Project | None:
    """The server's own configuration file, as the layer a project's file is.

    A build server has no project, and this file is the nearest thing it
    has to one: the same areas, the same keys, the same spellings — and
    the same place in the ladder. Its directory is what this server
    answers where a workstation answers its project root, which is what
    makes ``secrets/trust-anchor/<base-domain>.json`` mean here what it
    means there.

    That is also why the file carries the name a project's file carries.
    A named file that is not there is refused rather than skipped: a
    person who named one meant it.
    """
    if stated is None:
        return None
    file = Path(stated)
    if file.name != api.PROJECT_CONFIG_FILE:
        raise api.ConfigError(
            f"--server-config takes a file called {api.PROJECT_CONFIG_FILE}, not {file.name!r}.",
            hint=(
                "this server reads its own file where a project's file is read, under "
                f"that file's name, and the directory holding it is where trust anchors "
                f"are looked for. Rename it:\n    mv {file} {file.parent / api.PROJECT_CONFIG_FILE}"
            ),
        )
    if not file.is_file():
        raise api.ConfigError(
            f"The configuration file named by --server-config is not there: {file}.",
            hint=(
                "create it, or leave the flag out to run on the system and user configuration alone"
            ),
        )
    return api.Project(root=file.parent, discovered=False)


def _patch_layers(stated: Sequence[str]) -> tuple[str, ...]:
    """The patch layers this server accepts, or a refusal naming the set."""
    unknown = sorted(name for name in stated if not is_patch_layer_name(name))
    if unknown:
        raise api.ConfigError(
            f"{', '.join(unknown)}: not a patch layer this server knows.",
            hint=(
                f"server.allowed_patch_layers takes {', '.join(PATCH_LAYERS)}, or a "
                "third-party layer name carrying the x- prefix reserved for it"
            ),
        )
    return tuple(dict.fromkeys(stated))


def _repositories(settings: api.Settings) -> tuple[str, ...]:
    """The allowlist, checked to be repositories and nothing more.

    A tag moves and a digest would have to be relisted on every release,
    so neither is a thing an allowlist can be written in; and Docker's
    shorthand for its own registry is spelled out rather than accepted
    quietly, so that the list an operator reads back is the list this
    server compares.
    """
    name = "server.allowed_container_repositories"
    stated = tuple(dict.fromkeys(settings.value(name)))
    if not stated:
        raise api.ConfigError(
            f"{name} is empty, and this server would then run no build environment at all.",
            hint=(
                "name at least one repository, or remove the key to serve MCUHome's own "
                "build environment"
            ),
        )
    for entry in stated:
        repository = repository_of(entry)
        if entry.startswith(repository) and entry != repository:
            raise api.ConfigError(
                f"{name} takes a repository, not {entry!r}: no tag and no digest.",
                hint=(
                    "a tag moves and a digest would have to be relisted on every "
                    f"release — write {repository!r} instead"
                ),
            )
        if repository != entry:
            raise api.ConfigError(
                f"{name} wants the registry named too: write {repository!r} rather than {entry!r}.",
                hint="the list an operator reads back is the list this server compares",
            )
    return stated


def _registries(settings: api.Settings) -> tuple[api.RegistrySettings, ...]:
    """The configured registries, with MCUHome's own anchored as it ships.

    The map is read exactly as a project's is. What this server adds is
    the one answer a project gets from its own ``secrets/trust-anchor/``
    and a server has nowhere to get: the trust anchor for MCUHome's
    package registry, taken from the copy the workbench ships. An
    operator who states an anchor, mirrors or ``untrusted`` for that
    domain has said what they want and keeps it.
    """
    configured = tuple(settings.value("registry") or ())
    official = api.OFFICIAL_BASE_DOMAIN
    for entry in configured:
        if entry.base_domain != official:
            continue
        if entry.anchor is not None or entry.untrusted:
            return configured
        return tuple(
            replace(one, anchor=_bundled_anchor(official)) if one is entry else one
            for one in configured
        )
    return (
        *configured,
        api.RegistrySettings(base_domain=official, anchor=_bundled_anchor(official)),
    )


def _bundled_anchor(base_domain: str) -> Path:
    return api.BUNDLED_ANCHOR_DIR / f"{base_domain}.json"


def _check_budget(build: api.BuildOptions) -> None:
    """Refuse a CPU or memory figure that cannot be read, at startup.

    Both stay strings and numbers in the configuration — the CPU figure
    because fractions are allowed, the memory figure because it carries
    a unit — and both are turned into a budget only when a step is
    started. Read only there, a typo passes startup and surfaces as an
    internal error on the first build, to whichever client happened to
    send it. So the same reading happens here, where it costs nothing
    and the operator who wrote the value is still watching.

    ``nan`` and ``inf`` are the two figures the declaration's own
    "greater than zero" does not catch: they parse as floats and would
    reach a container as a budget nobody can act on. A memory figure so
    large that it has no whole number arrives as an arithmetic error
    from the conversion behind the parse, and means the same thing to an
    operator as a figure that could not be read at all.
    """
    if build.cpus is not None and not math.isfinite(build.cpus):
        raise api.ConfigError(
            f"build.cpus must be a number of cores, not {build.cpus!r}.",
            hint="fractions are allowed — 2, 1.5",
        )
    try:
        build.limits()
    except (ArithmeticError, ValueError) as unreadable:
        raise api.ConfigError(
            f"build.memory must be an amount of memory, not {build.memory!r}.",
            hint=(
                "it takes a byte count or a number with a unit — 512m, 8g, 2048k — "
                "the way a container runtime spells it"
            ),
        ) from unreadable
