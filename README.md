# mcuhome-buildserver

`mcuhome-buildserver` is a headless service that runs a MCUHome firmware build
on a machine other than the one asking for it. It is the remote half of the
build path: it serves the session protocol and drives build environments
without ever being one.

## Status: remote builds run on the build-environment image

A build environment is a container image that declares the packages it was
assembled from, and this server runs one. A build context pins those
**packages** — the workspace and the tools package, each by name, version and
content hash — and this server finds the image whose labels declare exactly
that set, in a repository its operator allows, and starts one fresh container
per build step in it. What comes back is an unsigned image and the build report
its client signs from; this server holds no key and never signs.

**What it accepts.** A build may carry an image pin, in the `send-context`
payload and never inside the context — a context references packages and never
an image. Four forms: none at all, a bare repository, `:<tag>` or
`@sha256:<digest>` on their own, or the canonical `<repository>:<tag>` /
`<repository>@sha256:<digest>`. A pin narrows which images are looked at and
never what is accepted: the labels are checked either way, and an image that
declares a different package set is a different environment and is refused. A
pin naming a repository outside `server.allowed_container_repositories` is
refused before any registry is asked; without a pin the allowed repositories
are searched in order, newest assembly revision first. Which image was chosen is answered at
`send-context` — its digest and the declaration its labels carry — and a client
records that digest as what built the firmware.

**Where the packages come from.** A context's packages are fetched from the
directories the operator configured — `build.sdk_sources`,
`build.workspace_sources`, `build.tools_sources`, one key per package kind —
and, behind them, from the package registry. That registry is configured the
way a project configures one, under `registry.<base-domain>`: its mirrors, its
trust anchor, whether an unsigned source is accepted. MCUHome's own registry
keeps the trust anchor the workbench ships unless a configuration names
another, so a server that configures nothing trusts exactly what a workstation
trusts.

**A developer build cannot be built here.** A context created against a west
workspace somebody maintains themselves names no packages anybody else has, and
this server says so instead of guessing. Neither can a context that does not say
which tool wrote it: the declaration is what a build environment's own "which
contexts do I accept" is checked against, so a context without it is refused
before an environment is started for it.

## What this repository holds

- The session protocol: one WebSocket endpoint, a frame envelope, and eleven
  verbs (`capabilities`, `open-session`, `send-context`, `extend-context`,
  `lock-context`, `verify`, `build`, `cancel`, `get-artifact`,
  `attach-session`, `close-session`) and the state machine they move through.
- The context store: streaming ingress caps, safe extraction into a per-session
  directory this server owns, and the freeze that computes the context ID and
  writes the manifest beside the uploaded pins.
- The build-environment half of a session: the image lookup by package labels,
  one fresh container per build step, the invocation record, the event and log
  relay, and artifact egress.
- Policy an operator sets: the repositories a build environment may come from,
  bearer-token authentication, same-host pairing for the Home Assistant case,
  session seats, and the caps that bound uploads, disk and container resources.
- The process entry point (`mcuhome-buildserver`): the configuration ladder
  every MCUHome program reads, `/ws` for sessions and `/health` for liveness.

## Using it

The package installs a console script. Given a bearer token, it binds a host
and a port and serves the session protocol until it is stopped.

```sh
printf %s "$TOKEN" | mcuhome-buildserver --server-token -
```

A client opens a session, uploads a build context, locks it, and asks for a
build; what comes back over the same session is an unsigned image and the build
report its client signs from. `verify` is answered by this server itself — it
re-measures the locked context against what it froze, which is the one question
a build environment could not answer better.

## How it fits into MCUHome

Builds here run through the container profile of
[`mcuhome-workbench`](https://github.com/mcu-home/mcuhome-workbench) — the
image lookup, the launcher and the judgement of what came back are the same
code a local container build runs, so a fix to either is a fix to both. What a
build environment is, and what it may assume, is the build environment
specification in [`mcuhome-sdk`](https://github.com/mcu-home/mcuhome-sdk),
which also publishes the packages a context pins and the images that deliver
them. The context ID that both ends compute comes from `mcuhome-model`. The
clients that open sessions are
[`mcuhome-cli`](https://github.com/mcu-home/mcuhome-cli) and
[`mcuhome-ui`](https://github.com/mcu-home/mcuhome-ui), each through the
session client on the caller's side of the protocol, and neither a dependency
of this package.

## Development — how to work on this repository

This repository has its own virtual environment in `.venv/`; nothing is
installed into the system Python or into another repository's environment.
`bin/` holds the user-facing entry points, `scripts/` the development
tooling: `scripts/test` and `scripts/lint` dispatch the checks — `all` runs
every one, `list` names them, `<name>` runs one — and each check is its own
wrapper in `scripts/test.d/` or `scripts/lint.d/`. The wrappers select
`.venv` themselves (never activate one by hand) and are exactly what CI
runs, one job per check.

Needs Python ≥3.13; `requirements-dev.txt` installs it together with sibling
checkouts of `mcuhome-sdk` (`packaging/model`) and `mcuhome-workbench`, whose
container profile this server drives a build with — see the file for the
git-URL form when this is the only checkout. `scripts/test e2e` additionally
needs a container runtime, `mcuhome.model.context` importable from `.venv`,
the `mcuhome` command in it (the harness drives the real client), and an SDK
archive directory — its first argument or `MCUHOME_E2E_SDK_DIR`, built with
`mcuhome-sdk/scripts/build_sdk_archive.py`. It pins no image: the
environment is resolved from the allowed repositories and fetched if this
host does not hold it.

```sh
python3 -m venv .venv && .venv/bin/pip install \
  -r requirements-dev.txt --group dev
```

```sh
scripts/test all
scripts/lint all
```

The rules that hold across every MCUHome repository — coding standards,
commits, licensing — are in the organization's
[contributing guide](https://github.com/mcu-home/.github/blob/main/CONTRIBUTING.md).

## Configuration

This server reads the configuration every MCUHome program on the host reads,
and it reads it the same way. Its own options are the area `server`; what it
shares with a build on a workstation keeps that build's key. A key is
`<area>.<name>`, its environment variable is `MCUHOME_` plus the key in capitals,
and its flag is `--` plus the key with dots and underscores as dashes — one
declaration, three spellings, none of them written down twice.

### The layers

Ascending, later wins, and `--print-config` says which one every value came
from:

```
default → program → /etc/mcuhome/configuration.yaml → $XDG_CONFIG_HOME/mcuhome/configuration.yaml → --server-config → environment → flags
```

`program` is this server's own value for a shared key: it states `build.memory`
as `8g` there, because a workstation with no memory ceiling builds with whatever
is free while a build server whose linker took the host down would take every
other session with it. It sits below every file, so an operator's configuration
still wins.

`--server-config` names this server's own `mcuhome.yaml`, read in the place a
project's file has. A build server has no project, and that file is the nearest
thing it has to one — same areas, same keys, same spellings:

```yaml
server:
  max_sessions: 2
  allowed_container_repositories:
    - ghcr.io/mcu-home/build-environment
build:
  memory: 12g
  sdk_sources:
    - /srv/mcuhome/packages
registry:
  packages.mcuhome.org:
    mirrors:
      mcuhome-sdk:
        - /srv/mcuhome/mirror
```

The directory that file lies in is also where trust anchors are looked for
(`secrets/trust-anchor/<base-domain>.json`), exactly as in a project.

### What this server does for its own operation

| Key | Flag | Variable | Default | What it controls |
|---|---|---|---|---|
| `server.host` | `--server-host` | `MCUHOME_SERVER_HOST` | `0.0.0.0` | the address this server binds |
| `server.port` | `--server-port` | `MCUHOME_SERVER_PORT` | `8100` | the port this server binds |
| `server.allowed_origins` | `--server-allowed-origins` | `MCUHOME_SERVER_ALLOWED_ORIGINS` | – | browser origins accepted for the WebSocket upgrade |
| `server.log_level` | `--server-log-level` | `MCUHOME_SERVER_LOG_LEVEL` | `INFO` | logging verbosity |
| `server.token_file` | `--server-token-file` | `MCUHOME_SERVER_TOKEN_FILE` | – | the file holding the bearer token clients must present |
| `server.pair_file` | `--server-pair-file` | `MCUHOME_SERVER_PAIR_FILE` | `/share/mcuhome/build-server.token` | where the bearer token is published for a same-host App pair |
| `server.publish_pair_file` | `--server-publish-pair-file` | – | `true` | publish the bearer token to the pair file at all |
| `server.context_root` | `--server-context-root` | `MCUHOME_SERVER_CONTEXT_ROOT` | – | the directory the per-session directories are created in |
| `server.session_idle_timeout_seconds` | `--server-session-idle-timeout-seconds` | `MCUHOME_SERVER_SESSION_IDLE_TIMEOUT_SECONDS` | `600` | how long a session may sit idle before it is closed |
| `server.max_sessions` | `--server-max-sessions` | `MCUHOME_SERVER_MAX_SESSIONS` | `4` | how many sessions may be open at once |
| `server.seat_retry_seconds` | `--server-seat-retry-seconds` | `MCUHOME_SERVER_SEAT_RETRY_SECONDS` | `60` | base wait a refused client is told to keep before presenting its seat again |
| `server.seat_retry_max_seconds` | `--server-seat-retry-max-seconds` | `MCUHOME_SERVER_SEAT_RETRY_MAX_SECONDS` | `900` | ceiling on that wait, however deep the queue is |
| `server.max_seats` | `--server-max-seats` | `MCUHOME_SERVER_MAX_SEATS` | `128` | how many waiting turns this server holds before it stops issuing them |
| `server.reconnect_grace_seconds` | `--server-reconnect-grace-seconds` | `MCUHOME_SERVER_RECONNECT_GRACE_SECONDS` | `60` | how long a session whose client is gone is kept before a waiting one may have it |
| `server.max_connections` | `--server-max-connections` | `MCUHOME_SERVER_MAX_CONNECTIONS` | `64` | concurrent /ws connections this server accepts before it refuses the upgrade |
| `server.max_inflight_commands` | `--server-max-inflight-commands` | `MCUHOME_SERVER_MAX_INFLIGHT_COMMANDS` | `32` | in-flight command tasks one /ws connection may run at once |
| `server.build_deadline_seconds` | `--server-build-deadline-seconds` | `MCUHOME_SERVER_BUILD_DEADLINE_SECONDS` | `5400` | how long one invocation may run before this server stops it |
| `server.cancel_grace_seconds` | `--server-cancel-grace-seconds` | `MCUHOME_SERVER_CANCEL_GRACE_SECONDS` | `60` | how long a cancelled invocation has to stop itself before the hard path |
| `server.allowed_container_repositories` | `--server-allowed-container-repositories` | `MCUHOME_SERVER_ALLOWED_CONTAINER_REPOSITORIES` | `ghcr.io/mcu-home/build-environment` | build-environment repository this server may run, without tag or digest; searched in the order given and enforced as the boundary a pinned repository has to be inside |
| `server.auto_pull` | `--server-auto-pull` | – | `true` | fetch an allowed build environment this host does not have yet |
| `server.allowed_patch_layers` | `--server-allowed-patch-layers` | `MCUHOME_SERVER_ALLOWED_PATCH_LAYERS` | – | build-context patch layer this server accepts (sdk, zephyr, chip, mcuboot, or a third-party x-* name); unlisted layers are denied |
| `server.max_compressed_bytes` | `--server-max-compressed-bytes` | `MCUHOME_SERVER_MAX_COMPRESSED_BYTES` | `67108864` | ingress cap: the archive bytes a session may upload in total |
| `server.max_decompressed_bytes` | `--server-max-decompressed-bytes` | `MCUHOME_SERVER_MAX_DECOMPRESSED_BYTES` | `268435456` | ingress cap: the cumulative unpacked bytes a session may produce |
| `server.max_entries` | `--server-max-entries` | `MCUHOME_SERVER_MAX_ENTRIES` | `4096` | ingress cap: the archive entries a session may deliver in total |
| `server.max_file_bytes` | `--server-max-file-bytes` | `MCUHOME_SERVER_MAX_FILE_BYTES` | `67108864` | ingress cap: the size of one context file |
| `server.max_path_depth` | `--server-max-path-depth` | `MCUHOME_SERVER_MAX_PATH_DEPTH` | `16` | ingress cap: the path segments one context entry may have |
| `server.max_context_yaml_bytes` | `--server-max-context-yaml-bytes` | `MCUHOME_SERVER_MAX_CONTEXT_YAML_BYTES` | `65536` | ingress cap: the size of the context.yaml pin document, bounded before it is parsed |
| `server.session_quota_bytes` | `--server-session-quota-bytes` | `MCUHOME_SERVER_SESSION_QUOTA_BYTES` | `2147483648` | per-session disk quota in bytes, answered typed rather than by host exhaustion |
| `server.max_artifact_bytes` | `--server-max-artifact-bytes` | `MCUHOME_SERVER_MAX_ARTIFACT_BYTES` | `268435456` | egress cap: the size of one artifact this server will serve |

The two booleans have no variable: the configuration layer has no spelling for
a boolean in an environment variable, and a channel that cannot be read is
worse than one that was never offered. Both are set in a configuration file or
with their own flags, and a boolean always has both — `--server-auto-pull` and
`--no-server-auto-pull` — because "not used" and "turned off" are different
statements.

### What it shares with a build on a workstation

These are the workbench's own keys and mean here what they mean there. A list
in a variable holds paths separated by the platform's path separator (`:` on
Linux), and a flag that carries a list is repeatable — each use appends one
entry.

| Key | Flag | Variable | Default | What it controls |
|---|---|---|---|---|
| `build.container_program` | `--build-container-program` | `MCUHOME_BUILD_CONTAINER_PROGRAM` | `docker` | the program that runs build containers |
| `build.cpus` | `--build-cpus` | `MCUHOME_BUILD_CPUS` | – | how much CPU one build may use, in cores; unset means all of them |
| `build.memory` | `--build-memory` | `MCUHOME_BUILD_MEMORY` | – | how much memory one build may use (512m, 8g, or bytes); unset means what is free |
| `build.pids` | `--build-pids` | `MCUHOME_BUILD_PIDS` | `4096` | how many processes one build container may have at once |
| `build.cache_shared` | `--build-cache-shared` | `MCUHOME_BUILD_CACHE_SHARED` | – | a compiler cache shared with other machines, read-only to a build |
| `build.sdk_sources` | `--build-sdk-sources` | `MCUHOME_BUILD_SDK_SOURCES` | – | directories holding hash-pinned MCUHome SDK packages |
| `build.workspace_sources` | `--build-workspace-sources` | `MCUHOME_BUILD_WORKSPACE_SOURCES` | – | directories holding build workspace packages |
| `build.tools_sources` | `--build-tools-sources` | `MCUHOME_BUILD_TOOLS_SOURCES` | – | directories holding build tools packages |

The three package-source keys are one rule and no fallback: each names the
directories searched for packages of **its own kind**, and a kind is never
looked for under another kind's key — a machine that keeps all three in one
directory names that directory in all three keys. Behind them is the package
registry.

Every other `build` key of the workbench may still be set in a file or a
variable — the files are shared — and simply has no flag here, because this
server does not read it.

### Package registries

`registry.<base-domain>` is a map in a configuration file, keyed by domain,
exactly as a project writes it: `mirrors.<source>` replaces the mirror list a
source serves, `anchor` names the trust-anchor file to check its signatures
against, and `untrusted: true` accepts an unsigned source with a warning.
MCUHome's own registry keeps the trust anchor the workbench ships unless a
configuration states one for it.

### The bearer token

A token is not optional, and there is no environment variable for one: a secret
in a variable is in the environment of every child process this server starts.
Two channels:

- `--server-token <value>`, and `--server-token -` reads it from standard input
  so it stands in no shell history and in no process list:
  `printf %s "$TOKEN" | mcuhome-buildserver --server-token -`
- `server.token_file` — the file that holds it, named in a configuration file,
  in `MCUHOME_SERVER_TOKEN_FILE`, or with `--server-token-file`.

Configure neither and one is generated at startup and logged once, so a fresh
container is usable in one step and never open. The token is also published to
`server.pair_file` for a same-host Home Assistant App pair, unless the
directory does not exist or `--no-server-publish-pair-file` says not to.

### Spellings this server used to have

One thing has one spelling. Every flag below is refused by name, with what
states the same thing today; nothing is accepted as an alias.

| Written before | It is now |
|---|---|
| `--host` | `server.host` (`--server-host`) |
| `--port` | `server.port` (`--server-port`) |
| `--allowed-origin` | `server.allowed_origins` (`--server-allowed-origins`) |
| `--log-level` | `server.log_level` (`--server-log-level`) |
| `--token` | `--server-token`, which also takes `-`; `server.token_file` names a file |
| `--token-file` | `server.token_file` (`--server-token-file`) |
| `--pair-file` | `server.pair_file` (`--server-pair-file`) |
| `--no-pair-file` | `--no-server-publish-pair-file`, the boolean `server.publish_pair_file` |
| `--context-root` | `server.context_root` (`--server-context-root`) |
| `--session-idle-timeout-seconds` | `server.session_idle_timeout_seconds` (`--server-session-idle-timeout-seconds`) |
| `--max-sessions` | `server.max_sessions` (`--server-max-sessions`) |
| `--seat-retry-seconds` | `server.seat_retry_seconds` (`--server-seat-retry-seconds`) |
| `--seat-retry-max-seconds` | `server.seat_retry_max_seconds` (`--server-seat-retry-max-seconds`) |
| `--max-seats` | `server.max_seats` (`--server-max-seats`) |
| `--reconnect-grace-seconds` | `server.reconnect_grace_seconds` (`--server-reconnect-grace-seconds`) |
| `--max-connections` | `server.max_connections` (`--server-max-connections`) |
| `--max-inflight-commands` | `server.max_inflight_commands` (`--server-max-inflight-commands`) |
| `--build-deadline-seconds` | `server.build_deadline_seconds` (`--server-build-deadline-seconds`) |
| `--cancel-grace-seconds` | `server.cancel_grace_seconds` (`--server-cancel-grace-seconds`) |
| `--max-compressed-bytes` | `server.max_compressed_bytes` (`--server-max-compressed-bytes`) |
| `--max-decompressed-bytes` | `server.max_decompressed_bytes` (`--server-max-decompressed-bytes`) |
| `--max-entries` | `server.max_entries` (`--server-max-entries`) |
| `--max-file-bytes` | `server.max_file_bytes` (`--server-max-file-bytes`) |
| `--max-path-depth` | `server.max_path_depth` (`--server-max-path-depth`) |
| `--max-context-yaml-bytes` | `server.max_context_yaml_bytes` (`--server-max-context-yaml-bytes`) |
| `--session-quota-bytes` | `server.session_quota_bytes` (`--server-session-quota-bytes`) |
| `--max-artifact-bytes` | `server.max_artifact_bytes` (`--server-max-artifact-bytes`) |
| `--allow-environment` | `server.allowed_container_repositories` (`--server-allowed-container-repositories`) |
| `--no-auto-pull` | `--no-server-auto-pull`, the boolean `server.auto_pull` |
| `--allow-patch-layer` | `server.allowed_patch_layers` (`--server-allowed-patch-layers`) |
| `--docker` | `build.container_program` (`--build-container-program`) |
| `--container-memory` | `build.memory` (`--build-memory`) |
| `--container-cpus` | `build.cpus` (`--build-cpus`) |
| `--container-pids` | `build.pids` (`--build-pids`) |
| `--ccache-dir` | `build.cache_shared` (`--build-cache-shared`) |
| `--sdk-source` | `build.sdk_sources` (`--build-sdk-sources`), and the two kinds beside it |

The whole `MCUHOME_BUILDSERVER_` family is refused the same way: an option's
variable derives from its key, and these keys are in the areas `server` and
`build`.

| Written before | It is now |
|---|---|
| `MCUHOME_BUILDSERVER_HOST` | `MCUHOME_SERVER_HOST` |
| `MCUHOME_BUILDSERVER_PORT` | `MCUHOME_SERVER_PORT` |
| `MCUHOME_BUILDSERVER_ALLOWED_ORIGINS` | `MCUHOME_SERVER_ALLOWED_ORIGINS` |
| `MCUHOME_BUILDSERVER_LOG_LEVEL` | `MCUHOME_SERVER_LOG_LEVEL` |
| `MCUHOME_BUILDSERVER_TOKEN` | no variable — `--server-token -` or `server.token_file` |
| `MCUHOME_BUILDSERVER_TOKEN_FILE` | `MCUHOME_SERVER_TOKEN_FILE` |
| `MCUHOME_BUILDSERVER_PAIR_FILE` | `MCUHOME_SERVER_PAIR_FILE` |
| `MCUHOME_BUILDSERVER_CONTEXT_ROOT` | `MCUHOME_SERVER_CONTEXT_ROOT` |
| `MCUHOME_BUILDSERVER_SESSION_IDLE_TIMEOUT_SECONDS` | `MCUHOME_SERVER_SESSION_IDLE_TIMEOUT_SECONDS` |
| `MCUHOME_BUILDSERVER_MAX_SESSIONS` | `MCUHOME_SERVER_MAX_SESSIONS` |
| `MCUHOME_BUILDSERVER_SEAT_RETRY_SECONDS` | `MCUHOME_SERVER_SEAT_RETRY_SECONDS` |
| `MCUHOME_BUILDSERVER_SEAT_RETRY_MAX_SECONDS` | `MCUHOME_SERVER_SEAT_RETRY_MAX_SECONDS` |
| `MCUHOME_BUILDSERVER_MAX_SEATS` | `MCUHOME_SERVER_MAX_SEATS` |
| `MCUHOME_BUILDSERVER_RECONNECT_GRACE_SECONDS` | `MCUHOME_SERVER_RECONNECT_GRACE_SECONDS` |
| `MCUHOME_BUILDSERVER_MAX_CONNECTIONS` | `MCUHOME_SERVER_MAX_CONNECTIONS` |
| `MCUHOME_BUILDSERVER_MAX_INFLIGHT_COMMANDS` | `MCUHOME_SERVER_MAX_INFLIGHT_COMMANDS` |
| `MCUHOME_BUILDSERVER_BUILD_DEADLINE_SECONDS` | `MCUHOME_SERVER_BUILD_DEADLINE_SECONDS` |
| `MCUHOME_BUILDSERVER_CANCEL_GRACE_SECONDS` | `MCUHOME_SERVER_CANCEL_GRACE_SECONDS` |
| `MCUHOME_BUILDSERVER_MAX_COMPRESSED_BYTES` | `MCUHOME_SERVER_MAX_COMPRESSED_BYTES` |
| `MCUHOME_BUILDSERVER_MAX_DECOMPRESSED_BYTES` | `MCUHOME_SERVER_MAX_DECOMPRESSED_BYTES` |
| `MCUHOME_BUILDSERVER_MAX_ENTRIES` | `MCUHOME_SERVER_MAX_ENTRIES` |
| `MCUHOME_BUILDSERVER_MAX_FILE_BYTES` | `MCUHOME_SERVER_MAX_FILE_BYTES` |
| `MCUHOME_BUILDSERVER_MAX_PATH_DEPTH` | `MCUHOME_SERVER_MAX_PATH_DEPTH` |
| `MCUHOME_BUILDSERVER_MAX_CONTEXT_YAML_BYTES` | `MCUHOME_SERVER_MAX_CONTEXT_YAML_BYTES` |
| `MCUHOME_BUILDSERVER_SESSION_QUOTA_BYTES` | `MCUHOME_SERVER_SESSION_QUOTA_BYTES` |
| `MCUHOME_BUILDSERVER_MAX_ARTIFACT_BYTES` | `MCUHOME_SERVER_MAX_ARTIFACT_BYTES` |
| `MCUHOME_BUILDSERVER_ALLOW_ENVIRONMENTS` | `MCUHOME_SERVER_ALLOWED_CONTAINER_REPOSITORIES` |
| `MCUHOME_BUILDSERVER_AUTO_PULL` | no variable — the boolean `server.auto_pull` |
| `MCUHOME_BUILDSERVER_ALLOW_PATCH_LAYERS` | `MCUHOME_SERVER_ALLOWED_PATCH_LAYERS` |
| `MCUHOME_BUILDSERVER_DOCKER` | `MCUHOME_BUILD_CONTAINER_PROGRAM` |
| `MCUHOME_BUILDSERVER_CONTAINER_MEMORY` | `MCUHOME_BUILD_MEMORY` |
| `MCUHOME_BUILDSERVER_CONTAINER_CPUS` | `MCUHOME_BUILD_CPUS` |
| `MCUHOME_BUILDSERVER_CONTAINER_PIDS` | `MCUHOME_BUILD_PIDS` |
| `MCUHOME_BUILDSERVER_CCACHE_DIR` | `MCUHOME_BUILD_CACHE_SHARED` |
| `MCUHOME_BUILDSERVER_SDK_SOURCES` | `MCUHOME_BUILD_SDK_SOURCES`, and the two kinds beside it |

A variable is refused rather than warned about, which is where this server
differs from a command line a person types: it is started once, deliberately,
from a unit file or a container definition, and a variable that was quietly
ignored would be an operator's token, allowlist or cache not in effect.

### Seeing what is in effect

```sh
mcuhome-buildserver --print-config
```

answers every option, its value, and the layer and the file, variable or flag
it came from — and exits without binding anything.

## Security

A session is equivalent to shell access on the host it runs on: a build
compiles data the session supplied, and the bearer token is the gate in front
of that. A server reachable over a network belongs behind TLS, because a bearer
token on a plaintext connection is a token that has been given away. This
server holds no private key and signs nothing, and it runs a build environment
only from a repository its operator listed. Vulnerabilities are reported
through the organization's
[security policy](https://github.com/mcu-home/.github/blob/main/SECURITY.md).

## Documentation

- [Build environment specification](https://github.com/mcu-home/mcuhome-sdk/blob/main/docs/spec/build-environment-specification.md) — what a session runs
- [Build context format](https://github.com/mcu-home/mcuhome-sdk/blob/main/docs/spec/build-context-format.md) — the document a client uploads
- [Build actions](https://github.com/mcu-home/mcuhome-sdk/blob/main/docs/spec/build-actions.md) — what an invocation asks for
- [MCUHome project overview](https://github.com/mcu-home) — the repositories and how they relate

## Contributing and support

Bugs and feature requests go through
[Issues](https://github.com/mcu-home/mcuhome-buildserver/issues). Read the
organization's [contributing guide](https://github.com/mcu-home/.github/blob/main/CONTRIBUTING.md)
before opening a pull request.

## License

Apache-2.0. See [LICENSE](LICENSE).
