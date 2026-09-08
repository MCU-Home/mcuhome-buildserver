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
pin naming a repository outside `--allow-environment` is refused before any
registry is asked; without a pin the allowed repositories are searched in
order, newest assembly revision first. The digest that actually ran is in the
build's own record.

**One limitation worth stating plainly.** The packages a context pins are
fetched from the directories the operator configured (`--sdk-source`) and,
behind them, from MCUHome's own package registry — `packages.mcuhome.org`,
checked against the trust anchor the workbench ships. There is no option for a
different registry and none for a different trust anchor: a build server is an
operator's machine and not a project, and a trust root that a flag could point
elsewhere would be a trust decision made where nobody looks.

**A developer build cannot be built here.** A context created against a west
workspace somebody maintains themselves names no packages anybody else has, and
this server says so instead of guessing.

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
- The process entry point (`mcuhome-buildserver`): configuration from flags and
  environment, `/ws` for sessions and `/health` for liveness.

## Using it

The package installs a console script. Given a bearer token, it binds a host
and a port and serves the session protocol until it is stopped.

```sh
mcuhome-buildserver --token-file /path/to/token
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
checkouts of `mcuhome-sdk` (`packaging/model`) and `mcuhome-workbench`, the
build environment this server orchestrates — see the file for the git-URL
form when this is the only checkout. `scripts/test e2e` additionally needs a
container runtime and the pinned build-container image.

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

Every option is a command-line flag with an environment form prefixed
`MCUHOME_BUILDSERVER_`: bind address, the bearer token or the file holding it,
the directories SDK packages are read from, the build-environment repositories
this server may run, and the limits on uploads, sessions and containers. Run
`mcuhome-buildserver --help` for the full list.

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
