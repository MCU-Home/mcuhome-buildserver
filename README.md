# mcuhome-buildserver

`mcuhome-buildserver` is a headless service that runs a MCUHome firmware build
on a machine other than the one asking for it. It is the remote half of the
build path: it serves the session protocol and drives build environments
without ever being one.

## What this repository holds

- The session protocol: one WebSocket endpoint, a frame envelope, and eleven
  verbs (`capabilities`, `open-session`, `send-context`, `extend-context`,
  `lock-context`, `verify`, `build`, `cancel`, `get-artifact`,
  `attach-session`, `close-session`) and the state machine they move through.
- The context store: streaming ingress caps, safe extraction into a per-session
  directory this server owns, and the freeze that computes the context ID and
  writes the manifest beside the uploaded pins.
- The build-environment half of a session: one container per session, the
  invocation record, the event and log relay, and artifact egress.
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
verify or a build; what comes back over the same session is an unsigned image
and the build report its client signs from.

## How it fits into MCUHome

Builds here run through [`mcuhome-workbench`](https://github.com/mcu-home/mcuhome-workbench),
whose build API materializes a session's build environment — the same object a
local build gets. The context ID that both ends compute comes from
`mcuhome-model`, which [`mcuhome-sdk`](https://github.com/mcu-home/mcuhome-sdk)
publishes along with the build environments themselves; a client pins one by
digest in the context it uploads. The clients that open sessions are
[`mcuhome-cli`](https://github.com/mcu-home/mcuhome-cli) and
[`mcuhome-ui`](https://github.com/mcu-home/mcuhome-ui), each through the
session client on the caller's side of the protocol, and neither a dependency
of this package.

## Working on this repository

Python 3.13 and a container runtime are the environment. `requirements-dev.txt`
satisfies the two MCUHome dependencies from sibling checkouts of `mcuhome-sdk`
and `mcuhome-workbench`, and names the git URLs to install them from when this
is the only checkout; the unit suite lives in `tests/python`. `tests/e2e/run.py`
drives this server as a real process, against a real build environment and a real
client, through one remote build. Continuous integration runs ruff, both
suites, REUSE, codespell, and the file-hygiene and commit-message checks.

```sh
pip install -r requirements-dev.txt
pytest
```

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
- [Decision records](https://github.com/mcu-home/mcuhome-workbench/tree/main/docs/adr) — the project's architecture decisions
- [MCUHome project overview](https://github.com/mcu-home) — the repositories and how they relate

## Contributing and support

Bugs and feature requests go through
[Issues](https://github.com/mcu-home/mcuhome-buildserver/issues). Read the
organization's [contributing guide](https://github.com/mcu-home/.github/blob/main/CONTRIBUTING.md)
before opening a pull request.

## License

Apache-2.0. See [LICENSE](LICENSE).
