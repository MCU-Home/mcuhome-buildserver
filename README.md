# mcuhome-build-server

The build service of the [MCUHome](https://github.com/mcu-home) project:
a headless service that serves the **session build protocol**
([mcuhome ADR 0019](https://github.com/mcu-home/mcuhome/blob/main/docs/adr/0019-session-build-protocol-and-container-contract.md)).
One session is one ephemeral build environment and one effective build
context. It is the fat half of [dashboard ADR 0003](https://github.com/mcu-home/dashboard/blob/main/docs/adr/0003-two-home-assistant-apps-dashboard-never-compiles.md)'s
two-App topology, extracted into its own repository per the remote-build
architecture: the dashboard and the build server are separate products
with separate release cycles, joined by one protocol.

**The build server is an orchestrator and is never itself the build
environment.** It materializes paths, invokes the build program and
reads its result — over `docker exec` into a per-session container, or
as a subprocess in one shared filesystem where there is no container
runtime. Both profiles are specified by
[the build-container contract](https://github.com/mcu-home/mcuhome/blob/main/docs/design/build-container-contract.md) §1.2.

It has no user interface, no configuration tree, no secrets store and no
signing key. It knows the one device it is currently building and
nothing else.

> **Operate a build server as a trusted machine.** A Matter device's
> commissioning credentials are compile-time Kconfig, so this server
> necessarily learns each device's passcode, discriminator and SPAKE2+
> verifier ([dashboard ADR 0007](https://github.com/mcu-home/dashboard/blob/main/docs/adr/0007-wire-content-and-credential-exposure.md)
> decision 2). It is inside the trust boundary of every device it
> builds — exactly like the machine that holds the signing key.
>
> A leaked bearer token is **equivalent to shell access** on this
> machine. A build server reachable over a network must sit behind TLS;
> a bearer token on a plaintext connection is a token you have given
> away.

## Status: a protocol skeleton, and it cannot build

What is real is the **protocol surface**: the transport, the bearer
token, the frame envelope, session admission with version negotiation,
the lease bookkeeping, the per-layer patch policy and the typed error
registry. A client can connect, negotiate, open a session, attach to it
and close it.

What is not here is **the container backend** — context upload and
extraction, the overlay patch views, invoking the build program,
progress streaming, artifact retrieval, scheduling and metering. Every
verb that needs it answers a typed `session.not-implemented` instead of
a guess, so a client sees a protocol that is honest about its state
rather than one that almost works.

Two verbs of the amended concept are also still missing:
`lock-context`, which freezes the context and returns its id, and
`cancel`, which aborts a running invocation while the session survives
(dashboard ADR 0012 decision 3, amended 2026-08-09, from ADR 0019).
Without `lock-context` a client cannot reach `build` at all.

The one-shot job protocol that used to live here — `submit_job`,
`cancel_job`, `follow_job`, `download_artifacts`, `queue_status`, the
job directory on disk, the `mcuhome` builder subprocess and
`GET /capabilities` — has been **removed rather than migrated**. Its
transport, threat model and frame envelope are what survived, and they
are what the session protocol runs on.

## Running it

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
mcuhome-build-server
```

Every option also has an environment variable prefixed
`MCUHOME_BUILDSERVER_` (`--log-level` → `MCUHOME_BUILDSERVER_LOG_LEVEL`);
the command line wins. `--help` lists them all.

| Option | Default | What it is |
|---|---|---|
| `--host` / `--port` | `0.0.0.0` / `8100` | where to listen. A build server on loopback is a build server nobody can submit to — the safety is the mandatory token, not the binding |
| `--token`, `--token-file` | generated | the bearer token. There is no configuration without one |
| `--pair-file` | `/share/mcuhome/build-server.token` | where the token is published for a same-host App pair (written only if the directory exists) |
| `--allowed-origin` | none | accepted browser origin for the WebSocket upgrade (repeatable) |
| `--allow-patch-layer` | none | allow build-context patches for a layer (`sdk`, `zephyr`, `chip`); repeatable; unlisted layers are denied |
| `--log-level` | `INFO` | logging verbosity |

The per-server limits that ADR 0019 names for v1.0 — maximum concurrent
sessions, session TTL, idle timeout, disk budget and the compile-lane
limit — are **not configurable yet**. Three of them exist as defaults on
`SessionManager` (`sessions.py`) with no option in front of them; the
other two have nothing to limit until the container backend exists. They
belong to that work, not to this configuration surface, and inventing
options for them now would advertise knobs that do nothing.

## The API

One WebSocket endpoint, `/ws`, and one REST endpoint. Everything but
`/health` needs `Authorization: Bearer <token>`.

### Frames

Identical in shape to the dashboard's own API — there is no reason for
two envelopes in one product family:

```jsonc
// client → server
{"id": "7", "type": "open-session", "payload": {/* … */}}
// server → client, answering it
{"id": "7", "type": "result", "payload": {"session": {/* … */}}}
{"id": "7", "type": "error",  "error": {"code": "version.protocol-mismatch", /* … */}}
// server → client, unprompted
{"type": "event", "event": "…", "payload": {/* … */}}
```

Almost every refusal uses the typed session envelope below. Two codes
sit outside it, on purpose: `bad_request` for a frame that never parsed
(malformed JSON, a binary message on a text endpoint) and
`internal_error` for the command loop's catch-all. Neither has a
session or a verb to attribute a typed code to, and the registry's
layer set is fixed by the concept — so they stay in the envelope's own
vocabulary until a protocol decision says otherwise.

### Verbs

The session protocol is the whole vocabulary of this endpoint.

| Verb | Payload | Today |
|---|---|---|
| `capabilities` | `{}` | **answers**: protocol version, builder image inventory (empty until the backend exists), per-layer patch policy from configuration, quota summary |
| `open-session` | `{"profile", "protocol_version", "context_format", "manifest"}` | **answers**: admission — session id, lease, negotiated versions. A version mismatch is a typed rejection at the door |
| `send-context` | `{"session_id", …}` | typed `session.not-implemented` |
| `extend-context` | `{"session_id", …}` | typed `session.not-implemented` |
| `verify` | `{"session_id"}` | typed `session.not-implemented` |
| `build` | `{"session_id", "mode"}` | typed `session.not-implemented` |
| `get-artifact` | `{"session_id", "invocation_id", "path"}` | typed `session.not-implemented` |
| `attach-session` | `{"session_id"}` | **answers**: the session record and lease (event replay is future work) |
| `close-session` | `{"session_id"}` | **answers**: the closed session record |

An unknown verb is answered with `version.verb-unknown`, whose details
name the verbs this server does have.

`capabilities` is the pre-session query: it lets a client choose a
container during pin resolution rather than discover the mismatch from
inside one. It is token-gated like everything else on `/ws`, because
what it names — builder images, patch policy, quota — is an inventory of
the machine.

### The error envelope

Session-protocol errors use a **fixed envelope** in the error frame:

```jsonc
{"id": "7", "type": "error", "error": {
  "code": "version.protocol-mismatch",   // from the append-only registry
  "layer": "version",                    // the dotted prefix of the code
  "retryable": false,                    // authoritative — clients never infer it
  "message": "…",                        // for a human
  "details": {"server": 2, "client": 3}  // structured, code-specific
}}
```

Codes come from the append-only registry in
`mcuhome_buildserver/errors.py` (`policy.*`, `session.*`, `context.*`,
`version.*`, `builder.*`; `x-*` is reserved for third parties). A code,
once released, is never renamed, removed or re-classified; clients treat
unknown codes as non-retryable-fatal and surface the message.

Patch policy is configuration (`--allow-patch-layer`, deny by default):
the server's builder config **is** the policy, and `capabilities`
advertises it per layer so a client fails fast instead of mid-session.

### Backpressure

A client that stops reading must not apply backpressure through the log
reader and from there into a compiler, so a full outbox drops its
**oldest** frame. What makes that safe is that a progress stream carries
resumable offsets: a client whose offsets jump asks for the gap instead
of displaying a log with a silent hole in it. The stream this applies to
lands with the container backend; the outbox that will carry it is
already here.

### REST

| Endpoint | Purpose |
|---|---|
| `GET /health` | liveness, open, says nothing about what this server holds |

`/health` names this service's own version and nothing else. It used to
also report the version of the `mcuhome` builder this server spawned;
there is no such subprocess any more, and the build environments it
drives are per-session, so no single version could be named here
truthfully. What this server can build is a question for the
`capabilities` verb.

## What is on disk

**Nothing yet.** Sessions are in-memory on purpose: a session is bound
to one build environment on this machine, so unlike a job record it has
nothing worth surviving a restart — a restarted server has no
containers, and leases guarantee clients find out through typed
`session.unknown` answers rather than hangs.

Per-session directories arrive with the container backend, and ADR 0019
already fixes their lifetime: **the context and every artifact in it are
deleted at `close-session`.** Artifact download therefore happens inside
the session, after the build and before closing. There is no grace
period, because the directory it would keep alive holds a device's
commissioning credentials.

## Deployment

### On the WSL build machine (the current development target)

The real target today is the WSL instance `mcuhome-build` on the
Windows machine, with the workspace mirrored at `/root/MCUHome` — the
operational details, the sync command and the machine's own quirks live
in the workspace-level `REMOTE-BUILD.md`, which is the source of truth
for that box.

Install into the instance (once):

```sh
wsl -d mcuhome-build -u root -e sh -c '
  cd /root/MCUHome/build-server &&
  python3 -m venv /opt/mcuhome-build-server &&
  /opt/mcuhome-build-server/bin/pip install -e .
'
```

A systemd unit for the instance (it has systemd, and Docker is already
enabled there) — `/etc/systemd/system/mcuhome-build-server.service`:

```ini
[Unit]
Description=MCUHome build server
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=exec
Environment=MCUHOME_BUILDSERVER_TOKEN_FILE=/etc/mcuhome/build-server.token
ExecStart=/opt/mcuhome-build-server/bin/mcuhome-build-server --no-pair-file
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Create the token once and keep it out of the unit file, where `systemctl
show` would print it:

```sh
install -d -m 700 /etc/mcuhome
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > /etc/mcuhome/build-server.token
chmod 600 /etc/mcuhome/build-server.token
systemctl enable --now mcuhome-build-server
```

The instance's address changes with WSL's NAT; reach it from the dev
machine over the Windows host's port proxy, or over SSH with a
forwarded port. Either way the dashboard is configured with a URL and
that token.

### As a Home Assistant App

Packaging lives in the future packaging repo, not here. What this
package expects of it: `/share` mounted so the token can be published
for the dashboard App to find, and a build environment it can drive —
which in an App is the `subprocess` profile of the container contract,
since an App has no container runtime of its own.

### Standalone and self-hosted

The primary target (ADR 0019): a machine an operator installs the
service on and reaches over the transport above. Storage for
per-session context and output arrives with the container backend.

## Development

```sh
pytest                       # the whole suite, no real build
ruff check --fix . && ruff format .
```

The suite never compiles anything, and nothing in it fakes a build
environment either: this server is an orchestrator, so what is under
test is the transport, the bearer token and the session protocol — all
of which run without a toolchain anywhere near them.

The frame envelope is kept from drifting apart from the dashboard's by
`tests/test_protocol.py`, which compares this package's constants
against `mcuhome_dashboard.protocol` whenever both are importable —
install the sibling checkout's backend (`pip install -e
../dashboard/backend`) to run that check; it skips otherwise.

## Layout

| Module | Role |
|---|---|
| `config.py` | command line, environment, the token rules |
| `server.py` | process entry point; binds and serves |
| `app.py` | shared state, the app factory, `/health` |
| `security.py` | the bearer token, origin check, same-host pairing |
| `protocol.py` | the frame envelope and its codec |
| `errors.py` | the session protocol's error envelope and its append-only code registry |
| `sessions.py` | session protocol v2: the session registry and one handler per verb |
| `ws.py` | the `/ws` endpoint and the command loop |
