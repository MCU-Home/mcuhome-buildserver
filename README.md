# mcuhome-build-server

The build service of the [MCUHome](https://github.com/mcu-home) project:
a headless service that takes a resolved `device-model.json` over the
protocol of [dashboard ADR 0006](https://github.com/mcu-home/dashboard/blob/main/docs/adr/0006-build-service-protocol.md),
compiles it with the `mcuhome` builder, and hands the artifacts back. It
is the fat half of [dashboard ADR 0003](https://github.com/mcu-home/dashboard/blob/main/docs/adr/0003-two-home-assistant-apps-dashboard-never-compiles.md)'s
two-App topology, extracted into its own repository per the remote-build
architecture: the dashboard and the build server are separate products
with separate release cycles, joined by one protocol.

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

## Status: blocked on one builder flag

Everything in this package works, and no job can be built yet, because
of one gap in the builder's CLI:

**ADR 0007 decision 1 makes the resolved `device-model.json` the wire
format, and `mcuhome build` cannot consume one.** It takes a `<device>`
argument that is a folder name or a path to a *YAML configuration*, and
re-runs stages 1-3 itself. What is needed is a single option:

```sh
mcuhome build --model <device-model.json> --build-dir <dir> --no-sign --public-key <pem> --json
```

Reconstructing YAML from a model here was the alternative, and it is the
one thing this side may never do — it would be a second implementation
of what a valid configuration is, on the side of the boundary that must
not hold one (the schema is owned by the firmware repository).

So the server **asks** rather than assumes. At startup it probes
`mcuhome build --help`; `GET /capabilities` reports
`builder.model_input`; and while it is `false`, `submit_job` is refused
with `unsupported` and a message naming exactly what is missing —
ADR 0006 decision 4's "a clear refusal, never a silent fallback, never a
failure ten minutes into a compile". When the flag lands in the firmware
repository, nothing here changes.
`mcuhome_buildserver/builder.py` carries the full argument.

## Running it

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt        # builder lib from ../mcuhome, `mcuhome` command from ../cli
mcuhome-build-server --workspace /root/MCUHome
```

Every option also has an environment variable prefixed
`MCUHOME_BUILDSERVER_` (`--jobs-root` → `MCUHOME_BUILDSERVER_JOBS_ROOT`);
the command line wins. `--help` lists them all.

| Option | Default | What it is |
|---|---|---|
| `--host` / `--port` | `0.0.0.0` / `8100` | where to listen. A build server on loopback is a build server nobody can submit to — the safety is the mandatory token, not the binding |
| `--token`, `--token-file` | generated | the bearer token. There is no configuration without one |
| `--pair-file` | `/share/mcuhome/build-server.token` | where the token is published for a same-host App pair (written only if the directory exists) |
| `--jobs-root` | `/data/jobs` inside an App | one sub-directory per job |
| `--workspace` | builder discovers it | west workspace top directory the builder compiles in |
| `--slots` | `1` | concurrent compiles (ADR 0006 decision 5) |
| `--build-jobs` | builder's detection | `MCUHOME_JOBS` for the child — a dedicated machine knows better than the RAM heuristic |
| `--native` / `--no-native` | container | `--native` compiles on this machine's own toolchain instead of in the builder image |
| `--image` | builder's default | builder container image tag |
| `--job-timeout` | `3600` | seconds before a build is killed |
| `--keep-jobs`, `--job-ttl-days` | `20`, `14` | retention (ADR 0008 decision 4) |
| `--allow-patch-layer` | none | session protocol v2: allow build-context patches for a layer (`sdk`, `zephyr`, `chip`); repeatable; unlisted layers are denied |

## The API

One WebSocket endpoint, `/ws`, plus two REST endpoints. Everything but
`/health` needs `Authorization: Bearer <token>`.

### Frames

Identical in shape to the dashboard's own API — ADR 0006 decision 2
makes the frame vocabulary the contract, and there is no reason for two
envelopes in one product family:

```jsonc
// client → server
{"id": "7", "type": "submit_job", "payload": {/* … */}}
// server → client, answering it
{"id": "7", "type": "result", "payload": {"job_id": "20260808-143012-a1b2c3"}}
{"id": "7", "type": "error",  "error": {"code": "unsupported", "message": "…"}}
// server → client, unprompted
{"type": "event", "event": "job_state_changed", "payload": {"job": {/* … */}}}
```

Error codes: `bad_request`, `not_found`, `unauthorized`, `unavailable`,
`conflict`, `unsupported`, `internal_error`. `unsupported` is the
negotiation failure of ADR 0006 decision 4 — the frame is fine and this
server cannot honour it. An unknown command is answered with the typed
envelope of the session protocol below (`version.verb-unknown`), which
names the known verbs.

### Commands

| Command | Payload | Result |
|---|---|---|
| `submit_job` | `{"model", "model_version", "public_key", "options"}` | `{"job_id", "job"}` |
| `cancel_job` | `{"job_id"}` | `{"job"}` |
| `follow_job` | `{"job_id", "offset"}` | `{"job_id", "state", "offset", "text", "next_offset", "eof", "live"}` |
| `download_artifacts` | `{"job_id"}` or `{"job_id", "path", "offset"}` | the index, or one chunk |
| `queue_status` | `{"limit"}` | `{"slots", "queued", "running", "jobs"}` |

`options`: `{"native": false, "image": null, "snippets": [], "jobs": null}`.

**`submit_job` never signs.** There is no `sign` option and `no_sign`
may only be `true`: the private key lives where the dashboard runs
(ADR 0007 decision 3), so this server has nothing to sign with. A
payload that asks it to is refused rather than quietly built unsigned,
which would hand back an image the client believes is flashable. Sending
a *private* key is refused with a message saying why.

### Events

`job_state_changed` carries the whole job record and goes to **every**
connection: a queue is shared information, and a second dashboard tab
should see the first one's build.

`job_output` carries `{"job_id", "offset", "text"}` and goes only to the
connections that called `follow_job` for that job.

**Output may be dropped, and that is designed.** A client that stops
reading must not apply backpressure through the log writer into the
compiler, so a full outbox drops its oldest frame. Every `job_output`
carries the byte offset it starts at, so a client whose offsets jump
calls `follow_job` with its own last offset and gets the gap — instead
of displaying a log with a silent hole in it.

### Logs: history-then-live (ADR 0006 decision 6)

Build output goes to a per-job sidecar file. `follow_job` states the
byte offset the client already has, gets everything after it, and is
switched to the live stream in the same answer. `eof: false` means there
is more history than one answer carries — call again with
`next_offset`. `live: true` means `job_output` events for this job now
arrive on this connection.

The order inside is the whole trick: the follower is registered *first*,
at the log's current length, and the history below that length is read
afterwards. A chunk written while the history is being read arrives as
an event instead of falling between the two steps.

### Artifacts: chunked and hashed (ADR 0006 decision 7)

`download_artifacts` without a `path` answers with the build manifest
and every file it names, each with the SHA-256 **the build computed**.
With a `path` it answers with one base64 chunk carrying its own SHA-256.

Two hashes, two jobs: the per-chunk hash says the transfer worked; the
per-file hash from the manifest says the artifact is the one the build
produced, which is the anti-substitution anchor the dashboard's flash
flow (ADR 0010) needs.

Only paths that are in the index can be named, so path traversal is not
defended against here — it is unreachable.

### REST

| Endpoint | Purpose |
|---|---|
| `GET /health` | liveness, open, says nothing about what this server holds |
| `GET /capabilities` | token-gated negotiation before a job exists (ADR 0006 decision 4): versions, `model_version` range, builder features, architecture, job slots, image tag, workspace |

## Session protocol v2 (skeleton)

The remote-build architecture replaces the one-shot job protocol with a
**session model**: one session = one ephemeral builder container = one
effective build context, the same verb set driven locally by the lib or
remotely through this server. The protocol skeleton is in place on the
same `/ws` endpoint, alongside the v1 commands; the container backend,
context transport, scheduling and metering land behind it in later
blocks.

Verbs, in fast-path order:

| Verb | Payload | Today |
|---|---|---|
| `capabilities` | `{}` | **answers**: protocol version, builder image inventory (placeholder), per-layer patch policy from configuration, quota summary (placeholder) |
| `open-session` | `{"profile", "protocol_version", "context_format", "manifest"}` | **answers**: admission — session id, lease, negotiated versions. A version mismatch is a typed rejection at the door |
| `send-context` | `{"session_id", …}` | typed `session.not-implemented` |
| `extend-context` | `{"session_id", …}` | typed `session.not-implemented` |
| `verify` | `{"session_id"}` | typed `session.not-implemented` |
| `build` | `{"session_id", "mode"}` | typed `session.not-implemented` |
| `get-artifact` | `{"session_id", "invocation_id", "path"}` | typed `session.not-implemented` |
| `attach-session` | `{"session_id"}` | **answers**: the session record and lease (event replay is future work) |
| `close-session` | `{"session_id"}` | **answers**: the closed session record |

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
advertises it per layer so the lib fails fast instead of mid-session.

## What is on disk

A job is a directory, so retention is `rmtree` and restart recovery is a
directory scan.

```
<jobs root>/<job id>/
├── job.json            the record — no credentials, ever
├── device-model.json   the submitted model, 0600, DELETED when the build exits
├── signing.pub         the public key it was built against, deleted likewise
├── log.txt             the log sidecar
└── build/              the builder's --build-dir
    ├── build-manifest.json
    ├── device-model.json   (the builder's own copy, stage 4)
    └── build/…             images and artifacts
```

The job record carries the device name, the board, the versions, the
state and the manifest — never a passcode. The submitted model is
deleted the moment its only consumer exits. The builder's copy inside
the build directory stays, because it is generator output that the
build produced; retention removes it with the rest, and it is why the
trusted-machine instruction at the top of this file is at the top of
this file.

A job that was queued or running when the process stopped comes back as
`interrupted` — not `failed`. The build did not break; the server did,
and a history should be able to say which.

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
  /opt/mcuhome-build-server/bin/pip install -e /root/MCUHome/mcuhome -e .
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
# The workspace is mirrored here; the builder compiles in it.
WorkingDirectory=/root/MCUHome
Environment=MCUHOME_BUILDSERVER_TOKEN_FILE=/etc/mcuhome/build-server.token
Environment=MCUHOME_BUILDSERVER_JOBS_ROOT=/var/lib/mcuhome-build-server/jobs
Environment=MCUHOME_BUILDSERVER_WORKSPACE=/root/MCUHome
# Sixteen cores and 28 GB: the builder's RAM heuristic would pick 13,
# and this machine is a dedicated build server (REMOTE-BUILD.md).
Environment=MCUHOME_BUILDSERVER_BUILD_JOBS=24
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
package expects of it: `/data` for `jobs/`, `/share` mounted so the
token can be published for the dashboard App to find (ADR 0006 decision
8), and the builder image contents in the App image with the west
workspace baked in (ADR 0003).

### Standalone container

The build server *is* the toolchain container (ADR 0003 decision 3):
the builder image with this server installed into it, the west
workspace baked in, and `--jobs-root` on a volume.

## Development

```sh
pytest                       # the whole suite, no real build, ~5 s
ruff check --fix . && ruff format .
```

The suite never compiles anything. `tests/conftest.py` writes a small
`mcuhome`-shaped script — it understands the same options, prints a
manifest on stdout and a log on stderr, and can be told to fail, to hang
or to ignore signals. What is under test is the engine around a process,
not a compiler.

One test in `tests/test_builder.py` runs against the **real** installed
builder and skips with an explanation while the `--model` flag of the
"Status" section above is missing. It is the tripwire for that gap.

The frame vocabulary is kept from drifting apart from the dashboard's by
`tests/test_protocol.py`, which compares this package's envelope
constants against `mcuhome_dashboard.protocol` whenever both are
importable — install the sibling checkout's backend
(`pip install -e ../dashboard/backend`) to run that check; it skips
otherwise.

## Layout

| Module | Role |
|---|---|
| `config.py` | command line, environment, the token rules |
| `server.py` | process entry point; probes the builder, then binds |
| `app.py` | shared state, the app factory, `/health` and `/capabilities` |
| `security.py` | the bearer token, origin check, same-host pairing |
| `protocol.py` | the ADR 0006 frame vocabulary and its validation |
| `errors.py` | the session protocol's error envelope and its append-only code registry |
| `sessions.py` | session protocol v2: the session registry and one handler per verb |
| `ws.py` | the `/ws` endpoint and one function per command |
| `jobs.py` | the queue, the engine, job records, retention |
| `builder.py` | how the `mcuhome` CLI is invoked, and the feature probe |
| `logs.py` | log sidecars and the resumable follow |
| `artifacts.py` | the manifest's file set, chunked and hashed |
