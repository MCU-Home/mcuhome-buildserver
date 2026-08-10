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

## Status: the context path is real; it still cannot build

What is real is the **protocol surface and the whole context path**: the
transport, the bearer token, the frame envelope, session admission with
version negotiation, the lease bookkeeping, the context state machine
with its typed refusals, the per-layer patch policy, the typed error
registry — and, since 2026-08-10, receiving a context, extending it and
freezing it. A client can connect, negotiate, open a session, upload a
base context as a `tar.zst`, add to it and remove from it, lock it, get
the context ID back, and close the session.

What is not here is **the container backend** — the overlay patch views,
invoking the build program, progress streaming, artifact retrieval and
scheduling. Every verb that needs it answers a typed
`session.not-implemented` instead of a guess, so a client sees a
protocol that is honest about its state rather than one that almost
works.

One stub is a **seam** rather than a bare refusal: **the cancellation
signal** behind `cancel`. What it becomes is fixed by the container
contract §8 — the backend creates the per-invocation cancel sentinel
file, whose *existence* means "stop" — and there is no per-invocation
directory to put one in until there is a backend. The bookkeeping around
it is real.

Two things the context path does that the documents require and this
server cannot yet do, named here rather than left to be discovered:
build-container contract §9.1 requires the backend to check
`container.digest` against the image it **actually pulled** and
`mcuhome.package.sha256` against the package bytes it **actually
fetched**. This server pulls and fetches nothing, so it checks the
*spelling* of both (§3.3.1, refused and never normalized) and defers the
comparison to the backend that will have something to compare against.
For the same reason no `version.builder-unavailable` is raised: the
container inventory is an empty placeholder, and refusing every context
against it would be a false refusal rather than a strict one.

The one-shot job protocol that used to live here — `submit_job`,
`cancel_job`, `follow_job`, `download_artifacts`, `queue_status`, the
job directory on disk, the `mcuhome` build-tool subprocess and
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

The session protocol is the whole vocabulary of this endpoint. Eleven
verbs, the complete set of dashboard ADR 0012 decision 3.

| Verb | Payload | Today |
|---|---|---|
| `capabilities` | `{}` | **answers**: protocol version, build-container inventory (empty until the backend exists), per-layer patch policy from configuration, session quota |
| `open-session` | `{"profile", "protocol_version", "context_format"}` | **answers**: admission — session id, lease, negotiated versions, backend profile. A version mismatch is a typed rejection at the door |
| `send-context` | `{"session_id", "archive": {"size", "sha256"}}` + BINARY frames | **answers**: the pins accepted and the context state. `context.exists` on a second base context, `context.locked` after the lock |
| `extend-context` | `{"session_id", "archive"?, "remove"?}` + BINARY frames | **answers**: the context state, the file count and how many named paths were removed. `context.pins-immutable` for `context.yaml`, `context.missing` with no base context, `context.locked` after the lock |
| `lock-context` | `{"session_id"}` | **answers**: `{"context_id"}` and nothing else. `context.missing` with no base context, `context.locked` on a second lock |
| `verify` | `{"session_id"}` | `context.not-locked` before the lock; typed `session.not-implemented` after it |
| `build` | `{"session_id", "mode"}` | `context.not-locked` before the lock; typed `session.not-implemented` after it |
| `cancel` | `{"session_id", "invocation_id"}` | **answers**: the stop signal is set (never "it stopped"); `already_finished` for a completed invocation, `invocation.unknown` for one this session never ran. The session, its lease and its context are untouched |
| `get-artifact` | `{"session_id", "invocation_id", "path"}` | typed `session.not-implemented` |
| `attach-session` | `{"session_id"}` | **answers**: the session record with its context state, and the lease (event replay is future work) |
| `close-session` | `{"session_id"}` | **answers**: the closed session record |

An unknown verb is answered with `version.verb-unknown`, whose details
name the verbs this server does have.

`capabilities` is the pre-session query: it lets a client choose a build
container during pin resolution rather than discover the mismatch from
inside one. It is token-gated like everything else on `/ws`, because
what it names — build-container images, patch policy, quota — is an
inventory of the machine.

### The context has its own lifetime, and `lock-context` ends it

A session and the context it builds do not begin and end together, and
the verb set says where the boundary is (ADR 0019 §2):

```
open-session       session id, lease, version negotiation (no context yet)
send-context       base context incl. the pins; the container can be created
extend-context     repeatable; MUST NOT touch the pin file
[read-only commands permitted]
lock-context       freezes the context, writes manifest.yaml, computes and
                   returns the context id; unlocks the writing commands
verify / build     only from here
get-artifact
close-session
```

The freeze is an explicit verb rather than an implicit one on "the first
writing command", because an implicit freeze needs an enumerated list of
writing commands kept in sync with a verb set that is append-only by
decision — and a third-party command could not know which side of the
line it falls on. Making it a verb buys three things: the context ID
gets an **observable moment**, at which both sides compare values they
computed independently; `verify` gets a stable `files` list to check
against, without which it returned "not in the integrity list" for every
extension; and the two states get clean typed errors instead of a
command that quietly means something different depending on what ran
before it.

- **`context.not-locked`** — a working command (`verify`, `build`)
  before the lock. Nothing else in the flow carries the "only from here"
  qualification, so `get-artifact` and `cancel` are not gated on it:
  both address an invocation a build produced, and the refusal for an
  invocation id that does not exist is not specified anywhere.
- **`context.locked`** — a writing command (`send-context`,
  `extend-context`, a second `lock-context`) after it. The lock is
  one-way: adding a patch after a `verify` is a new session, not an
  extension.

The session record carries `context_state` (`none` | `unlocked` |
`locked`) so that a client returning through `attach-session` learns
whether it still has to lock. What is immutable for the session is
`context.yaml`, which carries the pins; `manifest.yaml` is written by
this server at the lock and never arrives from a client.

`cancel(invocation_id)` aborts one invocation and **the session and its
warm container survive it**. It exists because a closed socket is not a
stop signal: killing a `docker exec` client does not stop the process
inside the container, so a backend that merely drops the connection
leaves the compile running and the resources held. It is the deliberate
counterpart to `attach-session` — connection loss is never abandonment,
and the idle timeout counts absent *commands* rather than absent
connections, so cancellation has to be something a client says.

### Sending a context

`send-context` and `extend-context` carry their archive **out of band**:
the verb's JSON payload announces it, the bytes follow as WebSocket
BINARY frames, and the verb's own result frame is the acknowledgement.

```jsonc
→ {"id": "3", "type": "send-context", "payload": {
     "session_id": "s-…",
     "archive": {"size": 4711, "sha256": "<64 lowercase hex digits>"}}}
→ <binary frame> <binary frame> …                     // the tar.zst itself
← {"id": "3", "type": "result", "payload": {
     "session_id": "s-…",
     "context": {"state": "unlocked", "format": 1},
     "pins": {"mcuhome": {…}, "container": {…}, "target": {…}}}}
```

ADR 0019 §2 spells the verb `send-context(archive)`, and that one word
is the whole wire specification the verb set gives it; everything above
is the product owner's decision of 2026-08-09. The format is **tar.zst**
and is not negotiated — one format, chosen for family consistency with
the SDK package the same contract pins. Binary frames are accepted
**only while an upload is announced**; outside one this endpoint still
speaks JSON text frames only. One upload at a time per connection,
because a binary frame carries no id and can only belong to the upload
that is running.

`extend-context` takes the same archive for its add/overwrite half plus
an optional `"remove": [...]` of context paths, and both may travel in
one call; removals are applied first, so a path named in both ends up as
the archive's version. Removing a path that is not there is not an
error — the client asked for a state and that state holds — and the
answer says how many of the named paths existed. Neither half may touch
`context.yaml`: it carries the pins the session was admitted on, and
changing them is a new session rather than an extension
(`context.pins-immutable`).

`lock-context` takes `session_id` and nothing else and answers
`{"context_id": "sha256:…"}` and nothing else. The comparison ADR 0019
requires — both sides comparing values they computed independently —
therefore happens **on the client**: the workbench computes the ID from
the bytes it sent and closes the session on a disagreement. This server
never sees the client's value, so it can never raise that mismatch.

### The hardening floor

ADR 0019 decision 8, and it is identity-independent: single-tenancy
reduces none of it.

- **Five ingress caps, enforced streaming** — compressed size,
  cumulative decompressed size, entry count, per-file size, path depth.
  All five are configuration (`--max-compressed-bytes` and friends,
  defaults 64 MiB / 256 MiB / 4096 / 64 MiB / 16), because the ADR
  requires the caps and names no number for any of them. The first three
  count **cumulatively across the base context and every extension**: a
  per-archive cap would bound nothing, since `extend-context` repeats.
  A violation is `policy.ingress-limit-exceeded`.
  The 8 MiB WebSocket `max_msg_size` is a cap on a *frame* and is
  deliberately not this: a limit that only fires after the bytes arrived
  is not a limit. A decompression bomb is refused after at most one
  128 KiB output chunk over the budget.
- **Safe extraction** — regular files and directories only; absolute
  paths, `..`, symlinks, hardlinks and device nodes refused
  (`context.unsafe-entry`), and so are a name longer than the filesystem
  can hold and a path claimed as a file and a directory at once — in one
  archive or between an extension and the context it lands in. Writes
  are confined to `context.yaml` at the root plus `model/`, `keys/` and
  `patches/<layer>/`, inside a per-session directory this server owns.
  `manifest.yaml` is written here at the lock and is never an extraction
  target. The archive's own mode bits are discarded.
- **Never trust client-declared hashes** — the declared archive hash is
  recomputed from the bytes that arrived (`context.integrity-mismatch`),
  and every context file is re-hashed at the lock. `context.yaml` is
  re-measured against what `send-context` accepted, because the pins are
  three of the four hashed inputs and the document that declares them is
  outside the integrity list by construction.
- **Per-session disk quota** — `--session-quota-bytes`, default 2 GiB,
  answered `policy.quota-exceeded` rather than by the host running out
  of room.
- **`context.yaml` is parsed defensively** — bounded before it is parsed
  at all (`--max-context-yaml-bytes`, default 64 KiB: a YAML parser is
  the one place here where a small input buys unbounded work),
  safe-loaded so no tag can construct an object, and refused for
  duplicate keys and for anchors. It is measured against the context
  format the session was **admitted on**, never against whatever this
  server's newest supported version happens to be.

The per-session directory lives under `--context-root` (default: the
XDG state directory) and is deleted at `close-session`, at lease or idle
expiry, on any refused upload, and when the server shuts down. Expiry is
a **periodic sweep** rather than something a client has to ask for: a
client that crashes or simply closes its socket must not be able to
leave a device's commissioning credentials on disk, or hold an admission
slot, until somebody restarts the process. The one case that does leave
a directory behind is a server killed outright, and it is deliberately
not answered by sweeping `--context-root` at startup — two servers
sharing one root is a misconfiguration, and a startup sweep would answer
it by deleting the other's live sessions.

The root itself is checked before the server serves out of it: every
level it creates is created `0o700`, and every existing level up to `/`
must be owned by this server or by root and must not be world-writable
without the sticky bit. The default falls back to `/tmp` when a service
manager gives the process no `HOME`, and a fixed name in a directory
every local user can write to is a directory somebody else can own.

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
Append-only starts at the first *published* entry, and nothing here is
published yet — which is the only reason two stale codes could be taken
out rather than left to age (see the changelog). The `builder.*` prefix
is a wire value and is deliberately not renamed by the terminology
change; its spelling is settled when the registry is, before the first
release.

Patch policy is configuration (`--allow-patch-layer`, deny by default):
the server's patch configuration **is** the policy, and `capabilities`
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
also report the version of the `mcuhome` build tool this server spawned;
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
