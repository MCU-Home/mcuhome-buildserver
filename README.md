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

## Status: it builds

The whole protocol surface is real, and since 2026-08-10 so is the
**container backend**. A client can connect, negotiate, open a session,
upload a base context as a `tar.zst`, extend it, lock it, run `verify`
and `build` in a per-session container, watch the invocation's events
and raw log as they happen, download the artifacts as a `tar.zst`, and
close the session — which reaps the container and deletes everything it
held.

No verb answers `session.not-implemented` any more. The code stays in
the registry, because the registry is append-only and a future verb will
want it.

What a build costs before it starts: the image the context pins has to
be **on this host** (this server resolves the digest against the local
docker inventory and pulls nothing), and the SDK package the context
pins has to be in a directory named by `--sdk-source`. Neither is
fetched from the network — build-container contract §9.1 makes external
inputs "the backend's to fetch and to hand over as paths", and ADR 0019
§8 makes the url in a context a hint that is never followed.

Three duties of §9.1 that used to be deferred are now discharged:
`container.digest` is checked against the image actually resolved,
`mcuhome.package.sha256` against the package bytes actually unpacked,
and `target.board` against the pins the session was admitted on — the
last one as part of a full re-measurement of the locked context that
runs before **every** working invocation.

What is deliberately not here: no image is pulled, no registry is
configured, and no cache is ever offered writable. Each is a decision
rather than a gap, and each is argued where it is implemented.

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
| `--allow-patch-layer` | none | allow build-context patches for a layer (`sdk`, `zephyr`, `chip`, `mcuboot`, or an `x-` name); repeatable; unlisted layers are denied |
| `--sdk-source` | none | directory holding `mcuhome-sdk-<version>.tar.zst`; repeatable and searched in order. With none configured, every working action refuses `sdk.unavailable` |
| `--docker` | `docker` | the container runtime to drive |
| `--build-jobs` | `2` | `limits.jobs` for every invocation — authoritative, resolved host-side |
| `--build-deadline-seconds` | `5400` | how long one invocation may run before this server stops it |
| `--cancel-grace-seconds` | `60` | how long a cancelled invocation has to stop itself before the hard path |
| `--max-artifact-bytes` | 256 MiB | egress cap: the size of one artifact this server will serve |
| `--container-memory` | `8g` | `docker run --memory` for the session container; the empty string removes the ceiling |
| `--container-pids` | `4096` | `docker run --pids-limit` for the session container |
| `--container-cpus` | none | `docker run --cpus` for the session container |
| `--ccache-dir` | none | shared compiler cache, offered to every invocation **read-only** |
| `--log-level` | `INFO` | logging verbosity |

`--build-jobs` is authoritative and is resolved here on purpose: "the
container sees the host CPU count but not the RAM budget" (contract
§5.2), so a program that fell back to `nproc` would run several
concurrent sessions at full width and be killed for it. The default is
2 because a Matter build's ceiling is memory rather than cores.

The three `--container-*` limits are the enforcement half of the same
sentence. §1.2's `container` row promises "per-session resource limits"
and §9.1 makes them the backend's to set, and they go on the `run` that
creates the container rather than on the `exec` that uses it — an exec
limit bounds one process tree, and the promise is about the session.
`--container-memory` is also what makes the request document's silence
about `limits.memory_bytes` honest: the value is advisory to the
program, the runtime enforces the real one, so the document does not
state a number nothing behind it keeps. `--container-cpus` is unset by
default because `--build-jobs` already bounds the parallelism a
conforming program asks for.

There is no writable-cache option and there will not be one. §10:
"shared backends MUST offer a shared cache read-only for untrusted
work; cache warming is a deliberate operator invocation with a writable
cache and trusted contexts only" — which is a verb this server does not
have, and an option that made an untrusted build's cache writable would
be the one setting that turns a shared cache into a shared attack
surface.

The per-server limits that ADR 0019 names for v1.0 — maximum concurrent
sessions, session TTL, idle timeout and the compile-lane limit — are
**not configurable yet**: they exist as defaults on `SessionManager`
(`sessions.py`) with no option in front of them. Inventing options for
them now would advertise knobs that do nothing.

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
| `capabilities` | `{}` | **answers**: protocol version, the local build-container inventory (reference, digest and the three §2.1 labels), per-layer patch policy from configuration, session quota, and the **ingress caps** — the five of ADR 0019 decision 8 out of this server's own configuration plus the maximum WebSocket frame, so that a client can size an upload instead of discovering a limit by hitting it (E57) |
| `open-session` | `{"profile", "protocol_version", "context_format"}` | **answers**: admission — session id, lease, negotiated versions, backend profile (`container`). A version mismatch is a typed rejection at the door |
| `send-context` | `{"session_id", "archive": {"size", "sha256"}}` + BINARY frames | **answers**: the pins accepted, the context state and **the serving build container** — its digest, contract version, program id and command set, all out of `describe`. `version.builder-unavailable` if this host has no such image, `context.exists` on a second base context |
| `extend-context` | `{"session_id", "archive"?, "remove"?}` + BINARY frames | **answers**: the context state, the file count and how many named paths were removed. `context.pins-immutable` for `context.yaml`, `context.missing` with no base context, `context.locked` after the lock |
| `lock-context` | `{"session_id"}` | **answers**: `{"context_id"}` and nothing else. `context.missing` with no base context, `context.locked` on a second lock |
| `verify` | `{"session_id"}` | **answers immediately**: `{"invocation_id", "action", "context_id"}`. The outcome arrives as an `invocation.verdict` event. `context.not-locked` before the lock |
| `build` | `{"session_id", "mode"?}` | the same, with `mode` ∈ `clean` (default) \| `incremental`. `context.not-locked` before the lock |
| `cancel` | `{"session_id", "invocation_id"}` | **answers**: the stop signal is set (never "it stopped") — it creates the cancel sentinel the request document named; `already_finished` for a completed invocation, `invocation.unknown` for one this session never ran. The session, its lease and its context are untouched |
| `get-artifact` | `{"session_id", "invocation_id", "path"?}` | **answers**: an announcement (`{"archive": {"size", "sha256"}, "artifacts": […]}`) followed by the `tar.zst` as BINARY frames. One download at a time per connection, because a BINARY frame carries no id. `artifact.unknown` for a path the invocation did not declare, `invocation.unknown` for an id it never ran, `artifact.integrity-mismatch` for a declared artifact that is no longer the file §9.3 verified |
| `attach-session` | `{"session_id", "invocation_id"?, "from_seq"?}` | **answers**: the session record with its context state, the lease and how many events were replayed. The connection re-joins the session's live stream; named an invocation, its events are replayed from `from_seq` **before** the answer |
| `close-session` | `{"session_id"}` | **answers**: the closed session record. Running invocations get the stop signal, the directory is deleted and the container is removed |

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

### One invocation, end to end

`verify` and `build` are the two working actions, and both take the same
path. It is worth reading once, because every step of it is a duty
somebody wrote down.

1. **The state machine.** The session must not be poisoned and its
   context must be locked, or the verb refuses before doing anything.
2. **The context is re-measured.** Every file is re-hashed against the
   `files` list in the `manifest.yaml` this server wrote, and the three
   pins in that manifest are compared against the ones `send-context`
   accepted. A disagreement is `context.integrity-mismatch` naming every
   offending path, and it does **not** poison the session: nothing was
   applied to any tree. Contexts are small, so this runs before every
   invocation rather than once at the lock.
3. **The container, lazily.** On the first working command of a session:
   the image is resolved by digest, `describe` is asked (once per image
   digest per server start, then cached) and cross-checked against the
   §2.1 labels, the SDK package is found by `(version, sha256)` and
   unpacked into the session's own directory, the mounts are composed
   and one container is started. One session is one container is the
   trust boundary.
4. **The per-invocation directory.** `invocations/inv-N/` with an empty
   `out`, an empty `tmp`, an empty `events.ndjson` and the request
   document written atomically — outside the context, which is what lets
   the context be a kernel-enforced read-only mount.
5. **The invocation.** `docker exec … /mcuhome/run <action> <request>`:
   exactly two positional operands, never a flag, an argv that is frozen
   and never grows.
6. **The answer, immediately.** `{"invocation_id"}`. A build is minutes
   to hours, and a command frame that waited for it would make every
   client's socket a build timer.
7. **The streams.** The program's events are relayed from the NDJSON
   file as it appends to them; its merged stdout and stderr travel as
   `log` frames with their own counter.
8. **The verdict.** The result document is read **if it exists,
   regardless of the exit code**, and the invocation is successful
   exactly when all seven conditions of contract §5.3 hold — including
   that every declared artifact exists as a regular file under its
   declared root, re-hashes to its declared value, and that the context
   id the program computed matches the one this server computed. A
   contradiction between exit code and document is answered
   pessimistically **and** raises a contract violation against the
   image, which travels to the client.
9. **`invocation.verdict`**, carrying the status, the artifact list and,
   on a failure, the session protocol's own error envelope.

The invocation is owned by this server and not by the connection that
started it, which is the mechanical half of "connection loss is not
abandonment": a client may drop its socket, and the build keeps going,
keeps writing its events file, and finishes into a record a reattaching
client can still read.

**Liveness** is a ladder, and the sentinel is its first rung because it
is the only one that lets the program write a result document. A cancel
or a passed deadline creates the sentinel; `--cancel-grace-seconds`
later the `docker exec` client gets SIGTERM; ten seconds after that,
SIGKILL. It is worth saying plainly that SIGTERM does not reach the
process inside the container — killing a `docker exec` client never has,
which is exactly why the contract has a cooperative sentinel at all.
What actually reaps a program that ignored both is the container going
away at `close-session`.

**Patched layers cost nothing to make writable.** In the `container`
profile the container's own copy-on-write layer **is** the writable view
§6.2 asks for: the image's trees are writable inside the container by
construction, one session is one container, and the container is
discarded at `close-session` — so a patched `zephyr` cannot outlive the
session that patched it. This server asserts `writable: true` for an
in-image tree at the path `describe` reported and mounts nothing for it.
There is no overlay, no copy and no `docker cp` anywhere in this server.
The one tree that *is* a mount is the SDK, and a patched one is handed
over writable because it was unpacked per session and dies with it.

**The container sees the request document's paths and nothing else.**
The session tree is mounted piece by piece rather than as one writable
root with read-only holes carved out of it, because a hole is only as
good as the order the mounts are given in — and because the SDK, which
lives under the session root and is mounted at the path `describe`
asks for, was writable under its other name for exactly that reason.
Container path equals host path throughout, which is what makes a
stalled build inspectable from the host.

| Host path | In the container | Mode |
|---|---|---|
| `<session>/context` | same | read-only |
| `<session>/work` | same | writable |
| `<session>/invocations` | same | writable |
| `<session>/sdk` | `trees.sdk.path` (`describe`'s, else the host path) | read-only, writable if the `sdk` layer is patched |
| `<ccache>/<program.id>` | same | read-only, and only when `--ccache-dir` is set |

`invocations/` rather than one mount per invocation because bind mounts
are fixed when a container is created and an invocation directory does
not exist yet; the parent is the mount, so every `out`, `tmp`, request
and result created in it later is inside it. What is deliberately *not*
in the table: the upload spool, `staging/`, and `downloads/`, where
`get-artifact` builds the archive it is about to stream.

### Events, logs and replay

Three kinds of unprompted frame, and they are different kinds because
the contract makes them different things.

```jsonc
// a program event, relayed verbatim with this server's addressing added
{"type": "event", "event": "build.image.started",
 "payload": {"event": "build.image.started", "seq": 4, "image": "mcuboot",
             "current": 1, "total": 2,
             "session_id": "s-…", "invocation_id": "inv-1"}}
// one line of the raw log, with its own counter
{"type": "log", "payload": {"session_id": "s-…", "invocation_id": "inv-1",
                            "seq": 812, "line": "-- west build"}}
// this server's verdict on the invocation
{"type": "event", "event": "invocation.verdict",
 "payload": {"session_id": "s-…", "invocation_id": "inv-1", "action": "build",
             "status": "success", "context": "sha256:…",
             "artifacts": [{"root": "out", "path": "firmware.hex",
                            "role": "firmware", "sha256": "…"}],
             "error": null}}
```

**Unknown event names are relayed opaquely** — verbatim, with their
fields intact, never dropped and never rewritten — which is what lets a
third-party program report its own phases under `x-` names through a
server that has never heard of them. Lines over 8192 bytes and lines
that are not JSON objects are discarded and counted, never treated as an
abort.

**Two frames end an invocation, and their names tell them apart.**
`invocation.finished` is the registry event the *program* emits ("once,
immediately before the result document is written"); `invocation.verdict`
is this server's own completion frame, emitted after that document has
been read and judged. Both reach the client, because a relayed event is
never dropped. E46 first gave them one name and left `seq` to separate
them — every program event carries a monotonic counter and this server
invents none — but that made a program's §8 violation readable as this
server's judgement, so E58 renamed the verdict while the session layer
was still unpublished. The contract is frozen and keeps its event name.
Only the verdict carries `artifacts`, `context` and `error`.

The events file stays on disk for the life of the session and **is** the
replay buffer. `attach-session` with an `invocation_id` and a `from_seq`
reads it back; there is no in-memory ring, so there is nothing a long
reconnect can find already evicted. The raw log is not replayable — it
is a raw opaque stream consumers must not parse for machine decisions,
and its counter is what tells a client it missed lines.

### Downloading artifacts

`get-artifact` is the mirror of the upload, and the bytes are a
`tar.zst` in both directions:

```jsonc
→ {"id": "9", "type": "get-artifact", "payload": {
     "session_id": "s-…", "invocation_id": "inv-1", "path": "firmware.hex"}}
← {"id": "9", "type": "result", "payload": {
     "session_id": "s-…", "invocation_id": "inv-1",
     "archive": {"size": 8213, "sha256": "<64 lowercase hex digits>"},
     "artifacts": [{"root": "out", "path": "firmware.hex",
                    "role": "firmware", "sha256": "…"}]}}
← <binary frame> <binary frame> …                     // the tar.zst itself
```

With a `path` the archive holds exactly that declared artifact, without
one it holds all of them under their declared paths. The announced hash
is the **archive's**, computed at egress while the bytes are read off
disk; per-file integrity stays the client's own check against the result
payload it already holds. There is no acknowledgement frame after the
bytes, for the reason the upload needs one and this does not: the
receiving side is the client, and it knows the transfer is complete when
it has taken the announced number of bytes.

What is served is the **intersection of declared and verified**
(contract §9.3). After every invocation `out` is enumerated without
following symlinks; symlinks, hardlinks, devices, FIFOs and sockets are
refused; every declared path is normalized and strictly contained under
its named root, with an unknown root skipped rather than resolved; every
artifact is re-hashed from the bytes on disk against the one legal
spelling of §3.3.1; and a size cap is applied from those bytes, because
an artifact entry declares no size. Files that were not declared are not
served — and not deleted either: they are diagnostic material.

Artifacts live only inside the session. The per-session directory is
deleted at `close-session`, so download happens after the build and
before closing; there is no grace period, because the directory holds a
device's commissioning credentials.

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
  All five are **announced** through `capabilities`, together with the
  frame bound, so that a client refuses an oversized upload before the
  first byte leaves (E57) — announcing is a courtesy and never the
  enforcement, which stays here and stays streaming.
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
`version.*`, `builder.*`, `invocation.*`, `sdk.*`, `artifact.*`; `x-*`
is reserved for third parties). A code,
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

**A build container's own failures reach this envelope through one
explicit table.** The contract deliberately does not freeze that mapping
— its `reason` values classify *invocations*, while this envelope
classifies *protocol operations* — so `errors.REASON_CODES` is this
server's answer and no document's. Three properties hold across every
row. `retryable` is never taken from the program: `error.retryable` is
"the program's promise about its own failure", and relaying it would let
a container forge the server's own value, so it travels in the details
as information instead. The `reason` itself always travels verbatim,
so a client that wants a finer distinction than the code has it. And an
unmapped reason — an `x-` one from a third-party image, or one added to
the registry after the table was written — is handled as its status
class, which is `builder.failed`.

### Backpressure

A client that stops reading must not apply backpressure through the log
reader and from there into a compiler, so a full outbox drops its
**oldest** frame. Program events and log lines go out that way, and both
survive it: the log carries a counter that makes a gap visible, and the
events file on disk is the replay buffer, so `attach-session` can fetch
the gap. Two frames deliberately do **not** drop. `invocation.verdict`
is the one frame a client is waiting on and there is no second way to
learn it — it is this server's judgement and is in no events file,
unlike the program's own `invocation.finished` — and a download's BINARY
frames would not degrade under a drop — they would corrupt, and the
client would find out from a hash that does not match at the end of a
transfer it already paid for.

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

One directory per session, under `--context-root`, named by session id
and created `0o700`:

```
<context-root>/s-<id>/
  context/                 the context, and manifest.yaml written at the lock
  work/                    the session's persistent working area (contract §4)
  sdk/                     the SDK package, unpacked for this session
  invocations/inv-N/       out/  tmp/  request.json  result.json
                           events.ndjson  cancel
  downloads/               a get-artifact archive, while it is being streamed
  staging/  upload.tar     an extension in flight
```

ADR 0019 §2 spells the per-invocation area `/out/<invocation-id>/`. That
is superseded prose rather than a layout to mimic: `out` is one of five
things an invocation needs a directory for, and the contract that came
after names all five.

**Everything under it is deleted at `close-session`**, at lease or idle
expiry, on any refused upload, and when the server shuts down — and the
session's container is removed with it, because the directory *is* the
container's mounts. Artifact download therefore happens inside the
session, after the build and before closing. There is no grace period,
because the directory holds a device's commissioning credentials.

Sessions themselves are in-memory on purpose: a session is bound to one
container on this machine, so unlike a job record it has nothing worth
surviving a restart — a restarted server has no containers, and leases
guarantee clients find out through typed `session.unknown` answers
rather than hangs. A server that is *killed outright* leaves containers
behind, which is what the `org.mcuhome.build-server.session` label on
each of them is for; there is deliberately no startup sweep, for the
same reason the context root is not swept at startup.

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
since an App has no container runtime of its own. **This server does not
implement that profile**: it is a `container`-profile backend and says
so at `open-session`. A `subprocess`-profile backend "serves exactly one
build environment — the one it runs in", which is a different program
from this one.

### Standalone and self-hosted

The primary target (ADR 0019): a machine an operator installs the
service on and reaches over the transport above. It needs a container
runtime, at least one build-container image **already present** on the
host (nothing is pulled), a directory of SDK packages named by
`--sdk-source`, and room under `--context-root` for one session
directory per concurrent session — the context, the SDK unpacked, the
build's working area and its output.

## Development

```sh
pytest                       # the whole suite, no real build
ruff check --fix . && ruff format .
```

**The suite never starts a container and never compiles anything.**
Docker is stubbed at the two impure functions of
`mcuhome_buildserver/container.py`, by an **autouse** fixture: a test
that forgot to ask for the stub would otherwise start a real container
on the machine running the suite, which is the exact failure mode the
reference implementation warns about. The fake is a *conforming
program* by default — it answers `describe` with a complete `program`
block, writes real files into `out`, declares them with the hashes they
actually have and emits the events contract §8 seeds its registry with —
so a test that does not care about the container never has to know what
one looks like, and a test that wants a non-conforming one replaces a
single attribute.

What that leaves under test is exactly what a backend is: the argv it
composes, the request documents it writes, what it makes of the result
documents that come back, and what reaches the client while it happens.

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
| `ingress.py` | the streaming ingress caps and safe extraction, for a context and for an SDK package |
| `contextstore.py` | the per-session directory, `context.yaml`, the freeze, and the re-measurement before every invocation |
| `backend.py` | the container backend: image discovery, the session's container, invocations, liveness and the streams |
| `container.py` | docker, and the one seam every call to it goes through |
| `abi.py` | the invocation ABI: the request document out, the result document back |
| `events.py` | the invocation's NDJSON event stream: relay and replay |
| `artifacts.py` | egress hardening, and the download archive |
| `sdkstore.py` | the SDK package: found by its pin, verified by its hash, unpacked per session |
