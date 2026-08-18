# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(0.x during incubation).

## [Unreleased]

### Changed

- **This server no longer chooses a build environment; it finds the one
  the context pins** — context format **3**, which is the only format it
  accepts. A context names one image with its digest, that digest is part
  of the context's identity, and an image "of the same line" is therefore
  not a substitute for it. The selection that used to happen at
  `send-context` is gone, and with it the reason the freeze had to be
  handed a container: everything `manifest.yaml` states now comes from
  the client's pins or from the files, so two servers handed one context
  write one manifest.
- `send-context` answers `build_environment` — how this host names the
  image it found — in place of the `image`/`tag`/`digest` triple it used
  to answer with. An acknowledgement rather than a decision.
- A context this server does not have the image for is
  `version.builder-unsatisfiable`, with the environments it does have in
  `available`. It still pulls nothing.
- The `subprocess` profile checks the Zephyr line of the **device model**
  against its own, because it is the one profile that cannot honour an
  image pin at all: the host *is* the build environment.
- The three image labels are read under their new names
  (`org.mcuhome.build-environment.*`), imported from `mcuhome-model`
  rather than spelled here — a second copy is how one side starts looking
  for a label the other stopped writing.

### Added

- **A session nobody is attached to is handed to a client that is
  waiting.** Before admission refuses for want of capacity, it releases
  a session that has no live connection naming it, nothing running, and
  has been quiet for `--reconnect-grace-seconds` (default 60) — with its
  build environment and directory. Measured with `--max-sessions 1`: a
  client killed without closing its session held the server for the full
  idle timeout, because connection loss is never abandonment. That rule
  stands; it stops being unconditional. Only under scarcity — with a
  free slot nothing is taken — and only for sessions nobody is driving:
  any command counts as attached, not `attach-session` alone, so a long
  upload on a fresh socket is safe, and a detached build is work rather
  than idleness. Nothing new on the wire and no event: a session with
  nobody attached has nobody to tell, and its client hears
  `session.expired` on its next command with a sentence that says
  another client was waiting.

- **Seat tokens: a busy server hands out turns instead of running a
  lottery.** A client refused for want of capacity now gets a seat token
  and the seconds to wait in the details of `session.limit-exceeded`,
  sends the token back in its next `open-session`, and is either
  admitted — the seat is spent — or told to wait again with the same
  token and a fresh time. Additive on both ends, so no protocol version
  moves. **A freed slot is held for the head of the queue**, which is
  the guarantee the whole thing exists for: without it, whoever happens
  to be dialling in that microsecond wins. The wait grows with the
  position (`--seat-retry-seconds × position`, capped by
  `--seat-retry-max-seconds`), which is what makes the head the fastest
  poller and the reservation affordable — about 3 % idle capacity per
  handover instead of the 17 % a uniform five-minute wait would cost.
  A seat expires at its own appointment plus a minute, so the next one
  moves up and no "give up my seat" verb is needed.

  **The order is never on the wire.** A client learns when to come back
  and nothing else: seats are served in arrival order today, and a later
  version that admits a paying client ahead of a free one would turn a
  published position into a lie. The seconds are relative rather than a
  timestamp — over a wait of minutes the least reliable clock in the
  system is the client's — and the queue's own bookkeeping is monotonic,
  so a time correction cannot reorder it or resurrect an expired seat.

- `session.no-seat`: admission refused **without** issuing a turn, with
  the reason in `details`. A refusal that hands out a seat is a promise
  to serve, and there has to be a way to refuse without making one.
  Today the only reason is `queue-full` (`--max-seats`, default 128,
  which also bounds the queue's memory); the reason that will join it is
  a per-client seat quota, which needs an identity this server does not
  have while one bearer token is one principal. Fairness here is per
  request, not per user.

- `--max-sessions` (`MCUHOME_BUILDSERVER_MAX_SESSIONS`, default 4): the
  concurrent-session cap, which was a constant. It made the `container`
  profile's four simultaneous builds — four containers at
  `--container-memory` each — a number an operator could not lower on a
  machine that cannot feed them, and made the `subprocess` profile's
  "one build environment, therefore one session" unsayable. A
  `subprocess` deployment now sets `1` and that is a configuration, not
  a special case in the code.

- An **end-to-end job**: one real remote build in CI, with nothing faked
  — this server as a process, a real build container, `mcuhome device
  build --build-mode remote` against it, a signed image at the end, and
  eight checks that each print the sentence they prove (`e2e/`). Four
  minutes, because the device it builds is the cheapest one that still
  walks the whole chain. Proven against the defects it exists for: each
  of the four that reached a real build was restored one at a time, and
  each turned the job red.

- `--session-idle-timeout-seconds` (`MCUHOME_BUILDSERVER_SESSION_IDLE_TIMEOUT_SECONDS`):
  how long a session may sit with no command and no running invocation.
  It was a constant, and the lease-versus-time defects above could
  therefore only be reproduced by a build long enough to outlast ten
  minutes of silence — which is a quarter of an hour of runner time per
  attempt. The hard half of the lease stays derived from the build
  deadline: a knob that could contradict the deadline is a knob that can
  end a build that is still running.

### Fixed

- **A session no longer dies under its own build.** The idle half of the
  lease counts absent commands, and a build is one command that then
  runs for minutes: a session compiling away looked idle after ten
  minutes and was reaped mid-compile, and one that finished a
  fifteen-minute build was already past its timeout when its client
  asked for the artifacts. A running invocation is now work, finishing
  one is activity, and a session the sweep does take away tells whoever
  is listening — an `invocation.verdict` carrying `session.expired`,
  instead of a client waiting forever on a socket that stays open.
- **The hard TTL follows the build deadline.** The deadline is the
  operator's and the TTL was a constant below it, so a build allowed
  ninety minutes lived in a session reaped after sixty.

### Changed

- **The container profile mounts every session at the same paths**
  (`/mcuhome/ctx`, `/mcuhome/work`, `/mcuhome/inv/<id>`), so a request
  document no longer names a directory of this server's. Contract §4
  leaves mount points to the backend and §10.1 says why these are worth
  choosing: the compiler cache is keyed on the compile command line,
  into which Zephyr puts three absolute paths, so a session directory in
  a mount target is a session directory in every cache key. A build in
  the container cannot tell this server from a workbench building
  locally. The `subprocess` profile is unchanged — several sessions
  share one filesystem namespace there and cannot all have
  `/mcuhome/work` — and `SessionBackend._inside` is the seam between the
  two.
- The shared compiler cache is **mounted read-only at the path the image
  configures** (`/ccache/cache-shared`) instead of being named in the
  request document. An image that configures ccache itself needs no
  field, and read-only for untrusted work is unchanged (§10).

### Added

- **The `subprocess` backend profile** — the second of the two profiles
  build-container contract §1.2 defines, and the one ADR 0019 names the
  Home Assistant App case. The build environment is the server's own
  filesystem and the program runs as a **child process** instead of
  through `docker exec`. `--backend-profile {container,subprocess}`
  (env `MCUHOME_BUILDSERVER_BACKEND_PROFILE`) picks one for the process,
  the default stays `container`, and `open-session` answers the choice
  in `negotiated.backend_profile` — which is the field that tells a
  client which promises are being made to it.
  - `--program PATH` (env `MCUHOME_BUILDSERVER_PROGRAM`) names the
    executable, invoked as `<program> <action> <request document>` —
    §5.1's frozen argv with nothing in front of it and nothing looked up
    on `PATH`. With none configured it is the installed MCUHome compiler
    through this server's own interpreter, which is the same entry point
    the build container's `/mcuhome/run` execs.
  - The child is started with a **stated** environment rather than an
    inherited one, and the statement is *composed*: `PATH`, `HOME`,
    `USER`/`LOGNAME`, `TMPDIR`, `TZ`, the locale and the `ZEPHYR_*`,
    `ZAP_*` and `CMAKE_*` namespaces — what makes this filesystem a
    build environment — and nothing of this server's own service
    environment, `MCUHOME_BUILDSERVER_TOKEN` above all. Contract §5.1
    says "no environment variable carries information the program
    needs", so nothing conforming can miss what is left out, while a
    copied environment would put the bearer token into
    `/proc/<pid>/environ` of every compiler child and into the raw log
    stream of any build step that prints its environment.
  - **The reduced promises are stated, never silently absent**: no
    network isolation, no per-session resource limits, no trust
    boundary — and, as a consequence of the third, no kernel-enforced
    write protection of `context` (§9.1's "strongest means its profile
    has" is, here, the obligation itself). The `--container-*` limits do
    nothing in this profile and this server says so instead of
    reinterpreting them. `limits.jobs` **is** passed through and stays
    authoritative: it is the only budget this profile has.
  - **One build environment, and it is the one this server runs in**
    (§1.2). The Zephyr line it carries is *discovered from the program*
    — `describe`'s `program.trees.zephyr.version` (§7.1.1), with west's
    leading `v` dropped exactly as the build container's own
    `org.mcuhome.zephyr` label does — and is deliberately not
    configurable. A context requiring another line is
    `version.builder-unsatisfiable` with the required line and the
    served lines in its details, the same code and detail shape the
    container profile answers; a program naming no usable Zephyr version
    (a host with the compiler installed and no west workspace behind it,
    or a third-party program that declares none) is refused at discovery
    with `version.builder-unavailable`, because absence is never read as
    compatible (§2.1.1).
  - With no image to name, `capabilities` answers **one entry per served
    line** (reference `<program id>:<version>`, `digest: null`, the
    `org.mcuhome.contract` and `org.mcuhome.zephyr` labels and
    deliberately no `org.mcuhome.toolchain`), and `manifest.yaml`'s
    `container:` block records the program's id and version with
    `digest: null`.
  - **Writable views**: a patched `sdk` is handed over writable exactly
    as in the container profile, because the SDK is unpacked per session
    and dies with it. Any other patched layer gets **no `trees` entry** —
    this backend constructs no host-side overlay and makes no copy, and
    asserting `writable: true` for a shared persistent tree would leak
    one session's patches into every later build. The `/trees/<layer>`
    pointer still goes into the request's `required` list, so a
    conforming program refuses the context with `unsupported.required`
    (§5.2 rule 2, a parsing refusal that precedes any work) naming that
    pointer in `error.details.required`. A program declaring a *fixed
    path* for `sdk` is refused at discovery
    (`version.builder-unavailable`): there is no mount namespace to give
    concurrent sessions their own view of one path (§4).
  - Cancellation reaches the **program and everything it started**: the
    child is spawned in its own process group and cancel, deadline and
    `close-session` all signal that group, so west, cmake, ninja and the
    compilers cannot survive as orphans on a host that has no
    per-session PID or memory ceiling. In the container profile SIGTERM
    only ever reached the `docker exec` client. `close-session`
    escalates over the group — SIGTERM, a bounded wait, SIGKILL — which
    is this profile's `docker rm --force`.

### Changed

- **`ContainerBackend` now stands on a shared `SessionBackend`**, which
  owns everything contract §9 asks of a backend in *either* profile: the
  per-invocation directories, the request document, the SDK verified
  against its pin, one invocation at a time per `work`, liveness, the
  event and log relay, egress hardening and the verdict. A profile
  supplies five things — `inventory`, `resolve_image`,
  `_session_environment`, `_materialize`, `_start`, `_release_runtime`.
  Behaviour of the container path is unchanged; the refactor is what
  makes "neither shape moves a duty from this list onto the program"
  (§9.1) a property of the code rather than of two transcriptions.
  - `ImageProfile` keeps its container-specific naming and inherits the
    profile-independent half (`ProgramProfile`): `describe`'s block, the
    action set, the tree paths and the `send-context` wire answer.
  - New `processes.py` holds the child-process plumbing both profiles
    start theirs with — the log pump, the line cap, the
    signal-an-exited-process rule, the process group and the bounded
    escalation over it. `container.run_docker` and `spawn_docker` stay
    as this profile's own seam, so a suite that stubs docker out does
    not thereby stub the other profile out. Two properties of the shared
    spawn are new and matter in both profiles: every spawned child is a
    session leader, so a signal addresses the child *and its
    descendants* rather than one pid; and the exit status is answered
    when the child exits rather than when its log pipe closes, so a
    descendant holding the inherited stdout can no longer make an
    invocation unfinishable (the last lines still get a bounded grace,
    and an expired one is logged). The container profile's child is a
    short-lived `docker exec` client with no descendants, so a group of
    one behaves there exactly as the single pid did.

- **Context format 2: the client requires a Zephyr line, this server
  chooses the container** (E61, product owner). A context no longer pins
  a build container by digest — it carries `zephyr: "<line>"`, the
  Zephyr release line its model was resolved against, and this server
  answers it with an image of that line out of the ones it already has.
  What it chose is written into `manifest.yaml` (`container:` with
  `image`, `tag` and `digest`, the last `null` for an image that was
  never pushed) and is hashed nowhere, so two servers serving one line
  with two different images freeze the same bytes to the same context
  ID. The ID now hashes `sdk.sha256`, `target.board` and the file list.
  - `send-context`'s answer keeps its E60 field names with new
    meanings: `pins` loses `container` and gains `zephyr`, and the
    answer's own `container` object is the resolution — `image` and
    `tag` joined it, because a client no longer knows them from having
    sent them.
  - New typed error **`version.builder-unsatisfiable`**: no container
    this server serves carries the required line. `details` name the
    line required and the lines available, which is what lets a client
    act without the operator. `version.builder-unavailable` stays for
    the image-level refusals it always meant.
  - `CONTEXT_FORMAT_MIN`/`MAX` are both `2`. Format 1 is gone rather
    than accepted alongside: nothing was published against it, and
    `mcuhome-model` no longer implements its hashing rule.
  - The pre-invocation re-check compares `zephyr` where it compared
    `container.digest`; the digest left because it is this server's own
    record now, and the line took its place because it is hashed nowhere
    and no other check would notice it moving. `context`, the manifest's
    own format version, is compared alongside it for the same reason.
  - **One session, one build environment.** The image is chosen once, at
    `send-context`, and held: the first `verify`/`build` starts the
    container the frozen `manifest.yaml` names rather than re-running the
    selection, so an image pulled into the host mid-session can never
    build a context whose record says otherwise. An image that has gone
    from the host by then is `version.builder-unavailable` naming it.
  - The freeze and the pre-invocation re-check compare `context.yaml`'s
    `zephyr` against the device model's own `toolchain.zephyr_line`.
    That is the invariant the ID rule rests on — the line is left out of
    the hash because it is provably inside the hashed model — and
    without the check two contexts differing only in their required line
    had one identity.

### Added

- **`capabilities` announces the ingress caps** (E57). The answer gains
  an `ingress` object carrying the five caps of ADR 0019 decision 8 —
  `compressed_bytes`, `decompressed_bytes`, `entries`, `file_bytes`,
  `path_depth` — read from *this server's configuration* rather than
  from constants, because the config is the policy (E44), plus
  `frame_bytes`: the largest WebSocket message the endpoint accepts.
  The caps exist so that a client can refuse an oversized upload before
  the first byte leaves, and a cap it could not see was discoverable
  only by hitting it; the frame bound is the one limit whose overrun is
  a dropped connection rather than a typed refusal, so it has to be
  knowable in advance. `MAX_FRAME_BYTES` moved from `ws` to `protocol`
  for it — the verbs announce it, the endpoint applies it, and the
  endpoint imports the verbs.
- **The container backend — this server builds.** `verify` and `build`
  materialize one container per session, write the request document of
  build-container contract §5.2 into a backend-owned per-invocation
  directory, invoke `/mcuhome/run <action> <request>` over `docker
  exec`, read the result document *if it exists regardless of the exit
  code*, and judge it against all seven conditions of §5.3. Both verbs
  answer `{"invocation_id"}` immediately and the outcome travels as a
  typed `invocation.verdict` event carrying the status and the artifact
  list (E46, E58) — a build is minutes to hours, and a command frame that
  waited for it would make every client's socket a build timer.
  `session.not-implemented` is now raised by nothing.
- **Container selection at `send-context`**, which is where ADR 0019's
  amendment puts discovery: the requirement arrives with the pins, so
  only then does the backend know which container serves the session.
  The context's Zephyr line is answered out of this host's **local**
  docker inventory (nothing is pulled — product-owner decision) by
  matching it against each image's `org.mcuhome.zephyr` label, newest
  release of the line wins; `describe` is asked once per image per
  server start and cached, the §2.1 labels are cross-checked against it,
  and the answer carries the chosen image, its tag and digest, its
  contract version, program identity and command set. A line this host
  does not serve is `version.builder-unsatisfiable`, at the moment the
  pins arrive rather than minutes into a build.
- **Events, logs and replay** (E46). The program's contract §8 events are
  relayed verbatim — unknown names included, "never dropped, never
  rewritten, never treated as an error" — with this server's
  `session_id` and `invocation_id` added; lines over 8192 bytes and
  non-objects are discarded and counted rather than treated as an abort.
  The raw merged log is its own frame kind with its own counter, because
  §8 makes it "one raw, opaque log stream" consumers must not parse. The
  NDJSON file on disk **is** the replay buffer: `attach-session` takes an
  `invocation_id` and a `from_seq` and reads it back, with no in-memory
  ring to find already evicted.
- **`get-artifact`, as a `tar.zst`** (E45): the mirror of E41's upload in
  the other direction. The result frame announces the archive's size and
  SHA-256 and the bytes follow as BINARY frames; with a `path` the
  archive holds exactly that artifact, without one all of them under
  their declared paths. The announced hash is the archive's, computed at
  egress while reading from disk. `artifact.unknown` names the paths the
  invocation did declare.
- **Egress hardening of contract §9.3**, all five duties: `out` is
  enumerated without following symlinks and refuses symlinks, hardlinks,
  devices, FIFOs and sockets; declared paths are normalized and strictly
  contained under a known root; every artifact is re-hashed from the
  bytes on disk against the one legal spelling of §3.3.1; exactly the
  intersection of declared and verified is served, with undeclared files
  neither served nor deleted; and a size cap (`--max-artifact-bytes`) is
  applied from those bytes, because an artifact entry declares no size.
- **The SDK is acquired, verified and unpacked per session** (E48).
  `--sdk-source` names one or more local directories holding
  `mcuhome-sdk-<version>.tar.zst`, searched in order — ADR 0019's
  amendment fixes a local directory as the first tier — and the pin from
  the *locked* context decides: the bytes must hash to
  `mcuhome.package.sha256` or the invocation does not happen. The url in
  a context is a hint and is never fetched. A pin no source holds is the
  new `sdk.unavailable`, naming the version, the hash and every
  directory searched.
- **The pin cross-checks of §9.1 are discharged.** The serving
  container is *selected* to carry the context's Zephyr line rather than
  compared after the fact, `mcuhome.package.sha256` is checked against
  the package bytes actually unpacked, and `target.board` and `zephyr`
  against the pins the session was admitted on — the last two as part of
  a full re-measurement of the locked context that runs before **every**
  working invocation (product-owner decision: contexts are small). A
  disagreement is `context.integrity-mismatch` naming every offending
  path, and it does not poison the session.
- **A liveness ladder, and a real cancel sentinel.** `cancel` and
  `close-session` now create the per-invocation `cancel` file the
  request document named — the seam left in place when E38 landed. The
  server's own deadline (`--build-deadline-seconds`) enters the same
  ladder at the top: sentinel first, because it is the only rung that
  lets the program write a `cancelled` result; SIGTERM at
  `--cancel-grace-seconds`; then SIGKILL. What actually reaps a program
  that ignored both is the container going away at `close-session`.
- **New configuration**: `--docker`, `--sdk-source`, `--build-jobs`
  (default 2 — `limits.jobs` is authoritative and resolved host-side,
  because the container sees the host CPU count but not the RAM budget),
  `--build-deadline-seconds`, `--cancel-grace-seconds`,
  `--max-artifact-bytes` and `--ccache-dir`. The shared cache is offered
  **read-only** with no way to ask otherwise: §10 makes a writable
  shared cache a deliberate operator invocation on trusted contexts, and
  this server has no such verb.
- **Four new error codes and two new layers.**
  `builder.runtime-unavailable` (retryable — no docker binary or a
  daemon that is down, and nothing about the context is wrong),
  `sdk.unavailable`, `artifact.unknown`, and a `reason` → envelope table
  (`errors.REASON_CODES`) covering every value contract §5.4 defines.
  The mapping is the backend's business and deliberately not frozen by
  the contract; `error.retryable` is never relayed as the envelope's
  `retryable`, because that value is the server's "precisely so the
  promise cannot be forged".
- **`capabilities` lists a real inventory**: every local image carrying
  the `org.mcuhome.contract` label, with its reference, repo digest and
  the three §2.1 labels. No container is started to answer it.
- **The context path, end to end**: `send-context` receives a `tar.zst`
  archive announced in its JSON payload and delivered as WebSocket
  BINARY frames, unpacks it into a per-session directory this server
  owns, parses the pins out of `context.yaml` and answers what it
  accepted; `extend-context` does the same for additions and takes a
  `remove` list with it; `lock-context` re-hashes the bytes received,
  computes the context ID **through `mcuhome-model`** and writes
  `manifest.yaml`, then answers `{"context_id"}` and nothing else. The
  wire shape of the two upload verbs is the product owner's decision of
  2026-08-09 (E41/E42) — ADR 0019 §2 spells `send-context(archive)` and
  that one word was the whole specification the verb set gave it.
- **The hardening floor of ADR 0019 decision 8.** Five ingress caps
  enforced while the bytes arrive (compressed size, cumulative
  decompressed size, entry count, per-file size, path depth), counted
  cumulatively across the base context and every extension; safe
  extraction confined to `context.yaml`, `model/`, `keys/` and
  `patches/<layer>/`, refusing absolute paths, `..`, symlinks, hardlinks
  and device nodes; the declared archive hash recomputed from what
  arrived; and a per-session disk quota answered typed instead of by
  host exhaustion. All seven numbers are configuration
  (`--max-compressed-bytes`, `--max-decompressed-bytes`, `--max-entries`,
  `--max-file-bytes`, `--max-path-depth`, `--max-context-yaml-bytes`,
  `--session-quota-bytes`) with the defaults E44 decided, because the ADR
  requires the caps and names no number for any of them — the config is
  the policy.
- **A session reaper**: a periodic sweep closes the sessions whose lease
  or idle timeout ran out and deletes their directories, so "deleted at
  lease expiry" no longer depends on a client coming back to ask. A
  stopping server takes the directories of the sessions it still holds,
  and an expired session no longer occupies an admission slot.
- `--context-root` (default: the XDG state directory), the parent of the
  per-session directories. They are deleted at `close-session`, at lease
  or idle expiry, on any refused upload and at shutdown. The root is
  created `0o700` level by level and refused at startup if any existing
  level up to `/` is owned by somebody else or is world-writable without
  the sticky bit — the no-`HOME` fallback lands in `/tmp`, and the
  directories under it hold a device's commissioning credentials.
- Two error codes: **`context.exists`** for a second base context before
  the lock (E43 — changes go through `extend-context`, a fresh start is
  a new session) and **`context.pins-immutable`** for an extension that
  writes or removes `context.yaml`, which ADR 0018's amendment requires
  to be a typed error without naming a code. It is deliberately distinct
  from `context.unsafe-entry`: that code is about extraction *shape*,
  while a `context.yaml` in an extension is a well-formed entry aimed at
  a forbidden target.
- `mcuboot` joins the patch layers, so all four names build-container
  contract §1.1 defines can be allowed; `--allow-patch-layer` also takes
  a third-party `x-` name now, and those are allowed only where an
  operator listed them.
- The `CONTEXT_ID_VECTORS` conformance suite runs on this side
  (ADR 0020 §4), together with a syntax check that no module in this
  package imports `mcuhome.workbench` or `mcuhome.compiler`.
- The build server, extracted from the
  [dashboard repository](https://github.com/mcu-home/dashboard) into its
  own repository per the remote-build architecture: the WebSocket
  transport with bearer-token authentication, the frame envelope, and
  same-host App pairing. Its pre-extraction history lives in the
  dashboard repository's changelog and git history.
- **Session protocol v2 skeleton**: the session verbs (`capabilities`,
  `open-session`, `send-context`, `extend-context`, `lock-context`,
  `verify`, `build`, `cancel`, `get-artifact`, `attach-session`,
  `close-session`) on the `/ws` endpoint, the fixed error envelope
  `{code, layer, retryable, message, details}`, the append-only typed
  error-code registry (`policy.*`, `session.*`, `context.*`,
  `version.*`, `builder.*`), version negotiation and admission at
  `open-session`, and a per-layer patch policy read from configuration
  (`--allow-patch-layer`, deny by default). Context transport,
  containers and scheduling are stubbed with typed
  `session.not-implemented` errors.
- **`lock-context` and `cancel`**, the two verbs dashboard ADR 0012
  decision 3 gained on 2026-08-09 from ADR 0019's amendment, completing
  the eleven-verb set. Neither was optional: without `lock-context` a
  client can never reach `build`, and without `cancel` a closed socket
  would be the only stop signal a client had — which is no stop signal
  at all, because killing a `docker exec` client does not stop the
  process inside the container.
- **The context state machine**, which is what those two verbs are for.
  A session is admitted on no context, receives one, may extend it any
  number of times, and then freezes it one-way. The session record
  carries `context_state` (`none` | `unlocked` | `locked`), and the two
  new error codes are the boundary: `context.not-locked` for a working
  command (`verify`, `build`) before the lock, `context.locked` for a
  writing command (`send-context`, `extend-context`, a second
  `lock-context`) after it.
- `open-session` now declares the **backend profile** serving the
  session (`negotiated.backend_profile`, `container` | `subprocess`).

### Changed

- **The completion verdict is `invocation.verdict`** (E58). E46 gave
  this server's own completion frame the name contract §8 seeds the
  event registry with, `invocation.finished`, and left the absence of
  `seq` to tell them apart — so a program that violated §8 by omitting
  its counter would have had its own announcement read as this server's
  judgement. The contract is frozen and keeps its event name; the
  session layer is not published yet, so the verdict was renamed while
  renaming still cost nothing. The discrimination is now the name.
  `ws.FINISHED_EVENT` is `ws.VERDICT_EVENT`, and the non-droppable
  guarantee it carries is exact for the first time: the verdict is in no
  events file, while the program's `invocation.finished` is one line of
  the replay buffer `attach-session` serves.
- **No host-side overlay, anywhere** (E47). Contract §6.2's writable view
  of a patched layer costs nothing in the `container` profile: the
  image's trees are writable inside the container by construction, one
  session is one container, and the container is discarded at
  `close-session`. This server asserts `writable: true` for an in-image
  tree at the path `describe` reported and mounts nothing for it; the
  program applies the patches with its own §6.2 machinery. No `docker
  cp`, no volumes, no overlayfs.
- `open-session` answers `backend_profile: "container"` instead of
  `null`. It can never be `subprocess`: that profile "serves exactly one
  build environment — the one it runs in", and this process is an
  orchestrator that is never itself a build environment.
- Three registry summaries were widened (`context.missing`,
  `context.integrity-mismatch`, `version.context-format-unsupported`) so
  that the `reason` table can land on them without a second code per
  row. No code was added and none changed its `retryable`, which is what
  makes the amendment legitimate under the pre-release window.
- The safe-extraction rule of `ingress.py` is now shared by the context
  and the SDK package: one implementation of "regular files and
  directories only", with the context's layout whitelist as the only
  varying part.
- The freeze is no longer a seam: it is wired onto `mcuhome-model` and
  restates none of the rule. Every file hash is `hashes.sha256_file`,
  every integrity entry is a `ContextFile`, the ID is `context_id` and
  the document is `ContextManifest.to_dict()` (ADR 0020 decision 4) —
  the rule is frozen so that both sides of the contract compute the same
  value, and a second implementation here would be two chances to
  disagree about a number whose only job is to be identical. What stays
  a seam is the cancellation signal (`_signal_cancellation`), which
  becomes the per-invocation cancel sentinel file of container contract
  §8 once there is a per-invocation directory to put one in.
- Two dependencies are declared, both for what `mcuhome-model`
  deliberately does not carry: `ruamel.yaml` (it ships the format and
  the hash rule, not a parser, so `context.yaml` and `manifest.yaml`
  need one here — the reference emitter lives in
  `mcuhome.workbench.contextdir`, which this repository may not import)
  and `zstandard` (the archive is `tar.zst`, and a streaming
  decompressor is what lets a cap refuse a bomb mid-expansion).
- `capabilities` answers `containers` instead of `builders`: the build
  environment is the **build container** and the orchestrator is the
  **build server**; "builder" is retired as a term (ADR 0019's
  amendment). The `builder.*` error prefix is a wire value and is
  deliberately *not* renamed with it — its spelling is settled when the
  registry is, before the first release.
- The `context.unsafe-entry` registry **summary** is widened to name a
  file/directory type collision and a name the filesystem cannot hold.
  The code and its `retryable` are untouched, and no new code was added:
  the entry has always meant "extraction refused this target", and a
  path that must be a file and a directory at once is one. Amending a
  summary is only legitimate in the pre-release window the registry
  describes, and nothing here has been published.

### Fixed

An adversarial review of the container backend, answered in full.

- **`get-artifact` re-verifies §9.3 at delivery.** The egress check ran
  when an invocation ended, and the archive was built whenever a client
  asked — arbitrarily later, on a tree that stays writable inside a
  container that outlives the invocation. A `firmware.hex` replaced by a
  symlink in between was *followed* at download time and the target's
  bytes streamed to the client under the declared name. Every member is
  now re-resolved segment by segment, opened `O_NOFOLLOW`, re-checked on
  the descriptor (regular file, one link) and **re-hashed while it is
  packed**; a member that is no longer what was verified is the new
  `artifact.integrity-mismatch` and the delivery is refused rather than
  built around it.
- **The session tree is mounted piece by piece and never wholesale.**
  One bind mount of the session root exposed the SDK writable at
  `<root>/sdk` while it was mounted read-only at the path `describe`
  asked for — so `trees.sdk.writable: false`, which §4.1 makes an
  assertion the program may never probe, was a claim this server made
  falsely. The container now sees exactly what the request document
  names, each at its own host path: `context` read-only, `work` and the
  per-invocation directories writable, the SDK at its target, the shared
  cache read-only. Nothing else of the session tree is visible — not the
  upload spool, not `staging`, and not `downloads`, where `get-artifact`
  builds the archive it is about to stream.
- **The session container is given the resource limits its profile
  promises.** §1.2's `container` row lists "per-session resource limits"
  and nothing was set: no `--memory`, no `--pids-limit`, no `--cpus`.
  All three are configurable now (`--container-memory`, default `8g`;
  `--container-pids`, default `4096`; `--container-cpus`, unset), and
  they are what makes the request document's silence about
  `limits.memory_bytes` honest rather than convenient.
- **A declared artifact this server cannot resolve now fails the build.**
  An entry whose `sha256` was not in §3.3.1's one legal spelling, or
  whose path left §9.2's charset, was silently dropped — so a build
  reported `status: success` with that artifact absent from the delivery
  and no error anywhere, which is the one outcome a client has no way to
  notice. Unresolvable entries (unknown `root`, a missing mandatory key)
  are still skipped as §5.4 requires; a resolvable entry that is wrong
  about itself is a problem and fails §5.3's sixth condition.
- **`layers` is compared against the patch set the backend derived.**
  §5.4 makes the block mandatory "for every patched layer" and states
  the backend's use of it; it was checked for being a dict, so a build
  on a context full of patches that answered `layers: {}` was fully
  successful. Both directions are checked now, including an entry for a
  layer the context does not patch.
- **The outbox's eviction policy asks what it is throwing away.** A log
  line offered while the outbox was full evicted the head of the queue
  whatever it was — including a BINARY chunk of a download in flight,
  the exact corruption `send_bytes` refuses `offer` to avoid. Only log
  and event frames are droppable now; a BINARY chunk, a command's answer
  and `invocation.verdict` never are, and an outbox holding nothing but
  those closes the connection with a close code instead of delivering an
  archive that will not hash.
- **One download at a time per connection, and a spool name per
  request.** Two `get-artifact` commands interleaved their BINARY
  frames, which carry no id for a client to sort them by, and when they
  addressed one invocation they wrote and unlinked the *same* spool
  file — so the announced size and hash and the delivered bytes came
  from different archives.
- **`attach-session` replays before it joins the live stream.** It
  attached first and read the events file afterwards, so live frames
  landed inside the region the verb calls history and an event the relay
  overtook was delivered twice. The replay now drains the file first and
  the connection joins with a boundary `seq` the backend excludes from
  its fan-out to that connection.
- **`close-session` kills the container before it deletes the tree**, and
  no longer promises a result document survives it. The old order set
  the cancel sentinel and deleted the session tree in the same
  synchronous call — the signal existed for the microseconds between two
  statements — and pulled the mount source out from under a program that
  was still running in it.
- **`describe` gets a per-probe directory** instead of one keyed by the
  image id. Nothing serialized two callers, so two sessions pinning one
  image raced over `request.json` and `result.json`, and the loser's
  `result.unlink` disqualified a perfectly good image with "no result
  document was written".
- **`docker image inspect` results are matched back to the reference
  they name** (`RepoTags`, `RepoDigests`, `Id`) rather than to the one
  at their position. A missing image is simply absent from stdout while
  its error text is merged into the same stream, so positional matching
  published one image's digest and labels under another image's name —
  the tag→digest pair a workbench resolves a pin from.
- **The SDK unpack, the egress re-hash and the download archive run off
  the event loop.** All three are multi-hundred-megabyte filesystem
  operations that sat in the path of commands promising to answer
  immediately, and the endpoint's thirty-second heartbeat means a long
  enough stall drops *unrelated* clients' connections.
- **A relative `--context-root` is refused at startup.** Every path in
  the request document descends from it and §5.2 rule 4 makes a
  non-absolute path `unsupported.request`; the same value is a
  `--volume` source, where docker reads a name without a slash as a
  named volume rather than a bind mount.
- **The program's own `error.retryable` is carried in the envelope
  details** as `container_retryable`, under a name that says whose
  promise it is — as `_envelope`'s docstring had claimed while dropping
  it. It is never the envelope's own `retryable`, which stays this
  server's (§5.4.1).
- **`_POISONING` is derived from the reason table** rather than written
  out beside it, so §6.3's `error.work.foreign` cannot fall out of one
  without falling out of the other.

Fifteen of the review's findings were about the *suite* rather than the
server, and every one of them is closed: §7.1.1's four pre-invocation
conformance gates, §7.2's delivery rules and the verified-versus-declared
distinction they turn on, the seven untested rows of §5.4's mandatory
table, the whole `ccache` path (§10), the `describe` argv — the fake now
refuses a request path no `--volume` reaches, so the probe mount is
exercised rather than assumed — `docker exec --user`, the container that
fails to start, `sdkstore`'s decompression cap, the `invocation.verdict`
delivery guarantee, §9.1's per-invocation preparation duties, and three
tests that stayed green with the behaviour they were named for removed.

An adversarial review of the context path, answered in full.

- **`lock-context` now takes the same in-flight guard as the uploads.**
  A lock arriving between an `extend-context`'s announcement and its
  bytes froze *around* the extension: the manifest listed the files
  present at that instant, the extension then applied to the locked
  context, and the session held a file that was in neither
  `manifest.yaml` nor the context ID already answered — with the client's
  own ID comparison agreeing, because the file arrived afterwards and was
  invisible to both sides.
- **`extend-context` is atomic for real.** The whole merge is checked
  against the context before the first removal runs, so a staged path
  that cannot be placed is a typed refusal rather than an
  `internal_error` on a half-applied context. And the merge uses
  `os.replace` rather than `shutil.move`, which re-parented a staged file
  *into* an existing directory of the same name and answered `result`.
- **A file/directory collision is a typed refusal** wherever it appears —
  inside one archive (both orders) and between an extension and the
  context — as is a path component longer than the filesystem accepts,
  which used to surface as `ENAMETOOLONG` inside an `internal_error`.
- **`close-session` racing an upload** answers `session.closed` instead
  of an `internal_error`, and no longer re-creates the per-session
  directory it had just destroyed.
- **`open-session` refuses `context_format: 0` and `profile: ""`**
  instead of reading a falsy value as an absent one and admitting the
  session on the defaults.
- **The negotiated context format is recorded on the session** and is
  what `context.yaml` is measured against — the refusal always claimed
  as much while comparing against this server's newest supported version.
- **The entry-count ledger is charged as members arrive**, like the byte
  counters, instead of only when an unpack succeeds.
- **`extend-context` no longer hashes the whole context** to answer a
  file count; the hashes have one consumer and it is the freeze.
- The bound on `context.yaml` moved into the configuration beside the
  other caps (`--max-context-yaml-bytes`), rather than being a constant
  in the module that enforces it while the README advertised its value.

### Removed

- **The manifest header, and everything that hung on it.** ADR 0019's
  amendment takes `open-session`'s first operand away — admission
  negotiates protocol version, context-format version and profile, and
  the pins arrive with `send-context`, in `context.yaml` — and ADR
  0018's retires the term itself: there is no header separate from
  `context.yaml`. Gone with it: the `manifest` payload key, the
  `manifest_header` field on the session record, and the error code
  `session.manifest-immutable`, whose rule ("`manifest.yaml` is
  immutable for the session's lifetime") the amendment replaced
  outright. `context.locked` and `context.not-locked` are what replace
  it: before the lock there is no manifest to protect, and after it the
  whole context is closed to writes rather than one file.
- `negotiated.container` from the `open-session` response. With no
  context at `open-session` the backend does not yet know which build
  container serves the session, so the serving container's contract
  version and command set are answered by `send-context`.
- `negotiated.cost_class` and `quota.work`. v1.0 is single-tenant and
  ADR 0019's amendment binds work metering and cost classes to the
  hosted phase: there is no work metering and there are no cost classes,
  and every limit is per **server** rather than per user.
- The error codes `builder.command-unsupported` and
  `builder.parameter-unsupported`. Both were defined as "the container
  answered reserved exit code 64/65", and the amendment drops 64 and 65
  by name — they are `EX_USAGE` and `EX_DATAERR`, which foreign runtimes
  emit for ordinary argument errors, so a Go program returning 64 on a
  typo would have been read as "command not supported". The meaning
  lives in the result document's `reason` now; how a backend maps that
  into this envelope is the backend's business, so replacements are
  registered when there is a backend to raise them.

  Removing registry entries at all is possible only because the registry
  is append-only **from its first published entry** and nothing here has
  been published (`0.1.0.dev0`, no release, no client implemented
  against it). That window closes at the first release.
- **The one-shot job protocol of dashboard ADR 0006, dismantled rather
  than migrated** (dashboard ADR 0012 decision 3). Gone: the commands
  `submit_job`, `cancel_job`, `follow_job`, `download_artifacts` and
  `queue_status`; the events `job_state_changed` and `job_output`; the
  job engine, job records and on-disk job directories with their
  retention; log sidecars with resumable follow; chunked and hashed
  artifact download; `GET /capabilities`; and the `mcuhome` builder
  subprocess with its feature probe — a build server is an orchestrator
  and never itself the build environment. With them go the options
  `--jobs-root`, `--workspace`, `--slots`, `--build-jobs`, `--native`,
  `--image`, `--job-timeout`, `--keep-jobs`, `--job-ttl-days` and
  `--builder-command`, and their environment forms.

  Nothing was released with these, and all four MCUHome repositories are
  private, so there is no deprecation path and none is offered.

  **What deliberately survived**, because dashboard ADR 0012 decision 3
  carries it forward: the WebSocket transport and bearer token, TLS at
  the deployment and the leaked-token threat model, same-host pairing,
  the frame envelope and its codec, the connection handling with its
  drop-oldest outbox, and the session protocol v2 skeleton.
- `GET /health` no longer reports a `mcuhome` builder version. There is
  no builder subprocess to name, and the build environments this server
  drives are per-session, so no single version could be named truthfully.
