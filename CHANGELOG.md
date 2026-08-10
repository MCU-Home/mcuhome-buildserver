# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(0.x during incubation).

## [Unreleased]

### Added

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
  session (`negotiated.backend_profile`, `container` | `subprocess`,
  `null` until this server has a backend).

### Changed

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
