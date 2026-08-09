# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(0.x during incubation).

## [Unreleased]

### Added

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

- The two things behind the new verbs are **explicit seams** rather than
  code: the freeze (`_freeze_context`) and the cancellation signal
  (`_signal_cancellation`) in `sessions.py`. Writing `manifest.yaml` and
  computing the context ID belong to `mcuhome-model` (ADR 0020 decision
  4) and are deliberately **not** re-implemented here — the ID rule is
  frozen so that both sides of the contract compute the same value, and
  a second implementation with no conformance vectors between them is
  two chances to disagree about it. The cancellation signal becomes the
  per-invocation cancel sentinel file of container contract §8.
- `capabilities` answers `containers` instead of `builders`: the build
  environment is the **build container** and the orchestrator is the
  **build server**; "builder" is retired as a term (ADR 0019's
  amendment). The `builder.*` error prefix is a wire value and is
  deliberately *not* renamed with it — its spelling is settled when the
  registry is, before the first release.

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
