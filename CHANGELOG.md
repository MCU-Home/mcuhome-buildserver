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
  `open-session`, `send-context`, `extend-context`, `verify`, `build`,
  `get-artifact`, `attach-session`, `close-session`) on the `/ws`
  endpoint, the fixed error envelope
  `{code, layer, retryable, message, details}`, the append-only typed
  error-code registry (`policy.*`, `session.*`, `context.*`,
  `version.*`, `builder.*`), version negotiation and admission at
  `open-session`, and a per-layer patch policy read from configuration
  (`--allow-patch-layer`, deny by default). Context transport,
  containers, scheduling and metering are stubbed with typed
  `session.not-implemented` errors.

### Removed

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
