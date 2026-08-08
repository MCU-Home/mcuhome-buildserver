# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(0.x during incubation).

## [Unreleased]

### Added

- The build server, extracted from the
  [dashboard repository](https://github.com/mcu-home/dashboard) into its
  own repository per the remote-build architecture: the ADR 0006 job
  protocol (`submit_job`, `cancel_job`, `follow_job`,
  `download_artifacts`, `queue_status`), the job engine with compile
  lane 1, log sidecars with resumable follow, chunked and hashed
  artifacts, bearer-token authentication and `GET /capabilities`. Its
  pre-extraction history lives in the dashboard repository's changelog
  and git history.
