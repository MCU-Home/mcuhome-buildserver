# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""MCUHome build server — the fat half of ADR 0003's two-App topology.

A headless aiohttp process that takes a resolved ``device-model.json``
over the protocol of ADR 0006, compiles it with the ``mcuhome`` builder,
and hands the artifacts back. It has no user interface, no configuration
tree, no secrets store and no signing key: it knows the one device it is
currently building and nothing else (ADR 0007).

Module map:

=====================================  ===================================
:mod:`mcuhome_buildserver.config`      runtime configuration (CLI + env)
:mod:`mcuhome_buildserver.server`      process entry point
:mod:`mcuhome_buildserver.app`         application factory, shared state,
                                       ``/capabilities`` and ``/health``
:mod:`mcuhome_buildserver.security`    the bearer token and where it comes from
:mod:`mcuhome_buildserver.protocol`    the ADR 0006 frame vocabulary
:mod:`mcuhome_buildserver.ws`          the ``/ws`` endpoint and its commands
:mod:`mcuhome_buildserver.jobs`        the queue, the engine and job records
:mod:`mcuhome_buildserver.builder`     how the ``mcuhome`` CLI is invoked
:mod:`mcuhome_buildserver.logs`        per-job log sidecars, resumable follow
:mod:`mcuhome_buildserver.artifacts`   the manifest's file set, chunked
=====================================  ===================================
"""

__version__ = "0.1.0.dev0"

__all__ = ["__version__"]
