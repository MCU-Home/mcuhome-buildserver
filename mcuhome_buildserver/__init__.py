# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""MCUHome build server — the fat half of ADR 0003's two-App topology.

A headless aiohttp process that serves the **session protocol**: one
session is one ephemeral build environment and one effective build
context. It is an orchestrator and never itself the build environment
(``build-container-contract.md`` §1.2) — it materializes paths, invokes
the build program and reads its result. It has no user interface, no
configuration tree, no secrets store and no signing key: it knows the
one device it is currently building and nothing else (ADR 0007).

**This is a protocol skeleton.** The verb surface, admission and the
typed error registry are real; the container backend behind them is
not, and every verb that needs it answers ``session.not-implemented``
rather than a guess. See :mod:`mcuhome_buildserver.sessions`.

Module map:

=====================================  ===================================
:mod:`mcuhome_buildserver.config`      runtime configuration (CLI + env)
:mod:`mcuhome_buildserver.server`      process entry point
:mod:`mcuhome_buildserver.app`         application factory, shared state,
                                       ``/health``
:mod:`mcuhome_buildserver.security`    the bearer token and where it comes from
:mod:`mcuhome_buildserver.protocol`    the frame envelope and its codec
:mod:`mcuhome_buildserver.errors`      the session protocol's error envelope
                                       and its append-only code registry
:mod:`mcuhome_buildserver.sessions`    session protocol v2: sessions and verbs
:mod:`mcuhome_buildserver.ws`          the ``/ws`` endpoint and the command loop
=====================================  ===================================
"""

__version__ = "0.1.0.dev0"

__all__ = ["__version__"]
