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

**Every session builds in a container.** One container per session, no
network, per-session limits, the session as the trust boundary — and
``open-session`` says so in ``negotiated.backend_profile``, because that
answer is what tells a client which promises it is getting. No verb
answers ``session.not-implemented``.

Module map:

==========================================  ===================================
:mod:`mcuhome.buildserver.config`           runtime configuration (CLI + env)
:mod:`mcuhome.buildserver.server`           process entry point
:mod:`mcuhome.buildserver.app`              application factory, shared state,
                                            the backend, ``/health``
:mod:`mcuhome.buildserver.security`         the bearer token and where it comes from
:mod:`mcuhome.buildserver.protocol`         the frame envelope and its codec
:mod:`mcuhome.buildserver.errors`           the session protocol's error envelope
                                            and its append-only code registry
:mod:`mcuhome.buildserver.sessions`         session protocol v2: sessions and verbs
:mod:`mcuhome.buildserver.ws`               the ``/ws`` endpoint and the command loop
:mod:`mcuhome.buildserver.backend`          this server's half of one session's
                                            build: discovery, invocations, egress
:mod:`mcuhome.buildserver.container`        docker, and the one seam to it
:mod:`mcuhome.buildserver.processes`        child processes
==========================================  ===================================
"""

__version__ = "0.1.0.dev0"

__all__ = ["__version__"]
