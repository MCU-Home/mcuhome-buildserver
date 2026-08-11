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

**Both backend profiles of §1.2 are real.** ``container`` starts one
container per session and invokes the program in it; ``subprocess`` runs
the program as a child process in this server's own filesystem, with the
reduced promises §1.2 names. The operator picks one
(``--backend-profile``) and ``open-session`` tells the client which it
got. No verb answers ``session.not-implemented``.

Module map:

==========================================  ===================================
:mod:`mcuhome_buildserver.config`           runtime configuration (CLI + env)
:mod:`mcuhome_buildserver.server`           process entry point
:mod:`mcuhome_buildserver.app`              application factory, shared state,
                                            backend selection, ``/health``
:mod:`mcuhome_buildserver.security`         the bearer token and where it comes from
:mod:`mcuhome_buildserver.protocol`         the frame envelope and its codec
:mod:`mcuhome_buildserver.errors`           the session protocol's error envelope
                                            and its append-only code registry
:mod:`mcuhome_buildserver.sessions`         session protocol v2: sessions and verbs
:mod:`mcuhome_buildserver.ws`               the ``/ws`` endpoint and the command loop
:mod:`mcuhome_buildserver.backend`          the backend seam both profiles share,
                                            and the ``container`` profile on it
:mod:`mcuhome_buildserver.subprocessbackend` the ``subprocess`` profile
:mod:`mcuhome_buildserver.container`        docker, and the one seam to it
:mod:`mcuhome_buildserver.program`          the program of the ``subprocess``
                                            profile, and the one seam to it
:mod:`mcuhome_buildserver.processes`        child processes, for both profiles
==========================================  ===================================
"""

__version__ = "0.1.0.dev0"

__all__ = ["__version__"]
