# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Process entry point: bind the socket and serve.

There is nothing to probe before binding any more. The build tool used
to be a subprocess on this machine, examined at startup so that the
log's first line said what this server could do; a build server is now
an orchestrator that never is the build environment itself
(build-container-contract.md §1.2), and what it can build is a
per-session question answered by the ``capabilities`` verb against a
build-container inventory. That inventory lands with the container
backend, and until it does this server admits sessions and builds
nothing — which the ``capabilities`` verb says in as many words by
answering an empty ``containers`` list.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import Sequence

from aiohttp import web

from mcuhome.buildserver import __version__
from mcuhome.buildserver.app import ServerState, create_app
from mcuhome.buildserver.config import Config, load_config
from mcuhome.buildserver.contextstore import UnsafeContextRoot
from mcuhome.buildserver.security import publish_pairing_token

__all__ = ["main", "run", "serve"]

logger = logging.getLogger(__name__)


def _announce(config: Config) -> None:
    logger.info("MCUHome build server %s", __version__)
    logger.info("listening on %s", config.site_summary())
    if config.token_generated:
        # The code-server pattern (ADR 0009 decision 2, borrowed): a
        # fresh container is usable in one step and never open. Printed
        # once, at a level nobody filters out.
        logger.warning(
            "No bearer token was configured, so one was generated for this run:\n\n"
            "    %s\n\n"
            "Set MCUHOME_BUILDSERVER_TOKEN (or --token-file) to keep one across "
            "restarts. A build server on a network must also be behind TLS: a bearer "
            "token on a plaintext connection is a token you have given away.",
            config.token,
        )


async def serve(config: Config, *, ready: asyncio.Event | None = None) -> None:
    """Run until cancelled."""
    state = ServerState(config)
    _announce(config)
    if config.pair_file is not None:
        publish_pairing_token(config.token, config.pair_file)

    runner = web.AppRunner(create_app(state))
    await runner.setup()
    try:
        await web.TCPSite(runner, config.host, config.port).start()
        if ready is not None:
            ready.set()
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


def run(config: Config) -> int:
    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    try:
        asyncio.run(serve(config))
    except UnsafeContextRoot as exc:
        # An operator's mistake about a path, not a crash: the message
        # says which directory and what is wrong with it, and the socket
        # was never bound. A traceback here would bury the one sentence
        # that fixes it.
        logger.error("%s", exc)
        return 2
    except KeyboardInterrupt:  # pragma: no cover - interactive
        logger.info("stopped")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return run(load_config(argv))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
