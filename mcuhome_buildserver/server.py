# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Process entry point: probe the builder, bind the socket, serve.

The startup order is deliberate. The builder is probed **before** the
socket is bound, so that the first thing in the log is what this server
can actually do, and ``/capabilities`` never answers with a guess. A
build server that cannot build still starts — refusing to would take
away the one endpoint that explains why — but it says so loudly and
refuses jobs with the reason rather than accepting them and failing.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import Sequence

from aiohttp import web

from mcuhome_buildserver import __version__, builder
from mcuhome_buildserver.app import ServerState, create_app
from mcuhome_buildserver.config import Config, load_config
from mcuhome_buildserver.security import publish_pairing_token

__all__ = ["main", "run", "serve"]

logger = logging.getLogger(__name__)


def _announce(config: Config, state: ServerState) -> None:
    logger.info(
        "MCUHome build server %s (builder mcuhome %s, device-model %d-%d)",
        __version__,
        builder.VERSION,
        builder.MODEL_VERSION_MIN,
        builder.MODEL_VERSION_MAX,
    )
    logger.info("listening on %s", config.site_summary())
    logger.info("jobs in %s, %d compile lane(s)", config.jobs_root, config.slots)
    logger.info("workspace: %s", config.workspace or "discovered by the builder at build time")
    logger.info(
        "builds run %s",
        "on this machine's own toolchain (--native)"
        if config.native
        else f"in the builder container ({config.image or 'the builder default image'})",
    )
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
    features = state.features or state.engine.features
    if not features.usable:
        logger.error("%s", features.refusal())
        logger.error(
            "This server will start, answer /capabilities and refuse every job with "
            "the reason above."
        )


async def serve(config: Config, *, ready: asyncio.Event | None = None) -> None:
    """Run until cancelled."""
    state = ServerState(config)
    await state.start()
    _announce(config, state)
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
        await state.stop()


def run(config: Config) -> int:
    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    try:
        asyncio.run(serve(config))
    except KeyboardInterrupt:  # pragma: no cover - interactive
        logger.info("stopped")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return run(load_config(argv))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
