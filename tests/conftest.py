# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures.

**Nothing here fakes a build environment, and that is the point.** The
build server is an orchestrator and is never itself the build
environment (build-container-contract.md §1.2), so there is no builder
subprocess to stand in for: what this suite exercises is the transport,
the bearer token and the session protocol, all of which run without a
toolchain anywhere near them.

The fixtures are correspondingly small — a config with a known token, a
server state, and an aiohttp client over the application it produces.
"""

from __future__ import annotations

import pytest

from mcuhome_buildserver.app import ServerState, create_app
from mcuhome_buildserver.config import Config

TOKEN = "test-token-000000000000000000000000"


@pytest.fixture
def config() -> Config:
    return Config(host="127.0.0.1", port=0, token=TOKEN, pair_file=None)


@pytest.fixture
def state(config: Config) -> ServerState:
    return ServerState(config)


@pytest.fixture
async def client(aiohttp_client, state: ServerState):
    return await aiohttp_client(create_app(state))


def auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}"}


async def call(ws, command_type: str, payload: dict | None = None, frame_id: str = "1") -> dict:
    """Send one command and return the frame that answers it."""
    await ws.send_json({"id": frame_id, "type": command_type, "payload": payload or {}})
    while True:
        frame = await ws.receive_json(timeout=15)
        if frame.get("id") == frame_id:
            return frame
