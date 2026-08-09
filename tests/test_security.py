# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""``/health`` and the bearer token.

The transport half of dashboard ADR 0006 — WebSocket plus a bearer
token, TLS at the deployment, the leaked-token threat model, same-host
pairing — is carried forward unchanged by dashboard ADR 0012 decision 3.
Its ``GET /capabilities`` endpoint is not: the session protocol's
``capabilities`` verb replaced it, so the assertions that used that
endpoint merely as *a gated path* now use ``/ws``, which is the only
one left.
"""

from __future__ import annotations

from pathlib import Path

import aiohttp
import pytest

from mcuhome_buildserver.config import load_config, resolve_token
from mcuhome_buildserver.security import publish_pairing_token, read_token_file
from tests.conftest import TOKEN


async def test_health_is_open_and_says_nothing_secret(client) -> None:
    response = await client.get("/health")
    assert response.status == 200
    body = await response.json()
    assert body["status"] == "ok"
    assert "token" not in str(body).lower()


async def test_a_missing_or_malformed_token_is_refused(client) -> None:
    assert (await client.get("/ws")).status == 401
    assert (await client.get("/ws", headers={"Authorization": "Bearer no"})).status == 401
    # A bare token with no `Bearer` scheme is not a credential.
    assert (await client.get("/ws", headers={"Authorization": TOKEN})).status == 401


async def test_the_token_may_come_in_the_query_for_a_browser(client) -> None:
    # A browser's WebSocket constructor cannot set a header. Everything
    # else should use the header, and the README says why.
    async with client.ws_connect("/ws", params={"token": TOKEN}) as ws:
        assert not ws.closed

    with pytest.raises(aiohttp.WSServerHandshakeError) as excinfo:
        await client.ws_connect("/ws", params={"token": "wrong"})
    assert excinfo.value.status == 401


async def test_the_websocket_upgrade_is_gated_too(client) -> None:
    response = await client.get("/ws")
    assert response.status == 401


class TestTokenResolution:
    def test_the_command_line_wins(self, tmp_path: Path) -> None:
        path = tmp_path / "token"
        path.write_text("from-file\n", encoding="utf-8")
        token, generated = resolve_token("from-cli", path, {"MCUHOME_BUILDSERVER_TOKEN": "env"})
        assert (token, generated) == ("from-cli", False)

    def test_then_the_environment_then_the_file(self, tmp_path: Path) -> None:
        path = tmp_path / "token"
        path.write_text("from-file\n", encoding="utf-8")
        assert resolve_token(None, path, {"MCUHOME_BUILDSERVER_TOKEN": "env"})[0] == "env"
        assert resolve_token(None, path, {})[0] == "from-file"

    def test_none_configured_generates_one(self) -> None:
        token, generated = resolve_token(None, None, {})
        assert generated is True
        assert len(token) >= 32
        # There is no configuration in which the server runs without one.
        assert resolve_token(None, None, {})[0] != token

    def test_a_missing_token_file_is_not_a_crash(self, tmp_path: Path) -> None:
        assert read_token_file(tmp_path / "nope") is None


class TestPairing:
    def test_the_token_is_published_where_the_pair_looks(self, tmp_path: Path) -> None:
        share = tmp_path / "share" / "mcuhome"
        share.mkdir(parents=True)
        target = share / "build-server.token"

        assert publish_pairing_token("abc", target) is True
        assert read_token_file(target) == "abc"
        assert target.stat().st_mode & 0o077 == 0

    def test_no_share_directory_means_no_pair_and_no_litter(self, tmp_path: Path) -> None:
        target = tmp_path / "share" / "mcuhome" / "build-server.token"
        assert publish_pairing_token("abc", target) is False
        assert not target.parent.exists()


class TestConfig:
    def test_defaults_bind_a_network_interface_with_a_token(self) -> None:
        config = load_config([], env={})
        assert config.host == "0.0.0.0"  # noqa: S104 - the point of the assertion
        assert config.token
        assert config.token_generated is True

    def test_the_environment_configures_everything(self) -> None:
        config = load_config(
            [],
            env={
                "MCUHOME_BUILDSERVER_HOST": "127.0.0.1",
                "MCUHOME_BUILDSERVER_PORT": "9000",
                "MCUHOME_BUILDSERVER_TOKEN": "shhh",
                "MCUHOME_BUILDSERVER_ALLOWED_ORIGINS": "https://ha.local, https://nas.local",
                "MCUHOME_BUILDSERVER_LOG_LEVEL": "DEBUG",
            },
        )
        assert (config.host, config.port, config.token) == ("127.0.0.1", 9000, "shhh")
        assert config.allowed_origins == ("https://ha.local", "https://nas.local")
        assert config.log_level == "DEBUG"
        assert config.token_generated is False

    def test_the_command_line_beats_the_environment(self) -> None:
        config = load_config(
            ["--port", "1234", "--log-level", "DEBUG"],
            env={
                "MCUHOME_BUILDSERVER_PORT": "9000",
                "MCUHOME_BUILDSERVER_TOKEN": "t",
                "MCUHOME_BUILDSERVER_LOG_LEVEL": "ERROR",
            },
        )
        assert (config.port, config.log_level) == (1234, "DEBUG")

    def test_no_pair_file_means_no_pair_file(self) -> None:
        assert load_config(["--no-pair-file"], env={}).pair_file is None
        assert load_config([], env={}).pair_file is not None
