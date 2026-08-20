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

from mcuhome.buildserver.config import load_config, resolve_token
from mcuhome.buildserver.security import (
    DEFAULT_AUTH_FREE_ATTEMPTS,
    AuthThrottle,
    publish_pairing_token,
    read_token_file,
)
from tests.conftest import TOKEN


async def test_health_is_open_and_says_nothing_secret(client) -> None:
    response = await client.get("/health")
    assert response.status == 200
    body = await response.json()
    # Only that the process is up. Not the token, and — since the version
    # leak was closed — not the version or uptime either: the one pre-auth
    # response is the wrong place to hand an attacker a version to target.
    assert body == {"status": "ok"}
    assert "token" not in str(body).lower()
    assert "version" not in str(body).lower()
    assert "uptime" not in str(body).lower()


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

    def test_the_connection_caps_come_from_cli_and_environment(self) -> None:
        config = load_config(["--max-connections", "3", "--max-inflight-commands", "7"], env={})
        assert (config.max_connections, config.max_inflight_commands) == (3, 7)
        config = load_config(
            [],
            env={
                "MCUHOME_BUILDSERVER_MAX_CONNECTIONS": "9",
                "MCUHOME_BUILDSERVER_MAX_INFLIGHT_COMMANDS": "11",
            },
        )
        assert (config.max_connections, config.max_inflight_commands) == (9, 11)
        # Non-positive is refused, like every other limit here.
        with pytest.raises(SystemExit):
            load_config(["--max-connections", "0"], env={})


# --------------------------------------------------------------------------
# Brute-force resistance for the bearer check
# --------------------------------------------------------------------------


class TestAuthThrottle:
    """The unit rules of the failed-auth backoff, driven on a fake clock.

    The token equals shell and a generated token is infeasible to guess;
    this defends an operator's own weak token against a line-rate grind,
    so it is hardening rather than a boundary. A fake clock lets the
    lockout windows be asserted without sleeping through them.
    """

    def test_it_locks_out_with_growing_backoff_and_clears_on_success(self) -> None:
        now = [100.0]
        throttle = AuthThrottle(
            free_attempts=2, base_delay=1.0, max_delay=10.0, clock=lambda: now[0]
        )
        source = "10.0.0.1"

        # The free attempts are answered without a lockout.
        for _ in range(2):
            assert throttle.retry_after(source) is None
            throttle.record_failure(source)

        # Past them, the source is locked, and the window doubles each round.
        throttle.record_failure(source)
        assert throttle.retry_after(source) == 1.0
        now[0] += 1.0
        assert throttle.retry_after(source) is None
        throttle.record_failure(source)
        assert throttle.retry_after(source) == 2.0

        # A correct token clears the history at once — a legitimate client
        # is never held to an attacker's backoff.
        throttle.record_success(source)
        assert throttle.retry_after(source) is None

    def test_the_backoff_is_capped(self) -> None:
        now = [0.0]
        throttle = AuthThrottle(
            free_attempts=0, base_delay=1.0, max_delay=4.0, clock=lambda: now[0]
        )
        source = "10.0.0.9"
        for _ in range(10):
            throttle.record_failure(source)
            now[0] += throttle.retry_after(source) or 0.0
        # 1, 2, 4, 4, 4 … never past max_delay.
        throttle.record_failure(source)
        assert throttle.retry_after(source) == 4.0

    def test_it_forgets_a_source_after_the_reset_window(self) -> None:
        now = [0.0]
        throttle = AuthThrottle(
            free_attempts=1, base_delay=5.0, reset_after=100.0, clock=lambda: now[0]
        )
        source = "10.0.0.2"
        throttle.record_failure(source)
        throttle.record_failure(source)
        assert throttle.retry_after(source) == 5.0

        # Idle past the reset window: the history is forgotten, so an old
        # mistake does not haunt a client that comes back much later.
        now[0] += 101.0
        assert throttle.retry_after(source) is None

    def test_the_global_backstop_closes_the_gate_for_everyone(self) -> None:
        """Per-source backoff does nothing against a grind that forges a
        fresh source per try, so a conservative global counter is the
        backstop: once too many failures land across all sources, even a
        brand-new source is turned away."""
        now = [0.0]
        throttle = AuthThrottle(
            free_attempts=100, global_threshold=5, global_lock=30.0, clock=lambda: now[0]
        )
        for index in range(6):
            source = f"10.0.0.{index}"
            assert throttle.retry_after(source) is None  # per-source never fires here
            throttle.record_failure(source)
        assert throttle.retry_after("10.0.0.250") == 30.0

    def test_the_source_table_is_bounded(self) -> None:
        now = [0.0]
        throttle = AuthThrottle(
            free_attempts=100, global_threshold=10**9, max_tracked=4, clock=lambda: now[0]
        )
        for index in range(50):
            now[0] += 1.0
            throttle.record_failure(f"10.0.0.{index}")
        assert len(throttle._by_source) <= 4


async def test_repeated_failed_tokens_are_locked_out_with_a_retry_after(client) -> None:
    """The bearer gate is not brute-forceable at line rate.

    After the free attempts, a source that keeps presenting a wrong token
    is answered ``429`` with ``Retry-After`` instead of a plain ``401``,
    so the token cannot be ground down. The default clock is real, but no
    sleep is needed: the lockout appears the moment the threshold is
    crossed.
    """
    bad = {"Authorization": "Bearer wrong"}
    # The free attempts, and the one that arms the lock, are answered 401:
    # the gate checks the lockout before it records the failure, so the
    # arming failure is itself still a plain 401.
    for _ in range(DEFAULT_AUTH_FREE_ATTEMPTS + 1):
        assert (await client.get("/ws", headers=bad)).status == 401

    # From here the source is locked out: 429 with a Retry-After.
    response = await client.get("/ws", headers=bad)
    assert response.status == 429
    assert int(response.headers["Retry-After"]) >= 1
