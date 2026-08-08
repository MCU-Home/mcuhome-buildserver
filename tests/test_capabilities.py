# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""``/capabilities``, ``/health`` and the bearer token (ADR 0006 decisions 1 and 4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcuhome_buildserver import builder
from mcuhome_buildserver.config import Config, load_config, resolve_token
from mcuhome_buildserver.security import publish_pairing_token, read_token_file
from tests.conftest import TOKEN, auth


async def test_health_is_open_and_says_nothing_secret(client) -> None:
    response = await client.get("/health")
    assert response.status == 200
    body = await response.json()
    assert body["status"] == "ok"
    assert "token" not in str(body).lower()


async def test_capabilities_needs_the_token(client) -> None:
    assert (await client.get("/capabilities")).status == 401
    assert (await client.get("/capabilities", headers={"Authorization": "Bearer no"})).status == 401
    assert (await client.get("/capabilities", headers={"Authorization": TOKEN})).status == 401


async def test_capabilities_answers_what_a_client_negotiates_on(client) -> None:
    response = await client.get("/capabilities", headers=auth())
    assert response.status == 200
    body = await response.json()

    assert body["mcuhome"]["version"] == builder.VERSION
    assert body["model_version"] == {
        "min": builder.MODEL_VERSION_MIN,
        "max": builder.MODEL_VERSION_MAX,
    }
    assert body["jobs"]["slots"] == 1
    assert body["arch"]
    assert set(body["commands"]) == {
        "submit_job",
        "cancel_job",
        "follow_job",
        "download_artifacts",
        "queue_status",
    }
    # This server can never sign; a dashboard that trusted it to would
    # skip its own signing step and hand out unbootable firmware.
    assert body["signing"]["detached_only"] is True
    assert body["builder"]["usable"] is True


async def test_the_token_may_come_in_the_query_for_a_browser(client) -> None:
    # A browser's WebSocket constructor cannot set a header. Everything
    # else should use the header, and the README says why.
    assert (await client.get("/capabilities", params={"token": TOKEN})).status == 200
    assert (await client.get("/capabilities", params={"token": "wrong"})).status == 401


async def test_the_websocket_upgrade_is_gated_too(client) -> None:
    response = await client.get("/ws")
    assert response.status == 401


async def test_an_unusable_builder_is_advertised_rather_than_hidden(
    aiohttp_client, config: Config
) -> None:
    from mcuhome_buildserver.app import ServerState, create_app

    broken = builder.BuilderFeatures(
        present=True,
        model_input=False,
        detached_signing=True,
        json_output=True,
        problem=None,
    )
    state = ServerState(config, features=broken)
    await state.start(probe=False)
    try:
        client = await aiohttp_client(create_app(state))
        body = await (await client.get("/capabilities", headers=auth())).json()
        assert body["builder"]["usable"] is False
        assert body["builder"]["model_input"] is False
    finally:
        await state.stop()


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
        assert config.slots == 1

    def test_the_environment_configures_everything(self, tmp_path: Path) -> None:
        config = load_config(
            [],
            env={
                "MCUHOME_BUILDSERVER_HOST": "127.0.0.1",
                "MCUHOME_BUILDSERVER_PORT": "9000",
                "MCUHOME_BUILDSERVER_TOKEN": "shhh",
                "MCUHOME_BUILDSERVER_JOBS_ROOT": str(tmp_path / "jobs"),
                "MCUHOME_BUILDSERVER_WORKSPACE": str(tmp_path),
                "MCUHOME_BUILDSERVER_SLOTS": "2",
                "MCUHOME_BUILDSERVER_BUILD_JOBS": "24",
                "MCUHOME_BUILDSERVER_KEEP_JOBS": "3",
            },
        )
        assert (config.host, config.port, config.token) == ("127.0.0.1", 9000, "shhh")
        assert config.jobs_root == tmp_path / "jobs"
        assert config.workspace == tmp_path.resolve()
        assert (config.slots, config.build_jobs, config.keep_jobs) == (2, 24, 3)
        assert config.token_generated is False

    def test_the_command_line_beats_the_environment(self) -> None:
        config = load_config(
            ["--port", "1234", "--slots", "1"],
            env={"MCUHOME_BUILDSERVER_PORT": "9000", "MCUHOME_BUILDSERVER_TOKEN": "t"},
        )
        assert config.port == 1234

    def test_no_pair_file_means_no_pair_file(self) -> None:
        assert load_config(["--no-pair-file"], env={}).pair_file is None
        assert load_config([], env={}).pair_file is not None

    def test_a_zero_lane_server_is_refused(self) -> None:
        with pytest.raises(SystemExit):
            load_config(["--slots", "0"], env={})
