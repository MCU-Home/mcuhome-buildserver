# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Session protocol v2: the envelope, the registry, and the verb skeleton."""

from __future__ import annotations

import pytest

from mcuhome_buildserver import errors, sessions
from mcuhome_buildserver.errors import LAYERS, REGISTRY, SessionError, envelope
from tests.conftest import auth, call

# --------------------------------------------------------------------------
# The error envelope and its registry
# --------------------------------------------------------------------------


def test_the_envelope_is_the_fixed_five_field_shape() -> None:
    made = envelope("session.unknown", "no such session", session_id="s-1")
    assert made == {
        "code": "session.unknown",
        "layer": "session",
        "retryable": False,
        "message": "no such session",
        "details": {"session_id": "s-1"},
    }
    # No details is an empty object, not a missing key: the envelope is
    # fixed, and a client never probes for fields.
    assert envelope("session.unknown", "x")["details"] == {}


def test_every_registered_code_is_dotted_and_in_a_known_layer() -> None:
    assert REGISTRY, "the registry must be seeded"
    for code, entry in REGISTRY.items():
        assert code == entry.code
        layer, dot, rest = code.partition(".")
        assert dot and rest, code
        assert layer in LAYERS, code
        assert entry.layer == layer
        assert isinstance(entry.retryable, bool)
        assert entry.summary


def test_every_concept_namespace_is_seeded() -> None:
    # The registry is append-only; this asserts the seed covers every
    # namespace the concept names, so growth has a place to go.
    assert {code.partition(".")[0] for code in REGISTRY} == set(LAYERS)


def test_retryable_is_authoritative_not_inferred() -> None:
    # A spot check per intent: quota exhaustion is worth retrying,
    # a version mismatch never is.
    assert REGISTRY["policy.quota-exceeded"].retryable is True
    assert REGISTRY["version.protocol-mismatch"].retryable is False


def test_an_unregistered_code_is_a_bug_and_raises() -> None:
    with pytest.raises(ValueError):
        envelope("session.invented-just-now", "nope")
    with pytest.raises(ValueError):
        SessionError("not-even-dotted", "nope")


def test_a_session_error_carries_its_envelope() -> None:
    error = SessionError("version.protocol-mismatch", "too new", server=2, client=3)
    assert error.to_envelope() == {
        "code": "version.protocol-mismatch",
        "layer": "version",
        "retryable": False,
        "message": "too new",
        "details": {"server": 2, "client": 3},
    }


# --------------------------------------------------------------------------
# capabilities
# --------------------------------------------------------------------------


async def test_capabilities_answers_the_negotiation_surface(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "capabilities")

    assert frame["type"] == "result"
    body = frame["payload"]
    assert body["protocol"]["version"] == sessions.SESSION_PROTOCOL_VERSION
    assert body["protocol"]["context_format"] == {"min": 1, "max": 1}
    assert set(body["protocol"]["profiles"]) == {"oneshot", "dev", "test"}
    # Placeholder until the container backend exists — and an empty
    # inventory is the truthful answer, not a missing key.
    assert body["builders"] == []
    # The config is the policy: nothing configured, everything denied.
    assert body["patch_policy"] == {
        "sdk": {"allow": False},
        "zephyr": {"allow": False},
        "chip": {"allow": False},
    }
    assert body["quota"]["sessions"]["max_open"] >= 1
    assert "work" in body["quota"]


async def test_the_patch_policy_comes_from_the_configuration(
    aiohttp_client, config, features
) -> None:
    from dataclasses import replace

    from mcuhome_buildserver.app import ServerState, create_app

    state = ServerState(replace(config, allowed_patch_layers=("sdk",)), features=features)
    await state.start(probe=False)
    try:
        client = await aiohttp_client(create_app(state))
        async with client.ws_connect("/ws", headers=auth()) as ws:
            frame = await call(ws, "capabilities")
        policy = frame["payload"]["patch_policy"]
        assert policy["sdk"] == {"allow": True}
        assert policy["zephyr"] == {"allow": False}
    finally:
        await state.stop()


def test_the_allow_patch_layer_option_and_its_environment_form() -> None:
    from mcuhome_buildserver.config import load_config

    config = load_config(["--allow-patch-layer", "sdk"], env={})
    assert config.allowed_patch_layers == ("sdk",)
    config = load_config([], env={"MCUHOME_BUILDSERVER_ALLOW_PATCH_LAYERS": "sdk,zephyr"})
    assert config.allowed_patch_layers == ("sdk", "zephyr")
    with pytest.raises(SystemExit):
        load_config([], env={"MCUHOME_BUILDSERVER_ALLOW_PATCH_LAYERS": "kernel"})


# --------------------------------------------------------------------------
# Unknown verbs
# --------------------------------------------------------------------------


async def test_an_unknown_verb_is_a_typed_rejection(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "frobnicate")

    assert frame["type"] == "error"
    error = frame["error"]
    assert error["code"] == "version.verb-unknown"
    assert error["layer"] == "version"
    assert error["retryable"] is False
    assert "open-session" in error["details"]["known"]
    assert "submit_job" in error["details"]["known"]


# --------------------------------------------------------------------------
# open-session: admission and negotiation
# --------------------------------------------------------------------------


async def test_open_session_admits_with_id_lease_and_negotiation(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(
            ws,
            "open-session",
            {
                "profile": "dev",
                "protocol_version": sessions.SESSION_PROTOCOL_VERSION,
                "context_format": 1,
                "manifest": {"context": 1, "target": {"board": "nrf7002dk/nrf5340/cpuapp"}},
            },
        )

    assert frame["type"] == "result"
    body = frame["payload"]
    assert body["session"]["id"].startswith("s-")
    assert body["session"]["profile"] == "dev"
    assert body["session"]["state"] == "open"
    lease = body["lease"]
    assert lease["ttl_seconds"] > 0
    assert lease["idle_timeout_seconds"] > 0
    assert lease["expires_at"] > body["session"]["created_at"]
    negotiated = body["negotiated"]
    assert negotiated["protocol_version"] == sessions.SESSION_PROTOCOL_VERSION
    assert negotiated["context_format"] == {"min": 1, "max": 1}
    # Placeholders until their backends land, present so the shape is
    # complete from day one.
    assert negotiated["container"] is None
    assert negotiated["cost_class"] == "default"


async def test_a_protocol_version_mismatch_is_rejected_at_the_door(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "open-session", {"protocol_version": 99})

    error = frame["error"]
    assert error["code"] == "version.protocol-mismatch"
    assert error["retryable"] is False
    assert error["details"] == {"server": sessions.SESSION_PROTOCOL_VERSION, "client": 99}

    # Not sending a version at all is the same mismatch, not a guess.
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "open-session", {"profile": "oneshot"})
    assert frame["error"]["code"] == "version.protocol-mismatch"


async def test_a_context_format_outside_the_range_is_rejected_typed(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(
            ws,
            "open-session",
            {"protocol_version": sessions.SESSION_PROTOCOL_VERSION, "context_format": 7},
        )
    error = frame["error"]
    assert error["code"] == "version.context-format-unsupported"
    assert error["details"]["received"] == 7


async def test_an_unknown_profile_is_rejected_typed(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(
            ws,
            "open-session",
            {"protocol_version": sessions.SESSION_PROTOCOL_VERSION, "profile": "yolo"},
        )
    assert frame["error"]["code"] == "session.profile-unknown"
    assert frame["error"]["details"]["profiles"] == ["oneshot", "dev", "test"]


# --------------------------------------------------------------------------
# The session lifecycle around the stubs
# --------------------------------------------------------------------------


async def _open(ws) -> str:
    frame = await call(
        ws, "open-session", {"protocol_version": sessions.SESSION_PROTOCOL_VERSION}, frame_id="o"
    )
    return frame["payload"]["session"]["id"]


async def test_the_stubbed_verbs_answer_typed_not_implemented(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        for index, verb in enumerate(
            ("send-context", "extend-context", "verify", "build", "get-artifact")
        ):
            frame = await call(ws, verb, {"session_id": session_id}, frame_id=str(index))
            error = frame["error"]
            assert error["code"] == "session.not-implemented", verb
            assert error["retryable"] is False
            assert error["details"]["verb"] == verb


async def test_a_stub_still_requires_a_real_session(client) -> None:
    # The handshake in front of the stub is real: a bogus session id is
    # session.unknown, not not-implemented.
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "build", {"session_id": "s-invented"})
    assert frame["error"]["code"] == "session.unknown"


async def test_attach_and_close_work_on_a_real_session(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)

        frame = await call(ws, "attach-session", {"session_id": session_id}, frame_id="a")
        assert frame["payload"]["session"]["id"] == session_id
        assert frame["payload"]["lease"]["ttl_seconds"] > 0

        frame = await call(ws, "close-session", {"session_id": session_id}, frame_id="c")
        assert frame["payload"]["session"]["state"] == "closed"

        # Commands after close are typed refusals, and closing again is
        # not an error: the client asked for a state and it holds.
        frame = await call(ws, "verify", {"session_id": session_id}, frame_id="v")
        assert frame["error"]["code"] == "session.closed"
        frame = await call(ws, "close-session", {"session_id": session_id}, frame_id="c2")
        assert frame["payload"]["session"]["state"] == "closed"


def test_an_expired_lease_is_a_typed_expiry() -> None:
    manager = sessions.SessionManager(ttl=0.0)
    session = manager.open(
        profile="oneshot",
        protocol_version=sessions.SESSION_PROTOCOL_VERSION,
        context_format=1,
        manifest_header={},
    )
    with pytest.raises(SessionError) as excinfo:
        manager.require(session.id)
    assert excinfo.value.code == "session.expired"


def test_the_concurrent_session_quota_is_enforced_and_retryable() -> None:
    manager = sessions.SessionManager(max_open=1)
    manager.open(
        profile="oneshot",
        protocol_version=sessions.SESSION_PROTOCOL_VERSION,
        context_format=1,
        manifest_header={},
    )
    with pytest.raises(SessionError) as excinfo:
        manager.open(
            profile="oneshot",
            protocol_version=sessions.SESSION_PROTOCOL_VERSION,
            context_format=1,
            manifest_header={},
        )
    assert excinfo.value.code == "session.limit-exceeded"
    assert errors.REGISTRY["session.limit-exceeded"].retryable is True
