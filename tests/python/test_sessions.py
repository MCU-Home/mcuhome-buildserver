# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Session protocol v2: the envelope, the registry, and the verb skeleton."""

from __future__ import annotations

import time

import pytest

from mcuhome.buildserver import errors, protocol, sessions
from mcuhome.buildserver.errors import LAYERS, REGISTRY, SessionError, envelope
from tests.python.conftest import auth, call

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


def test_the_lock_replaced_the_manifest_immutability_code() -> None:
    """``session.manifest-immutable`` is gone, and two codes replace it.

    It encoded the sentence ADR 0019's amendment replaced outright:
    "``manifest.yaml`` is immutable for the session's lifetime". Under
    the valid layer that rule cannot fire from either end — before the
    lock there is no manifest to protect, and after it the whole context
    is closed to writes, not just one file. Removing it is only possible
    while nothing is published (this package is ``0.1.0.dev0``); after
    the first release the registry is append-only and a wrong entry
    could only be superseded.
    """
    assert "session.manifest-immutable" not in REGISTRY
    assert REGISTRY["context.locked"].retryable is False
    assert REGISTRY["context.not-locked"].retryable is False


def test_the_dropped_exit_codes_left_no_codes_behind() -> None:
    """Codes 64 and 65 are gone, so the codes defined by them are too.

    ``builder.command-unsupported`` and ``builder.parameter-unsupported``
    were each defined as "the container answered reserved exit code N",
    and ADR 0019's amendment drops 64 and 65 by name — they are
    ``EX_USAGE`` and ``EX_DATAERR``, which foreign runtimes emit for
    ordinary argument errors. What carries the meaning now is the result
    document's ``reason``, and how a backend maps that into this
    envelope is the backend's business, so the replacements are
    registered when there is a backend to raise them.
    """
    assert "builder.command-unsupported" not in REGISTRY
    assert "builder.parameter-unsupported" not in REGISTRY


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


async def test_capabilities_answers_the_negotiation_surface(client, config) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "capabilities")

    assert frame["type"] == "result"
    body = frame["payload"]
    assert body["protocol"]["version"] == sessions.SESSION_PROTOCOL_VERSION
    assert body["protocol"]["context_format"] == {
        "min": sessions.CONTEXT_FORMAT_MIN,
        "max": sessions.CONTEXT_FORMAT_MAX,
    }
    assert set(body["protocol"]["profiles"]) == {"oneshot", "dev", "test"}
    # Real since the container backend landed: every local image
    # carrying the org.mcuhome.contract label, with the tag, the digest
    # and the labels ADR 0019 §2 asks for. Nothing here starts a
    # container — describe costs one, and a client asking what this
    # server has is not yet asking any image to prove it.
    assert [entry["digest"] for entry in body["containers"]] == ["sha256:" + "b" * 64]
    # The config is the policy: nothing configured, everything denied.
    # Four layers, because build-container contract §1.1 defines four —
    # `mcuboot` is one because every device build is `west build
    # --sysbuild` with MCUboot as the second image, and leaving it out
    # meant an operator could not allow a layer the contract names.
    assert body["patch_policy"] == {
        "sdk": {"allow": False},
        "zephyr": {"allow": False},
        "chip": {"allow": False},
        "mcuboot": {"allow": False},
    }
    assert body["quota"]["sessions"]["max_open"] >= 1
    # Sessions and nothing else: v1.0 has no work metering and no cost
    # classes, so there is no `quota.work` to answer.
    assert set(body["quota"]) == {"sessions"}
    # E57: what one upload may cost here, announced rather than
    # discovered by hitting it. The five caps of decision 8 plus the
    # transport bound below the verbs, whose overrun is a dropped
    # connection and can never be a typed refusal.
    assert body["ingress"] == {
        "compressed_bytes": config.max_compressed_bytes,
        "decompressed_bytes": config.max_decompressed_bytes,
        "entries": config.max_entries,
        "file_bytes": config.max_file_bytes,
        "path_depth": config.max_path_depth,
        "frame_bytes": protocol.MAX_FRAME_BYTES,
    }


async def test_capabilities_reports_version_and_uptime_behind_the_token(client) -> None:
    """Version and uptime moved off the unauthenticated ``/health`` to here.

    A liveness probe needs neither, and the one pre-auth response is the
    wrong place to disclose a version an attacker could match to a known
    weakness. A client that has presented the token may read them.
    """
    from mcuhome.buildserver import __version__

    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "capabilities")

    server = frame["payload"]["server"]
    assert server["build_server"] == __version__
    assert isinstance(server["uptime_seconds"], int | float)
    assert server["uptime_seconds"] >= 0


async def test_the_announced_ingress_caps_come_from_the_configuration(
    aiohttp_client, config
) -> None:
    """E44: the config **is** the policy, so the announcement follows it.

    An operator who lowered a cap has lowered what ``capabilities``
    says, and a client that sized its upload from the announcement is
    refused by nothing it could not see. Every one of the five is given
    a distinctive value here, because five caps announced from five
    constants would pass an assertion against the defaults.
    """
    from dataclasses import replace

    from mcuhome.buildserver.app import ServerState, create_app

    lowered = replace(
        config,
        max_compressed_bytes=4001,
        max_decompressed_bytes=4002,
        max_entries=4003,
        max_file_bytes=4004,
        max_path_depth=7,
    )
    client = await aiohttp_client(create_app(ServerState(lowered)))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "capabilities")

    assert frame["payload"]["ingress"] == {
        "compressed_bytes": 4001,
        "decompressed_bytes": 4002,
        "entries": 4003,
        "file_bytes": 4004,
        "path_depth": 7,
        # Not configurable and not this server's to relax: it is the
        # WebSocket's own `max_msg_size`, applied to the socket before
        # any verb exists to refuse anything.
        "frame_bytes": protocol.MAX_FRAME_BYTES,
    }


def test_the_frame_bound_is_announced_from_the_one_the_endpoint_applies() -> None:
    """The announced number and the socket's ``max_msg_size`` are one value.

    It moved to :mod:`~mcuhome.buildserver.protocol` for E57 — the verbs
    announce it and the endpoint applies it, and the endpoint imports
    the verbs, so a constant living in ``ws`` could only have been
    announced by copying it.
    """
    from mcuhome.buildserver import ws as ws_module

    assert ws_module.MAX_FRAME_BYTES is protocol.MAX_FRAME_BYTES
    assert protocol.MAX_FRAME_BYTES == 8 * 1024 * 1024


async def test_the_patch_policy_comes_from_the_configuration(aiohttp_client, config) -> None:
    from dataclasses import replace

    from mcuhome.buildserver.app import ServerState, create_app

    state = ServerState(replace(config, allowed_patch_layers=("sdk",)))
    client = await aiohttp_client(create_app(state))
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "capabilities")
    policy = frame["payload"]["patch_policy"]
    assert policy["sdk"] == {"allow": True}
    assert policy["zephyr"] == {"allow": False}


def test_the_allow_patch_layer_option_and_its_environment_form() -> None:
    from mcuhome.buildserver.config import load_config

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


def test_the_verb_set_is_the_whole_vocabulary() -> None:
    """The eleven session verbs are all this server answers.

    Re-homed from the deleted ``/capabilities`` test, which asserted the
    merged v1+v2 command set. The job commands are gone, so this table
    *is* the surface, and it is the complete list of dashboard ADR 0012
    decision 3 (amended 2026-08-09 from ADR 0019). The two that were
    missing are the load-bearing ones: without ``lock-context`` a client
    can never reach ``build``, and without ``cancel`` a closed socket
    would be the only stop signal — which is no stop signal at all.
    """
    from mcuhome.buildserver import ws as ws_module

    assert set(ws_module.COMMANDS) == {
        "capabilities",
        "open-session",
        "send-context",
        "extend-context",
        "lock-context",
        "verify",
        "build",
        "cancel",
        "get-artifact",
        "attach-session",
        "close-session",
    }
    # Derived, not copied: `ws.COMMANDS = dict(sessions.SESSION_VERBS)`,
    # so registering a verb once is registering it everywhere.
    assert set(ws_module.COMMANDS) == set(sessions.SESSION_VERBS)


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
                "context_format": sessions.CONTEXT_FORMAT_MAX,
            },
        )

    assert frame["type"] == "result"
    body = frame["payload"]
    assert body["session"]["id"].startswith("s-")
    assert body["session"]["profile"] == "dev"
    assert body["session"]["state"] == "open"
    # Admitted on no context at all: the pins arrive with send-context.
    assert body["session"]["context_state"] == sessions.CONTEXT_NONE
    lease = body["lease"]
    assert lease["ttl_seconds"] > 0
    assert lease["idle_timeout_seconds"] > 0
    assert lease["expires_at"] > body["session"]["created_at"]
    negotiated = body["negotiated"]
    assert negotiated["protocol_version"] == sessions.SESSION_PROTOCOL_VERSION
    assert negotiated["context_format"] == {
        "min": sessions.CONTEXT_FORMAT_MIN,
        "max": sessions.CONTEXT_FORMAT_MAX,
    }
    # What admission alone decides, and no more. The serving container's
    # contract version is send-context's answer, because at this point
    # the backend does not yet know which container serves the session.
    assert set(negotiated) == {"protocol_version", "context_format", "backend_profile"}
    # `container` | `subprocess` (contract §1.2), and it can only ever be
    # the first here: a subprocess-profile backend "serves exactly one
    # build environment — the one it runs in", and this process is an
    # orchestrator that is never itself a build environment.
    assert negotiated["backend_profile"] == "container"


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


@pytest.mark.parametrize(
    ("what", "payload", "code"),
    [
        ("context format 0", {"context_format": 0}, "version.context-format-unsupported"),
        ("an empty profile", {"profile": ""}, "session.profile-unknown"),
    ],
)
async def test_a_falsy_operand_is_a_value_and_not_an_absence(client, what, payload, code) -> None:
    """ "Version mismatch is a typed rejection at the door" (decision 2).

    Both operands were read as ``optional(...) or <default>``, which
    cannot tell "the client did not ask" from "the client asked for a
    falsy value": ``context_format: 0`` and ``profile: ""`` were quietly
    turned into the defaults and answered ``result``, so a client asking
    for a format this server does not read was admitted and would have
    discovered it downstream — the one place the ADR says a version
    mismatch must never surface.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(
            ws,
            "open-session",
            {"protocol_version": sessions.SESSION_PROTOCOL_VERSION, **payload},
        )
    assert frame["type"] == "error", what
    assert frame["error"]["code"] == code

    # And an operand that is genuinely absent still takes the default.
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(
            ws, "open-session", {"protocol_version": sessions.SESSION_PROTOCOL_VERSION}
        )
    assert frame["payload"]["session"]["profile"] == "oneshot"


# --------------------------------------------------------------------------
# The session lifecycle around the stubs
# --------------------------------------------------------------------------


async def _open(ws) -> str:
    frame = await call(
        ws, "open-session", {"protocol_version": sessions.SESSION_PROTOCOL_VERSION}, frame_id="o"
    )
    return frame["payload"]["session"]["id"]


def _admit(manager: sessions.SessionManager | None = None) -> sessions.Session:
    """One admitted session, straight from the manager.

    Admission takes three operands and no fourth — ADR 0019's amendment
    took the manifest header away from ``open-session`` — so this helper
    is the whole of it.
    """
    manager = manager or sessions.SessionManager()
    return manager.open(
        profile="oneshot",
        protocol_version=sessions.SESSION_PROTOCOL_VERSION,
        context_format=sessions.CONTEXT_FORMAT_MAX,
    )


async def test_no_verb_answers_not_implemented_any_more(client) -> None:
    """The container backend was the last stub, and it landed.

    Every verb now answers for itself: the context path, the freeze, the
    two working commands, the download and the two reconnection verbs.
    ``session.not-implemented`` stays in the registry, because the
    registry is append-only and a future verb will want it, and nothing
    raises it — which is what this asserts, from the one verb that used
    to.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        frame = await call(
            ws,
            "get-artifact",
            {"session_id": session_id, "invocation_id": "inv-1"},
            frame_id="g",
        )
        # An invocation this session never ran, not a missing backend.
        assert frame["error"]["code"] == "invocation.unknown"
    assert "session.not-implemented" in REGISTRY


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
    session = _admit(manager)
    with pytest.raises(SessionError) as excinfo:
        manager.require(session.id)
    assert excinfo.value.code == "session.expired"


def test_the_concurrent_session_limit_is_enforced_and_retryable() -> None:
    """Per server, not per user.

    v1.0 is single-tenant and one bearer token is one principal, so a
    per-user quota would be a per-server quota with a misleading name.
    """
    manager = sessions.SessionManager(max_open=1)
    _admit(manager)
    with pytest.raises(SessionError) as excinfo:
        _admit(manager)
    assert excinfo.value.code == "session.limit-exceeded"
    assert errors.REGISTRY["session.limit-exceeded"].retryable is True


def test_a_session_past_its_lease_does_not_hold_an_admission_slot() -> None:
    """Otherwise four clients that walked away close the server for good.

    ``open_count`` counted every ``STATE_OPEN`` record regardless of its
    lease, and nothing but a client presenting its own session id ever
    expired one — so four abandoned sessions blocked admission until
    somebody restarted the process, and pinned up to four times the
    per-session disk quota while they did it. The sweep runs every
    :data:`~mcuhome.buildserver.sessions.DEFAULT_REAP_INTERVAL` seconds
    and the answer must not depend on where in that interval the
    question lands, so the count asks about the lease itself.
    """
    manager = sessions.SessionManager(ttl=0.0, max_open=1)
    abandoned = _admit(manager)
    assert manager.open_count == 0
    fresh = _admit(manager)
    assert fresh.id != abandoned.id


# --------------------------------------------------------------------------
# The context state machine: send/extend, the lock, and what it unlocks
# --------------------------------------------------------------------------


def test_a_session_is_admitted_on_no_context_at_all() -> None:
    """The pins arrive with ``send-context``, not with admission.

    ADR 0019's amendment takes ``open-session``'s first operand away and
    ADR 0018's retires the term "manifest header" outright: there is no
    header separate from ``context.yaml``, and ``manifest.yaml`` does
    not exist until ``lock-context`` writes it. So a fresh session holds
    no context of any kind, and there is nothing on it to be immutable.
    """
    session = _admit()
    assert session.context_state == sessions.CONTEXT_NONE
    assert not hasattr(session, "manifest_header")


def test_a_writing_command_after_the_lock_is_refused_typed() -> None:
    """The lock is one-way, and ``context.locked`` is what says so.

    Adding a patch after a ``verify`` is a new session, not an
    extension — which is only enforceable because the freeze is an
    explicit verb with a state to check rather than an implicit one.
    """
    session = _admit()
    session.context_state = sessions.CONTEXT_LOCKED
    with pytest.raises(SessionError) as excinfo:
        session.require_writable_context()
    assert excinfo.value.code == "context.locked"


def test_a_working_command_before_the_lock_is_refused_typed() -> None:
    """``verify`` and ``build`` run only from the lock onwards.

    Both states before the lock refuse them, not just the empty one: a
    context that has arrived but is still open to extension has no
    stable ``files`` list, which is the thing ``verify`` checks against
    and the thing ``build`` is attributed to.
    """
    session = _admit()
    for state in (sessions.CONTEXT_NONE, sessions.CONTEXT_UNLOCKED):
        session.context_state = state
        with pytest.raises(SessionError) as excinfo:
            session.require_locked_context()
        assert excinfo.value.code == "context.not-locked", state


def test_the_lock_is_what_admits_the_working_commands() -> None:
    """The other half of the same rule: from the lock, they pass.

    Asserted separately because "unlocks the writing commands" is a
    thing the verb *does*, not merely a refusal it stops raising.
    """
    session = _admit()
    session.context_state = sessions.CONTEXT_LOCKED
    session.require_locked_context()
    session.require_context()


async def test_verify_and_build_before_the_lock_are_typed_refusals(client) -> None:
    """Over the wire, from a fresh session: the flow's own order.

    This is the structural reason the verb set could not stay at nine —
    a client that never locks the context can never reach ``build``.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        for index, verb in enumerate(("verify", "build")):
            frame = await call(ws, verb, {"session_id": session_id}, frame_id=str(index))
            assert frame["error"]["code"] == "context.not-locked", verb
            assert frame["error"]["retryable"] is False


async def test_lock_context_without_a_context_is_refused_typed(client) -> None:
    """Nothing to freeze is not the same as a freeze that failed.

    No ADR names a code for this case; ``context.missing`` is the
    registry's own entry for "the command needs a context and
    send-context has not happened", which is exactly what this is.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        frame = await call(ws, "lock-context", {"session_id": session_id}, frame_id="l")
    assert frame["error"]["code"] == "context.missing"
    assert frame["error"]["details"]["session_id"] == session_id


async def test_lock_context_needs_a_context_that_is_really_there(client, state) -> None:
    """The state machine and the disk agree, and both are checked.

    A session whose ``context_state`` says ``unlocked`` while no
    directory was ever created is a state only a test can build, and the
    freeze answers it as ``context.missing`` rather than trying to hash
    a directory that is not there. The two are set together by
    ``send-context``; checking both is what keeps that true when a
    second way into the state machine appears.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        state.sessions.require(session_id).context_state = sessions.CONTEXT_UNLOCKED
        frame = await call(ws, "lock-context", {"session_id": session_id}, frame_id="l")
    assert frame["error"]["code"] == "context.missing"


async def test_the_lock_closes_the_context_to_every_writing_command(client, state) -> None:
    """One rule, three verbs: after the lock nothing may write.

    Wider than the rule it replaced. That one protected ``manifest.yaml``
    alone; this closes the whole context, because a second
    ``lock-context`` is as much a write as another patch is.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        state.sessions.require(session_id).context_state = sessions.CONTEXT_LOCKED
        for index, verb in enumerate(("send-context", "extend-context", "lock-context")):
            frame = await call(ws, verb, {"session_id": session_id}, frame_id=str(index))
            assert frame["error"]["code"] == "context.locked", verb


async def test_the_lock_unlocks_verify_and_build(client, state) -> None:
    """Past the lock they stop being refused and start doing work.

    ``context.not-locked`` is the answer of a verb that was never
    allowed to run. This session's ``context_state`` was moved by hand
    and there is no directory behind it, so what the two reach instead
    is ``context.missing`` — a refusal from *inside* the working path,
    which is what proves the gate opened rather than merely stopped
    complaining.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        state.sessions.require(session_id).context_state = sessions.CONTEXT_LOCKED
        for index, verb in enumerate(("verify", "build")):
            frame = await call(ws, verb, {"session_id": session_id}, frame_id=str(index))
            assert frame["error"]["code"] == "context.missing", verb


async def test_attach_session_reports_the_context_state_in_any_of_them(client, state) -> None:
    """The reconnection verb is not gated on the lock, and says where it stands.

    Connection loss is never abandonment, so a client may come back at
    any point of the context's lifetime — and what it needs to know
    first is whether it still has to lock.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        for index, context_state in enumerate(
            (sessions.CONTEXT_NONE, sessions.CONTEXT_UNLOCKED, sessions.CONTEXT_LOCKED)
        ):
            state.sessions.require(session_id).context_state = context_state
            frame = await call(
                ws, "attach-session", {"session_id": session_id}, frame_id=str(index)
            )
            assert frame["payload"]["session"]["context_state"] == context_state


# --------------------------------------------------------------------------
# cancel
# --------------------------------------------------------------------------


async def test_cancel_needs_the_invocation_it_addresses(client) -> None:
    """``cancel(invocation-id)`` — the operand is the verb.

    A cancel without one would have to mean "whatever is running", and
    the documents define no such command: what it aborts is the running
    invocation named by the server-assigned id that ``build`` handed
    out.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        frame = await call(ws, "cancel", {"session_id": session_id}, frame_id="c")
    assert frame["error"]["code"] == "bad_request"


async def test_cancel_of_an_unknown_invocation_is_typed(client) -> None:
    """`invocation.unknown` — the one wrong answer is "cancelled" (E38).

    Answering an acknowledgement for an invocation that was never
    running would tell a client its build is stopping while nothing
    stops; the refusal names the ids the session does have, so a client
    holding a stale id can see what it raced against.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        frame = await call(
            ws, "cancel", {"session_id": session_id, "invocation_id": "inv-7"}, frame_id="c"
        )
    error = frame["error"]
    assert error["code"] == "invocation.unknown"
    assert error["details"]["invocation_id"] == "inv-7"
    assert error["details"]["known"] == []


async def test_cancel_acknowledges_the_signal_not_the_stop(client, state) -> None:
    """The E38 wire shape: the answer means "the stop signal is set".

    Never "it stopped" — only the invocation's result document says
    that, with ``status: "cancelled"``. And idempotently: the second
    cancel of a race gets the same acknowledgement as the first, because
    a client that retries into a signal already set did nothing wrong.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        session = state.sessions.require(session_id)
        session.invocations["inv-1"] = sessions.INVOCATION_RUNNING
        first = await call(
            ws, "cancel", {"session_id": session_id, "invocation_id": "inv-1"}, frame_id="c1"
        )
        second = await call(
            ws, "cancel", {"session_id": session_id, "invocation_id": "inv-1"}, frame_id="c2"
        )
    assert first["payload"] == {
        "session_id": session_id,
        "invocation_id": "inv-1",
        "cancelled": True,
        "already_finished": False,
    }
    assert second["payload"]["cancelled"] is True
    assert session.invocations["inv-1"] == sessions.INVOCATION_CANCELLING


async def test_cancel_racing_a_natural_completion_is_not_an_error(client, state) -> None:
    """`already_finished` is an answer, not a refusal (E38).

    The race between a cancel and a completion is legitimate — both
    parties behaved correctly — so the client gets a fact, not an error
    envelope it would have to classify.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        state.sessions.require(session_id).invocations["inv-1"] = sessions.INVOCATION_FINISHED
        frame = await call(
            ws, "cancel", {"session_id": session_id, "invocation_id": "inv-1"}, frame_id="c"
        )
    assert "error" not in frame or frame.get("error") is None
    assert frame["payload"]["cancelled"] is False
    assert frame["payload"]["already_finished"] is True


async def test_a_poisoned_session_refuses_work_and_keeps_its_exits(client, state) -> None:
    """`session.poisoned` for every working verb; the exits stay open (E39).

    The session is deliberately not reaped: the moment it poisons is the
    moment its owner most needs the logs and partial artifacts that
    explain what happened. get-artifact still answers (its own
    not-implemented refusal, not the poison), cancel still works on a
    running invocation, and close-session cleans up as always.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        session = state.sessions.require(session_id)
        session.context_state = sessions.CONTEXT_LOCKED
        session.invocations["inv-1"] = sessions.INVOCATION_RUNNING
        session.poison()

        for verb in ("send-context", "extend-context", "lock-context", "verify", "build"):
            frame = await call(ws, verb, {"session_id": session_id}, frame_id=f"p-{verb}")
            assert frame["error"]["code"] == "session.poisoned", verb

        # The exit that matters most: `get-artifact` answers about the
        # invocation rather than about the poison. This one declared
        # nothing (it never ran), so the answer is `artifact.unknown`
        # with the declared paths — not a refusal of the session.
        artifact = await call(
            ws,
            "get-artifact",
            {"session_id": session_id, "invocation_id": "inv-1", "path": "firmware.hex"},
            frame_id="g",
        )
        assert artifact["error"]["code"] == "artifact.unknown"
        assert artifact["error"]["details"]["declared"] == []

        cancelled = await call(
            ws, "cancel", {"session_id": session_id, "invocation_id": "inv-1"}, frame_id="c"
        )
        assert cancelled["payload"]["cancelled"] is True

        closed = await call(ws, "close-session", {"session_id": session_id}, frame_id="x")
        assert closed["payload"]["session"]["state"] == "closed"


async def test_close_session_cancels_a_running_invocation_implicitly(client, state) -> None:
    """close-session on a busy session sets the stop signal first (E39).

    Refusing to close while an invocation runs was rejected: connection
    loss is never abandonment (that is attach-session's reason to
    exist), so closing must never require cancel-reattach-wait from a
    client that may no longer be alive.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        session = state.sessions.require(session_id)
        session.invocations["inv-1"] = sessions.INVOCATION_RUNNING
        session.invocations["inv-2"] = sessions.INVOCATION_FINISHED
        frame = await call(ws, "close-session", {"session_id": session_id}, frame_id="x")
    assert frame["payload"]["session"]["state"] == "closed"
    assert session.invocations["inv-1"] == sessions.INVOCATION_CANCELLING
    assert session.invocations["inv-2"] == sessions.INVOCATION_FINISHED


async def test_every_authenticated_verb_refreshes_the_idle_timer(client, state) -> None:
    """One rule, no per-verb list: a command is a command.

    The idle timeout "counts absent *commands*" (ADR 0019), and the
    second amendment settles which verbs qualify: all of them —
    lock-context and cancel included. The refresh lives in
    SessionManager.require(), the one door every session verb walks
    through, which is what makes the rule structural rather than a list
    to maintain.

    The clock is wound back by a minute rather than to zero, because the
    idle timeout is now *enforced* there as well: a session last heard
    from at the epoch is not a session with a stale timer, it is one the
    reaper would already have taken.
    """
    backdated = time.time() - 60.0
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        session = state.sessions.require(session_id)
        session.invocations["inv-1"] = sessions.INVOCATION_RUNNING
        session.last_command_at = backdated
        await call(ws, "cancel", {"session_id": session_id, "invocation_id": "inv-1"}, frame_id="c")
        after_cancel = session.last_command_at
        session.last_command_at = backdated
        await call(ws, "lock-context", {"session_id": session_id}, frame_id="l")
        after_lock = session.last_command_at
    assert after_cancel > backdated
    assert after_lock > backdated


async def test_cancel_leaves_the_session_standing(client, state) -> None:
    """The session and its warm container survive a cancel.

    That is the promise that separates it from ``close-session``, and it
    is what makes it usable in a dev loop: a client aborts one build and
    starts another over the same locked context. So the verb must touch
    neither the session's state nor the context's.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await _open(ws)
        state.sessions.require(session_id).context_state = sessions.CONTEXT_LOCKED
        await call(ws, "cancel", {"session_id": session_id, "invocation_id": "inv-7"}, frame_id="c")
        frame = await call(ws, "attach-session", {"session_id": session_id}, frame_id="a")

    assert frame["payload"]["session"]["state"] == "open"
    assert frame["payload"]["session"]["context_state"] == sessions.CONTEXT_LOCKED
