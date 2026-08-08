# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The frame vocabulary of ADR 0006, and its agreement with the dashboard's."""

from __future__ import annotations

import json

import pytest

from mcuhome_buildserver import protocol
from mcuhome_buildserver.protocol import Command, ProtocolError


def test_a_command_round_trips() -> None:
    command = protocol.decode('{"id":"7","type":"submit_job","payload":{"a":1}}')
    assert command == Command(id="7", type="submit_job", payload={"a": 1})


def test_a_missing_payload_is_an_empty_one() -> None:
    assert protocol.decode('{"id":1,"type":"queue_status"}').payload == {}
    assert protocol.decode('{"id":1,"type":"queue_status","payload":null}').payload == {}


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "[1,2,3]",
        '"a string"',
        '{"id":"1"}',
        '{"id":"1","type":""}',
        '{"id":{"nested":true},"type":"queue_status"}',
        '{"id":"1","type":"queue_status","payload":[]}',
    ],
)
def test_a_malformed_frame_is_refused(raw: str) -> None:
    with pytest.raises(ProtocolError):
        protocol.decode(raw)


def test_the_three_frame_shapes() -> None:
    assert protocol.result_frame("7", {"ok": True}) == {
        "id": "7",
        "type": "result",
        "payload": {"ok": True},
    }
    assert protocol.error_frame("7", "not_found", "no such job", job_id="x") == {
        "id": "7",
        "type": "error",
        "error": {"code": "not_found", "message": "no such job", "job_id": "x"},
    }
    assert protocol.event_frame("job_output", {"a": 1}) == {
        "type": "event",
        "event": "job_output",
        "payload": {"a": 1},
    }


def test_the_job_events_carry_what_a_client_needs_to_reorder() -> None:
    event = protocol.job_output_event("j1", 4096, "text")
    assert event["payload"] == {"job_id": "j1", "offset": 4096, "text": "text"}
    state = protocol.job_state_event({"id": "j1", "state": "running"})
    assert state["payload"]["job"]["state"] == "running"


def test_encoding_is_deterministic_and_keeps_unicode() -> None:
    text = protocol.encode({"type": "result", "payload": {"message": "größer"}})
    assert "größer" in text
    assert json.loads(text)["payload"]["message"] == "größer"


class TestFieldAccessors:
    def command(self, **payload: object) -> Command:
        return Command(id="1", type="submit_job", payload=payload)

    def test_required_fields(self) -> None:
        assert self.command(job_id="x").require_str("job_id") == "x"
        with pytest.raises(ProtocolError):
            self.command(job_id="").require_str("job_id")
        with pytest.raises(ProtocolError):
            self.command().require_dict("model")

    def test_a_bool_is_not_a_number(self) -> None:
        # True == 1 in Python, and a byte offset of True is a bug that
        # would otherwise arrive as a successful follow.
        with pytest.raises(ProtocolError):
            self.command(offset=True).optional_int("offset")

    def test_optional_fields_fall_back(self) -> None:
        assert self.command().optional_int("offset", 0) == 0
        assert self.command().optional_bool("no_sign", True) is True
        assert self.command().optional_str_list("snippets") == []
        assert self.command(snippets="debug-rtt").optional_str_list("snippets") == ["debug-rtt"]


def test_the_envelope_matches_the_dashboard_s() -> None:
    """The two products must not drift apart on the frame envelope.

    ADR 0006 decision 2 makes the frame vocabulary the contract, and the
    build server keeps its own copy of the codec so it can be deployed
    without the dashboard package. This is what stops "its own copy"
    from becoming "its own dialect": in this repository's development
    install both are importable, and a rename on one side fails here.
    """
    dashboard = pytest.importorskip(
        "mcuhome_dashboard.protocol", reason="the dashboard package is not installed"
    )
    for name in (
        "TYPE_RESULT",
        "TYPE_ERROR",
        "TYPE_EVENT",
        "ERROR_BAD_REQUEST",
        "ERROR_UNKNOWN_COMMAND",
        "ERROR_NOT_FOUND",
        "ERROR_UNAUTHORIZED",
        "ERROR_UNAVAILABLE",
        "ERROR_CONFLICT",
        "ERROR_INTERNAL",
    ):
        assert getattr(protocol, name) == getattr(dashboard, name), name

    frame = {"id": "7", "type": "result", "payload": {"x": 1}}
    assert protocol.encode(frame) == dashboard.encode(frame)
    assert protocol.decode(dashboard.encode(frame)).payload == {"x": 1}
