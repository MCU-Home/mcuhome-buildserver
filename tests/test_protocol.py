# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The frame envelope, and its agreement with the dashboard's.

The envelope is the half of dashboard ADR 0006 that dashboard ADR 0012
decision 3 carries forward; only the vocabulary inside it was replaced.
So this file still tests the codec — with session verbs as its literals
instead of job commands.
"""

from __future__ import annotations

import json

import pytest

from mcuhome_buildserver import protocol
from mcuhome_buildserver.protocol import Command, ProtocolError


def test_a_command_round_trips() -> None:
    command = protocol.decode('{"id":"7","type":"open-session","payload":{"a":1}}')
    assert command == Command(id="7", type="open-session", payload={"a": 1})


def test_a_missing_payload_is_an_empty_one() -> None:
    assert protocol.decode('{"id":1,"type":"capabilities"}').payload == {}
    assert protocol.decode('{"id":1,"type":"capabilities","payload":null}').payload == {}


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "[1,2,3]",
        '"a string"',
        '{"id":"1"}',
        '{"id":"1","type":""}',
        '{"id":{"nested":true},"type":"capabilities"}',
        '{"id":"1","type":"capabilities","payload":[]}',
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
    assert protocol.error_frame("7", "bad_request", "not a frame", detail="x") == {
        "id": "7",
        "type": "error",
        "error": {"code": "bad_request", "message": "not a frame", "detail": "x"},
    }
    assert protocol.event_frame("progress", {"a": 1}) == {
        "type": "event",
        "event": "progress",
        "payload": {"a": 1},
    }


def test_encoding_is_deterministic_and_keeps_unicode() -> None:
    text = protocol.encode({"type": "result", "payload": {"message": "größer"}})
    assert "größer" in text
    assert json.loads(text)["payload"]["message"] == "größer"


class TestFieldAccessors:
    def command(self, **payload: object) -> Command:
        return Command(id="1", type="open-session", payload=payload)

    def test_required_fields(self) -> None:
        assert self.command(session_id="x").require_str("session_id") == "x"
        with pytest.raises(ProtocolError):
            self.command(session_id="").require_str("session_id")
        with pytest.raises(ProtocolError):
            self.command().require_str("session_id")

    def test_a_bool_is_not_a_number(self) -> None:
        # True == 1 in Python, and a protocol version of True is a bug
        # that would otherwise arrive as a successful negotiation.
        with pytest.raises(ProtocolError):
            self.command(protocol_version=True).optional_int("protocol_version")

    def test_optional_fields_fall_back(self) -> None:
        assert self.command().optional_int("context_format", 1) == 1
        assert self.command().optional_str("profile", "oneshot") == "oneshot"
        # Not "manifest": open-session lost that operand with ADR 0019's
        # amendment. The accessor stays — the codec is general, and the
        # verbs that carry objects are the ones still stubbed.
        assert self.command().optional_dict("params") == {}
        assert self.command(params={"mode": "clean"}).optional_dict("params") == {"mode": "clean"}
        with pytest.raises(ProtocolError):
            self.command(params=[]).optional_dict("params")
