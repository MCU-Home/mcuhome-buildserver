# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The build-service frame vocabulary (ADR 0006 decision 3).

One WebSocket endpoint, two kinds of frame — the same envelope the
dashboard's own API uses, because ADR 0006 decision 2 makes the frame
vocabulary the contract and there is no reason for two shapes of
envelope in one product family::

    → {"id": "7", "type": "submit_job",  "payload": {...}}
    ← {"id": "7", "type": "result",      "payload": {"job_id": "…"}}
    ← {"id": "7", "type": "error",       "error": {"code": "…", …}}
    ← {"type": "event", "event": "job_state_changed", "payload": {...}}

**Why this module is a sibling of** ``mcuhome_dashboard.protocol``
**rather than an import of it.** The dashboard and the build server are
separate products with separate version numbers (ADR 0003 decision 1),
and the build server is routinely installed where the dashboard is not —
a workstation under a desk, a NAS, a WSL instance. Importing the
dashboard's package here would make the fat half undeployable without
the thin half, which is exactly the coupling ADR 0003 spent its length
avoiding.

What must not drift is the *vocabulary*, and that is guarded rather than
assumed: ``tests/test_protocol.py`` compares this module's envelope
constants against ``mcuhome_dashboard.protocol`` whenever both packages
are importable, which in this repository's development install is
always. A rename on one side fails a test on the other instead of
producing two servers that almost agree.

**Commands** (client → server), ADR 0006 decision 3 plus the ``follow``
operation its decision 6 describes:

``submit_job``
    Queue one build. Payload: the resolved ``device-model.json``, the
    ``model_version`` it claims, the signing **public** key, and the
    build options.
``cancel_job``
    Stop one job — queued or running.
``follow_job``
    History-then-live log output from a byte offset the client states.
``download_artifacts``
    The artifact index, and then the artifacts themselves in chunks.
``queue_status``
    What the queue is doing, and the job records it remembers.

**Events** (server → client, unprompted): ``job_state_changed`` and
``job_output``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "COMMAND_TYPES",
    "ERROR_BAD_REQUEST",
    "ERROR_CONFLICT",
    "ERROR_INTERNAL",
    "ERROR_NOT_FOUND",
    "ERROR_UNAUTHORIZED",
    "ERROR_UNAVAILABLE",
    "ERROR_UNKNOWN_COMMAND",
    "ERROR_UNSUPPORTED",
    "EVENT_JOB_OUTPUT",
    "EVENT_JOB_STATE_CHANGED",
    "PROTOCOL_VERSION",
    "TYPE_ERROR",
    "TYPE_EVENT",
    "TYPE_RESULT",
    "Command",
    "ProtocolError",
    "decode",
    "encode",
    "error_frame",
    "event_frame",
    "job_output_event",
    "job_state_event",
    "result_frame",
]

#: Bumped when a frame changes shape in a way an old client cannot read.
#: Advertised by ``GET /capabilities`` so that the negotiation of ADR
#: 0006 decision 4 covers the protocol as well as the model.
PROTOCOL_VERSION = 1

TYPE_RESULT = "result"
TYPE_ERROR = "error"
TYPE_EVENT = "event"

EVENT_JOB_STATE_CHANGED = "job_state_changed"
EVENT_JOB_OUTPUT = "job_output"

#: Every command this server answers. Named as data so that an unknown
#: command can list the known ones instead of just refusing.
COMMAND_TYPES = (
    "submit_job",
    "cancel_job",
    "follow_job",
    "download_artifacts",
    "queue_status",
)

#: The frame was not understood: malformed JSON, missing fields, wrong
#: types. Always the client's fault.
ERROR_BAD_REQUEST = "bad_request"
#: A well-formed frame naming a command this server does not have.
ERROR_UNKNOWN_COMMAND = "unknown_command"
#: The command is fine, the job or artifact it names does not exist.
ERROR_NOT_FOUND = "not_found"
#: The token was missing or wrong.
ERROR_UNAUTHORIZED = "unauthorized"
#: A precondition outside the client's control is missing — no west
#: workspace, no builder, no disk.
ERROR_UNAVAILABLE = "unavailable"
#: The job is not in a state where this makes sense: cancelling a job
#: that already finished, downloading artifacts of one that failed.
ERROR_CONFLICT = "conflict"
#: The request is well-formed and this server cannot honour it — a
#: ``model_version`` outside the advertised range, or a builder that is
#: missing a feature the job needs. Distinct from ``bad_request``
#: because nothing about the frame is wrong, and the negotiation of ADR
#: 0006 decision 4 exists precisely so a client can see this coming.
ERROR_UNSUPPORTED = "unsupported"
#: A bug on this side. Carries no traceback; the log has it.
ERROR_INTERNAL = "internal_error"


class ProtocolError(Exception):
    """A frame this server refuses, with the code to answer with."""

    def __init__(
        self, message: str, *, code: str = ERROR_BAD_REQUEST, frame_id: Any = None, **detail: Any
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.frame_id = frame_id
        self.detail = detail


@dataclass(frozen=True)
class Command:
    """One decoded client frame."""

    id: Any
    type: str
    payload: dict[str, Any] = field(default_factory=dict)

    def require_str(self, key: str) -> str:
        value = self.payload.get(key)
        if not isinstance(value, str) or not value:
            raise ProtocolError(
                f'"{self.type}" needs a non-empty string "{key}" in its payload.',
                frame_id=self.id,
            )
        return value

    def optional_str(self, key: str, default: str | None = None) -> str | None:
        value = self.payload.get(key)
        if value is None:
            return default
        if not isinstance(value, str):
            raise ProtocolError(f'"{self.type}" wants "{key}" as a string.', frame_id=self.id)
        return value

    def require_dict(self, key: str) -> dict[str, Any]:
        value = self.payload.get(key)
        if not isinstance(value, dict):
            raise ProtocolError(
                f'"{self.type}" needs "{key}" as a JSON object in its payload.',
                frame_id=self.id,
            )
        return value

    def optional_dict(self, key: str) -> dict[str, Any]:
        value = self.payload.get(key)
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ProtocolError(f'"{self.type}" wants "{key}" as a JSON object.', frame_id=self.id)
        return value

    def optional_int(self, key: str, default: int | None = None) -> int | None:
        value = self.payload.get(key)
        if value is None:
            return default
        # bool is an int in Python and never a byte offset or a job count.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ProtocolError(f'"{self.type}" wants "{key}" as a whole number.', frame_id=self.id)
        return value

    def optional_bool(self, key: str, default: bool) -> bool:
        value = self.payload.get(key)
        if value is None:
            return default
        if not isinstance(value, bool):
            raise ProtocolError(f'"{self.type}" wants "{key}" as true or false.', frame_id=self.id)
        return value

    def optional_str_list(self, key: str) -> list[str]:
        value = self.payload.get(key, [])
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ProtocolError(
                f'"{self.type}" wants "{key}" as a list of strings.', frame_id=self.id
            )
        return list(value)


def decode(raw: str) -> Command:
    """Turn one text frame into a :class:`Command`, or refuse it.

    The only place where untrusted text becomes a command; everything
    downstream may assume a well-formed frame with a dictionary payload.
    """
    try:
        data = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise ProtocolError(f"This frame is not valid JSON: {exc}.") from exc

    if not isinstance(data, dict):
        raise ProtocolError("A frame must be a JSON object with id, type and payload.")

    frame_id = data.get("id")
    if frame_id is not None and not isinstance(frame_id, str | int):
        raise ProtocolError('"id" must be a string or a number.', frame_id=None)

    command_type = data.get("type")
    if not isinstance(command_type, str) or not command_type:
        raise ProtocolError('A frame needs a "type" naming the command.', frame_id=frame_id)

    payload = data.get("payload", {})
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ProtocolError('"payload" must be a JSON object.', frame_id=frame_id)

    return Command(id=frame_id, type=command_type, payload=payload)


def result_frame(frame_id: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return {"id": frame_id, "type": TYPE_RESULT, "payload": payload}


def error_frame(frame_id: Any, code: str, message: str, **detail: Any) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if detail:
        error.update(detail)
    return {"id": frame_id, "type": TYPE_ERROR, "error": error}


def event_frame(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"type": TYPE_EVENT, "event": name, "payload": payload}


def job_state_event(job: dict[str, Any]) -> dict[str, Any]:
    """``job_state_changed`` — the whole job record, not just the state.

    A client that missed an earlier transition should not have to
    reconstruct one from a sequence of deltas, and the record is small.
    """
    return event_frame(EVENT_JOB_STATE_CHANGED, {"job": job})


def job_output_event(job_id: str, offset: int, text: str) -> dict[str, Any]:
    """``job_output`` — one piece of build log, with the offset it starts at.

    The offset is what makes a gap detectable: a client whose events were
    dropped because it fell behind sees the next ``offset`` skip past its
    own end and repairs itself with ``follow_job`` instead of showing a
    log with a silent hole in it (ADR 0006 decision 6).
    """
    return event_frame(EVENT_JOB_OUTPUT, {"job_id": job_id, "offset": offset, "text": text})


def encode(frame: dict[str, Any]) -> str:
    """Serialize a frame. Deterministic, so tests can compare text."""
    return json.dumps(frame, ensure_ascii=False, separators=(",", ":"))
