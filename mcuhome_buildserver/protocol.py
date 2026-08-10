# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The frame envelope: the codec every verb is carried in.

One WebSocket endpoint and three kinds of frame — the same envelope the
dashboard's own API uses, because there is no reason for two shapes of
envelope in one product family::

    → {"id": "7", "type": "open-session", "payload": {...}}
    ← {"id": "7", "type": "result",       "payload": {"session": {...}}}
    ← {"id": "7", "type": "error",        "error": {"code": "…", …}}
    ← {"type": "event", "event": "…",     "payload": {...}}

**The envelope outlived the vocabulary it was built for.** It carried
the one-shot job protocol of dashboard ADR 0006; that protocol was
dismantled rather than migrated, and dashboard ADR 0012 decision 3
keeps exactly this — the frame envelope, the transport under it and the
bearer token in front of it — while the verbs inside became the session
protocol of :mod:`mcuhome_buildserver.sessions`.

**Why this module is a sibling of** ``mcuhome_dashboard.protocol``
**rather than an import of it.** The dashboard and the build server are
separate products with separate version numbers (ADR 0003 decision 1),
and the build server is routinely installed where the dashboard is not —
a workstation under a desk, a NAS, a WSL instance. Importing the
dashboard's package here would make the fat half undeployable without
the thin half, which is exactly the coupling ADR 0003 spent its length
avoiding.

What must not drift is the *envelope*, and that is guarded rather than
assumed: ``tests/test_protocol.py`` compares this module's constants
against ``mcuhome_dashboard.protocol`` whenever both packages are
importable. A rename on one side fails a test on the other instead of
producing two servers that almost agree.

**Errors come in two vocabularies, and the difference is which layer
failed.** A frame that parsed and named a verb is answered from the
typed registry in :mod:`mcuhome_buildserver.errors` — dotted code,
authoritative ``retryable``, structured details. The two constants
below are for the frames that never got that far, and they are the
whole reason this module still defines any error code at all.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ERROR_BAD_REQUEST",
    "ERROR_INTERNAL",
    "TYPE_ERROR",
    "TYPE_EVENT",
    "TYPE_LOG",
    "TYPE_RESULT",
    "Command",
    "ProtocolError",
    "decode",
    "encode",
    "error_frame",
    "event_frame",
    "log_frame",
    "result_frame",
]

TYPE_RESULT = "result"
TYPE_ERROR = "error"
TYPE_EVENT = "event"

#: The raw build log, as its **own** frame type (E46). It is a separate
#: kind rather than an event with a name because contract §8 makes the
#: two different things: events are a typed, registered, append-only
#: vocabulary that a consumer matches on, while "standard output and
#: standard error together are one raw, opaque log stream" that
#: consumers "MUST NOT parse for machine decisions". Carrying the log as
#: an event would have put an unparseable stream into the one channel
#: that exists to be parsed.
TYPE_LOG = "log"

#: The frame was not understood: malformed JSON, missing fields, wrong
#: types, a binary message on a text endpoint. Always the client's
#: fault, and necessarily *pre*-registry: the typed codes of
#: :mod:`mcuhome_buildserver.errors` describe a session's refusals, and
#: a frame that did not parse has no session and no verb to attribute
#: the refusal to. Adding a registry code for it is a protocol decision
#: — the layer set is fixed by the concept — so this constant stays
#: until that decision is taken, rather than being replaced by a guess.
ERROR_BAD_REQUEST = "bad_request"
#: A bug on this side, from the command loop's catch-all. Carries no
#: traceback; the log has it. Pre-registry for the same reason: an
#: unexpected exception is not a verdict any layer of the protocol
#: claims to render.
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
        # bool is an int in Python and never a version or a byte offset.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ProtocolError(f'"{self.type}" wants "{key}" as a whole number.', frame_id=self.id)
        return value


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


def log_frame(payload: dict[str, Any]) -> dict[str, Any]:
    """One line of an invocation's raw log, with its own counter.

    The counter is server-assigned and monotonic per invocation, and it
    is what makes the outbox's drop-the-oldest policy safe for this
    stream: a client that sees the numbers jump knows it lost lines
    rather than believing it read a complete log with a silent hole in
    it. There is deliberately no replay behind it — the events file is
    the replay buffer (E46) and the log is not written to disk by this
    server at all.
    """
    return {"type": TYPE_LOG, "payload": payload}


def encode(frame: dict[str, Any]) -> str:
    """Serialize a frame. Deterministic, so tests can compare text."""
    return json.dumps(frame, ensure_ascii=False, separators=(",", ":"))
