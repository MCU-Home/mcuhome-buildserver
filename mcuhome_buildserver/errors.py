# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The session protocol's error envelope and its typed code registry.

Session protocol v2 answers every refusal with one **fixed envelope**::

    {"code":      "version.protocol-mismatch",  # from the registry below
     "layer":     "version",                    # the code's dotted prefix
     "retryable": false,                        # authoritative, never inferred
     "message":   "…",                          # for a human
     "details":   {"server": 2, "client": 3}}   # structured, code-specific

``retryable`` is the server's promise, not the client's guess: a client
never derives retryability from the code or the message. A client that
receives a code it does not know treats it as **non-retryable fatal**
and surfaces the message — which is what lets this registry grow without
breaking anyone.

**The registry is append-only.** A code, once released, is never
renamed, never removed and never re-classified to a different
``retryable``; fixing a bad name means adding a new code and letting the
old one age out of use. Codes are dotted, and the first segment is the
``layer`` — one of :data:`LAYERS`. The ``x-`` prefix is reserved for
third-party builder containers and is deliberately not registered here:
an ``x-*`` code passes through with whatever the third party declared,
under the unknown-code rule above.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "LAYERS",
    "REGISTRY",
    "ErrorCode",
    "SessionError",
    "envelope",
]

#: The namespaces (envelope ``layer`` values) the registry may use.
#: Fixed by the protocol concept; ``x-`` is reserved for third parties.
LAYERS = ("policy", "session", "context", "version", "builder")


@dataclass(frozen=True)
class ErrorCode:
    """One registered code: its identity, its retryability, its meaning."""

    code: str
    retryable: bool
    #: What the code means, for this file's reader; the wire carries a
    #: per-occurrence ``message`` instead.
    summary: str

    @property
    def layer(self) -> str:
        return self.code.partition(".")[0]


def _seed(*codes: ErrorCode) -> dict[str, ErrorCode]:
    registry: dict[str, ErrorCode] = {}
    for entry in codes:
        layer, dot, rest = entry.code.partition(".")
        if layer not in LAYERS or not dot or not rest:
            raise ValueError(f"{entry.code!r} is not a dotted code in a known layer")
        if entry.code in registry:
            raise ValueError(f"{entry.code!r} is registered twice")
        registry[entry.code] = entry
    return registry


#: Every code this server may answer with. **Append-only** — see the
#: module docstring; new codes go at the end of their layer's block.
REGISTRY: dict[str, ErrorCode] = _seed(
    # policy.* — the server's builder configuration said no.
    ErrorCode(
        "policy.patch-layer-denied",
        retryable=False,
        summary="the context carries patches for a layer this server's config does not allow",
    ),
    ErrorCode(
        "policy.quota-exceeded",
        retryable=True,
        summary="a per-session or rolling per-user budget (work, disk, sessions) is exhausted",
    ),
    ErrorCode(
        "policy.ingress-limit-exceeded",
        retryable=False,
        summary="an upload exceeded an ingress cap (size, entry count, depth), enforced streaming",
    ),
    # session.* — the session machinery.
    ErrorCode(
        "session.unknown",
        retryable=False,
        summary="no session with this id exists on this server",
    ),
    ErrorCode(
        "session.expired",
        retryable=False,
        summary="the session's lease or hard TTL ran out and it was reaped",
    ),
    ErrorCode(
        "session.closed",
        retryable=False,
        summary="the session was closed and this verb needs an open one",
    ),
    ErrorCode(
        "session.limit-exceeded",
        retryable=True,
        summary="the per-user concurrent-session quota is reached",
    ),
    ErrorCode(
        "session.profile-unknown",
        retryable=False,
        summary="open-session named a profile this server does not have",
    ),
    ErrorCode(
        "session.profile-violation",
        retryable=False,
        summary="the command is outside the session's declared profile",
    ),
    ErrorCode(
        "session.manifest-immutable",
        retryable=False,
        summary="the manifest may not change during a session; a changed manifest is a new session",
    ),
    ErrorCode(
        "session.not-implemented",
        retryable=False,
        summary="the verb is part of the protocol and its server logic is not built yet",
    ),
    # context.* — the build context and its integrity.
    ErrorCode(
        "context.missing",
        retryable=False,
        summary="the command needs a context and send-context has not happened",
    ),
    ErrorCode(
        "context.integrity-mismatch",
        retryable=False,
        summary="a recomputed file hash or the context id disagrees with the received bytes",
    ),
    ErrorCode(
        "context.unsafe-entry",
        retryable=False,
        summary="extraction refused an entry: absolute path, .., link, device, or outside "
        "the whitelisted subtrees",
    ),
    # version.* — the negotiation.
    ErrorCode(
        "version.protocol-mismatch",
        retryable=False,
        summary="the client speaks a session protocol version this server does not",
    ),
    ErrorCode(
        "version.context-format-unsupported",
        retryable=False,
        summary="the context manifest format version is outside this server's supported range",
    ),
    ErrorCode(
        "version.verb-unknown",
        retryable=False,
        summary="the frame named a verb outside this server's vocabulary; details list "
        "the known ones",
    ),
    ErrorCode(
        "version.builder-unavailable",
        retryable=False,
        summary="no builder image on this server satisfies the manifest's container pin",
    ),
    # builder.* — the builder container contract.
    ErrorCode(
        "builder.command-unsupported",
        retryable=False,
        summary="the builder container answered reserved exit code 64: unsupported command",
    ),
    ErrorCode(
        "builder.parameter-unsupported",
        retryable=False,
        summary="the builder container answered reserved exit code 65: unsupported "
        "required parameter",
    ),
    ErrorCode(
        "builder.failed",
        retryable=False,
        summary="the build ran and failed; the log stream has the compiler's answer",
    ),
    ErrorCode(
        "builder.crashed",
        retryable=True,
        summary="the builder container died without a result document — an infrastructure "
        "failure, not a verdict on the context",
    ),
)


def envelope(code: str, message: str, **details: Any) -> dict[str, Any]:
    """The fixed error envelope for *code*, filled from the registry.

    An unregistered code is a bug on this side and raises: the registry
    is what makes ``retryable`` authoritative, and inventing an envelope
    for a code nobody registered would silently break that promise.
    """
    try:
        entry = REGISTRY[code]
    except KeyError:
        raise ValueError(f"{code!r} is not in the error-code registry") from None
    return {
        "code": entry.code,
        "layer": entry.layer,
        "retryable": entry.retryable,
        "message": message,
        "details": details,
    }


class SessionError(Exception):
    """A session-protocol refusal, carrying its full envelope.

    Raised inside a verb handler and turned into an error frame by the
    ``/ws`` command loop; the frame id is the loop's to know, so it is
    not carried here.
    """

    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self._envelope = envelope(code, message, **details)
        self.code = code
        self.message = message
        self.details = details

    def to_envelope(self) -> dict[str, Any]:
        return dict(self._envelope)
