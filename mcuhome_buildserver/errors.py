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
third-party build containers and is deliberately not registered here:
an ``x-*`` code passes through with whatever the third party declared,
under the unknown-code rule above.

**Append-only starts at the first published entry**, and nothing here
has been published: this package is ``0.1.0.dev0``, no release exists
and no client is implemented against it. ADR 0019's amendment says as
much of the protocol's own registry, and that window is the only reason
``session.manifest-immutable`` could be *taken out* rather than left to
age — ADR 0019's amendment replaced the rule it encoded outright (see
the ``context.*`` block, which has the two codes that replaced it). The
window closes at the first release; after that a wrong entry can only be
superseded, never removed.
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
    # policy.* — the server's own configuration said no.
    ErrorCode(
        "policy.patch-layer-denied",
        retryable=False,
        summary="the context carries patches for a layer this server's config does not allow",
    ),
    ErrorCode(
        "policy.quota-exceeded",
        retryable=True,
        summary="a per-server budget (disk, sessions) is exhausted",
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
        summary="this server's concurrent-session limit is reached",
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
        "session.not-implemented",
        retryable=False,
        summary="the verb is part of the protocol and its server logic is not built yet",
    ),
    # context.* — the build context, its lifetime and its integrity.
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
    # The two codes the explicit freeze verb exists to produce. They
    # replace `session.manifest-immutable`, whose rule — "manifest.yaml
    # is immutable for the session's lifetime" — ADR 0019's amendment
    # replaced rather than kept: before the lock there is no manifest at
    # all, `context.yaml` is what may not change, and after the lock the
    # context is closed to writes entirely. The old code was unreachable
    # under that arrangement from both ends at once.
    ErrorCode(
        "context.locked",
        retryable=False,
        summary="a writing command arrived after lock-context; the lock is one-way and "
        "adding to a locked context is a new session",
    ),
    ErrorCode(
        "context.not-locked",
        retryable=False,
        summary="a working command arrived before lock-context; verify and build run only "
        "from the lock onwards",
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
        summary="the context format version (declared in context.yaml) is outside this "
        "server's supported range",
    ),
    ErrorCode(
        "version.verb-unknown",
        retryable=False,
        summary="the frame named a verb outside this server's vocabulary; details list "
        "the known ones",
    ),
    # The pin lives in `context.yaml` and arrives with `send-context`;
    # `manifest.yaml` only exists once `lock-context` has written it and
    # merely repeats the pin (ADR 0018's amendment).
    ErrorCode(
        "version.builder-unavailable",
        retryable=False,
        summary="no build container on this server satisfies the context's container.digest pin",
    ),
    # builder.* — the thing that builds, whatever shape it takes. The
    # spelling was settled by the product owner on 2026-08-09, before the
    # first release made the registry append-only: the prefix names the
    # ROLE, not the deployment. The build container is the builder here,
    # but the builder is not necessarily the build container — in the
    # subprocess profile there is no container at all, and its build
    # environment fails under exactly these codes. `builder.failed` says
    # the one thing a client needs: the thing that was building had an
    # error; which profile stood behind it is the session's business.
    # This is deliberately not a leftover of the retired terminology —
    # "builder" was retired as a name for the *container*, and these
    # codes never meant the container specifically.
    #
    # Two entries are gone from this block: `builder.command-unsupported`
    # and `builder.parameter-unsupported` were defined by reserved exit
    # codes 64 and 65, which ADR 0019's amendment drops by name — they are
    # EX_USAGE and EX_DATAERR, which foreign runtimes emit for ordinary
    # argument errors, so a Go program returning 64 on a typo would have
    # been read as "command not supported". What carries that meaning now
    # is the result document's `reason` (`unsupported.action`,
    # `unsupported.required`), read whenever a result document exists
    # regardless of exit code. How a backend maps `reason` into this
    # envelope is the backend's business rather than contract text, so
    # the codes for it are registered when there is a backend to raise
    # them, not now.
    ErrorCode(
        "builder.failed",
        retryable=False,
        summary="the build ran and failed; the log stream has the compiler's answer",
    ),
    ErrorCode(
        "builder.crashed",
        retryable=True,
        summary="the build container died without a result document — an infrastructure "
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
