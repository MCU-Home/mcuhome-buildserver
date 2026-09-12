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
third-party build environments and is deliberately not registered here:
an ``x-*`` code passes through with whatever the third party declared,
under the unknown-code rule above.

**Append-only starts at the first published entry**, and nothing here
has been published: this package is ``0.1.0.dev0``, no release exists
and no client is implemented against it. That window is the only reason
``session.manifest-immutable`` could be *taken out* rather than left to
age — the rule it encoded was replaced outright (see
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
#:
#: **Two joined on 2026-08-10, with the container backend**, and both
#: name a thing the six could not. ``sdk`` is the one external input the
#: backend fetches and hash-verifies on a client's behalf — not a policy,
#: not a version negotiation and not the builder, which is the thing that
#: consumes it. ``artifact`` is what
#: ``get-artifact`` addresses beside an invocation id: a path that is
#: not a declared artifact is a statement about the artifact and not
#: about the invocation, which exists and answered.
LAYERS = ("policy", "session", "context", "version", "builder", "invocation", "sdk", "artifact")


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
    ErrorCode(
        "policy.environment-denied",
        retryable=False,
        summary="the context pins a build environment from a repository this server does not run",
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
        # The counterpart to the one above, and the difference is a
        # promise: `session.limit-exceeded` hands out a seat token and
        # is therefore an undertaking to serve this caller in its turn,
        # while this one refuses without making that promise and says
        # why in `details.reason`. Today the only reason is a full
        # waiting room; the one that follows is a per-client seat quota,
        # which needs an identity this server does not have yet.
        "session.no-seat",
        retryable=True,
        summary="admission refused and no waiting turn was issued",
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
        summary="the command needs a context, or a file inside one, that this session does "
        "not have: send-context has not happened, or the context carries no keys/signing.pub",
    ),
    ErrorCode(
        "context.integrity-mismatch",
        retryable=False,
        summary="a recomputed file hash or the context id disagrees with the received bytes, "
        "or the serving build environment could not read the manifest this server wrote",
    ),
    # The summary was widened on 2026-08-10 to name the type collision —
    # one path that has to be a file and a directory at once, in one
    # archive or between an extension and the context it lands in. The
    # code is unchanged and no new one was added: the entry has always
    # been "extraction refused this target", a path that cannot be both
    # is one, and a second code would have split one meaning in two. What
    # makes amending a *summary* legitimate at all is the pre-release
    # window this module's docstring describes — append-only starts at
    # the first published entry, and nothing here has been published.
    ErrorCode(
        "context.unsafe-entry",
        retryable=False,
        summary="extraction refused an entry: absolute path, .., link, device, a name the "
        "filesystem cannot hold, a path claimed as a file and as a directory at once, or "
        "outside the whitelisted subtrees",
    ),
    # The two codes the explicit freeze verb exists to produce. They
    # replace `session.manifest-immutable`, whose rule — "manifest.yaml
    # is immutable for the session's lifetime" — was
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
    # An extension that touches `context.yaml` needs a typed error of
    # its own, and it is deliberately NOT `context.unsafe-entry`: that
    # code is about extraction *shape* — an absolute path, a `..`, a
    # symlink — while a `context.yaml` in an
    # extension is a perfectly well-formed entry aimed at a forbidden
    # target. Telling a client its path was unsafe would send it looking
    # for the wrong mistake.
    ErrorCode(
        "context.pins-immutable",
        retryable=False,
        summary="an extension tried to write or remove context.yaml; it carries the pins "
        "the session was admitted on, and changing them is a new session",
    ),
    # A second `send-context` before the lock. Not `context.locked`
    # (nothing is frozen yet) and not an implicit replacement: the pins
    # were already accepted and answered, and replacing them mid-session
    # is the one thing the format forbids for a session's lifetime.
    ErrorCode(
        "context.exists",
        retryable=False,
        summary="a base context already arrived in this session; changes go through "
        "extend-context and a fresh start is a new session",
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
        summary="the context format version (declared in context.yaml) is outside the range "
        "this server, or the build environment serving the session, implements",
    ),
    ErrorCode(
        "version.verb-unknown",
        retryable=False,
        summary="the frame named a verb outside this server's vocabulary; details list "
        "the known ones",
    ),
    # The requirement lives in `context.yaml` and arrives with
    # `send-context`; `manifest.yaml` only exists once `lock-context` has
    # written it and repeats the requirement
    # beside the resolution this server chose for it.
    #
    # The summary was widened when the `container.digest`
    # pin was taken out of the context format: this code never meant the pin
    # specifically, it meant "the image this session would build in is
    # not one this server can invoke a build on", and both of its raisers
    # still say exactly that — an image the runtime cannot produce facts
    # for, and an image whose declared labels do not match what this session needs.
    ErrorCode(
        "version.builder-unavailable",
        retryable=False,
        summary="the build environment this session would use cannot serve it: the image is "
        "not on this host, or its labels do not match what this session needs",
    ),
    # A sibling of the entry above rather than a
    # rename of it. The two answer different questions and a client can
    # act on exactly one of them: `builder-unavailable` is about ONE
    # image — named in the details, actionable only by this server's
    # operator — while this one is about this server's whole inventory,
    # and its details name the line the context requires against the
    # lines actually served. A client reading it can pick another build
    # server, or set `zephyr_version` to a line that is offered, without
    # anyone touching this host. Folding the two would put those two
    # detail shapes under one code and lose the distinction that makes
    # either useful.
    ErrorCode(
        "version.builder-unsatisfiable",
        retryable=False,
        summary="this server does not have the build environment the context pins and will "
        "not fetch it; details name the pin and the environments available",
    ),
    ErrorCode(
        "version.builder-unfetchable",
        retryable=True,
        summary="the pinned build environment is not here and the fetch for it failed; "
        "retryable because its usual causes — no network, a registry wanting a login — "
        "come back",
    ),
    # invocation.* — one invocation of the build environment's program,
    # addressed by the server-assigned invocation id. One entry, on
    # purpose: a cancel that races a natural completion is answered
    # `already_finished` and is NOT an error — both parties behaved
    # correctly.
    ErrorCode(
        "invocation.unknown",
        retryable=False,
        summary="the session has no invocation with this id; details carry the ids it does have",
    ),
    # builder.* — the thing that builds, whatever shape it takes. The
    # spelling was settled before the first release made the registry
    # append-only: the prefix names the ROLE, not the deployment. In the
    # container profile, the build
    # environment's container is the builder; the builder is not
    # necessarily a container — in the subprocess profile a machine that
    # builds without one has no container at all, and its build
    # environment fails under exactly these codes. `builder.failed`
    # says the one thing a client needs: the thing that was building had
    # an error; what stood behind it is the session's business.
    # This is deliberately not a leftover of the retired terminology —
    # "builder" was retired as a name for the *container*, and these
    # codes never meant the container specifically.
    #
    # A build environment classifies nothing: its result document states
    # a status, a message for a human and the artifacts it wrote (build
    # environment specification §6.2), and the mapping into these codes
    # is therefore this server's own reading of that status — success,
    # failure, or "no environment of my kind can do this".
    ErrorCode(
        "builder.failed",
        retryable=False,
        summary="the build ran and failed; the log stream has the compiler's answer",
    ),
    ErrorCode(
        "builder.crashed",
        retryable=True,
        summary="the build environment died without a result document — an infrastructure "
        "failure, not a verdict on the context",
    ),
    # The third pre-start refusal of the container backend, and the one
    # that is genuinely retryable: no docker binary, or a daemon that
    # cannot be reached. Nothing about the context is wrong, the session
    # is untouched, and the same command works once the runtime is up —
    # which is exactly the promise `retryable: true` makes. A missing
    # *image* is deliberately not this code: it is
    # `version.builder-unavailable`, because a session does not silently
    # substitute another image for the one it already resolved — refetching
    # one gone missing would attribute the build to an image the manifest
    # never named, so "not on this host" is a final answer for that check.
    ErrorCode(
        "builder.runtime-unavailable",
        retryable=True,
        summary="this server cannot reach its container runtime at all — no docker binary, "
        "or a daemon that is down",
    ),
    # sdk.* — the one external input the backend fetches.
    ErrorCode(
        "sdk.unavailable",
        retryable=False,
        summary="no operator-configured source holds the SDK package this context pins, or "
        "the file found under that name does not hash to the pinned value",
    ),
    # artifact.* — what `get-artifact` addresses beside an invocation id.
    ErrorCode(
        "artifact.unknown",
        retryable=False,
        summary="the path is not a declared artifact of that invocation; details carry the "
        "paths it did declare",
    ),
    # The one genuinely new situation of the delivery re-verification:
    # the egress check ran when the invocation ended, and the bytes
    # behind a verified artifact are not those bytes any more when the
    # client asks for them. Not `artifact.unknown` — the artifact was
    # declared and was verified — and not `context.integrity-mismatch`,
    # which is about the context rather than about `out`. Not retryable:
    # a second download reads the same changed file, and what changed it
    # is inside the session's own tree.
    ErrorCode(
        "artifact.integrity-mismatch",
        retryable=False,
        summary="a declared artifact no longer is the file this server verified at egress — "
        "it was replaced, relinked or rewritten between the invocation's end and this "
        "download, and the archive is refused rather than built from it",
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
