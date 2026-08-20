# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The invocation ABI, from this server's side: the result document.

Build-container contract §5. Nothing here runs anything and nothing here
knows about sessions; this module reads the document an invocation is
answered with, and it is the only place in this server that knows that
shape.

**A working invocation's request document is not written here any more.**
It is the orchestrator's, together with the mounts, the liveness ladder
and §5.3's judgement — the same code a local build runs. What is left of
the outbound half is the two-field preamble ``describe`` takes
(:func:`write_request`), because *that* invocation is this server's own:
it is how an image proves it can be trusted with a build before any
session is admitted to it.

**Reading the result is a seven-part question, not a exit code.** §5.3:
"the backend reads the result document **if it exists**, regardless of
the exit code", and an invocation is successful exactly when all seven
conditions of :func:`read_result` hold. Where the exit code and the
document contradict each other the pessimistic reading wins *and* a
contract violation is raised against the image — which is why
:class:`InvocationOutcome` carries the violation as a value rather than
just logging it.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcuhome.model.artifacts import Artifact

__all__ = [
    "ARTIFACT_ROLES",
    "REASONS",
    "REQUEST_VERSION",
    "RESULT_VERSION",
    "ROOT_OUT",
    "STATUS_CANCELLED",
    "STATUS_FAILURE",
    "STATUS_SUCCESS",
    "STATUS_UNSUPPORTED",
    "InvocationOutcome",
    "ResultDocument",
    "TreeEntry",
    "read_result",
    "write_request",
]

#: The request format version this server writes and the result format
#: version it reads. Both are checked against ``describe``'s
#: ``program.request`` / ``program.result`` before an invocation is
#: attempted, so a mismatch is avoided rather than discovered (§7.1.1).
REQUEST_VERSION = 1
RESULT_VERSION = 1

STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_UNSUPPORTED = "unsupported"
STATUS_CANCELLED = "cancelled"

#: The three actions contract §7 defines. Named here as well as in
#: :mod:`mcuhome.buildserver.backend` because §5.4's mandatory-field
#: table is stated per action, and reading it needs the names beside it.
ACTION_DESCRIBE = "describe"
ACTION_VERIFY = "verify"
ACTION_BUILD = "build"

#: The enumerated set of §5.4. **Consumers MUST treat unknown values as
#: failure**, which is what :func:`read_result` does rather than
#: rejecting the document: an unknown status is a program saying
#: something this version does not understand, and the safe reading of
#: that is "not a success".
STATUSES = (STATUS_SUCCESS, STATUS_FAILURE, STATUS_UNSUPPORTED, STATUS_CANCELLED)

#: The one legal ``artifacts[].root`` value in v1. "A consumer that sees
#: a `root` it does not know MUST skip that artifact and MUST NOT
#: resolve it against `out`" — which is what makes a second output
#: location possible later without silent mis-resolution.
ROOT_OUT = "out"

#: The append-only role registry of §5.4. Kept for the record and
#: deliberately **not** enforced: `x-*` is reserved for third parties,
#: and "unknown values are handled as their class and passed through
#: verbatim" (§11). A role this server has never heard of is relayed,
#: not dropped.
ARTIFACT_ROLES = (
    "firmware",
    "bootloader",
    "combined",
    "symbols",
    "map",
    "report",
    "log",
)

#: The ``reason`` values contract v1 defines (twelve, plus
#: ``error.internal`` from the 2026-08-11 erratum). Listed so that the
#: envelope mapping in :mod:`mcuhome.buildserver.errors` can be checked
#: against the contract by a test rather than by reading; unknown values
#: are handled as their status class and passed through verbatim, so
#: this list is never a filter.
REASONS = (
    "unsupported.request",
    "unsupported.required",
    "unsupported.action",
    "unsupported.context",
    "error.context.incomplete",
    "error.context.unreadable",
    "error.context.mismatch",
    "error.layer.unknown",
    "error.patch.incomplete",
    "error.work.foreign",
    "error.build.failed",
    "error.deadline.exceeded",
    "error.internal",
)

#: ``artifacts[].path`` segments, §5.4. The same shape §9.2 forbids the
#: program to leave ``out``, which is what makes the egress enumeration
#: a check rather than a repair.
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._-]+\Z")

#: A bare hash in the one legal spelling of §3.3.1 — 64 lowercase hex
#: digits, no prefix. "A declared hash in any other rendering is a
#: mismatch, not a value to fold."
_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class TreeEntry:
    """One ``trees`` entry: where a layer's source tree is, and its mode.

    ``writable`` is **asserted by the backend and never probed by the
    program** (§4.1), so the flag has to be truthful: a program cannot
    reliably tell a read-only bind mount from a permission problem or a
    full disk by trying to write, and it is forbidden to try.
    """

    path: Path
    writable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"path": str(self.path), "writable": self.writable}


@dataclass
class ResultDocument:
    """The parsed result document, and what §5.4 makes of it."""

    data: dict[str, Any]

    @property
    def version(self) -> Any:
        return self.data.get("result")

    @property
    def status(self) -> str:
        found = self.data.get("status")
        # "Consumers MUST treat unknown values as `failure`" — including
        # a status that is not a string at all, which is the same
        # statement about a document this version cannot read.
        return found if found in STATUSES else STATUS_FAILURE

    @property
    def declared_status(self) -> Any:
        """What the document literally said, for the diagnosis."""
        return self.data.get("status")

    @property
    def action(self) -> Any:
        return self.data.get("action")

    @property
    def session(self) -> Any:
        return self.data.get("session")

    @property
    def reason(self) -> str | None:
        found = self.data.get("reason")
        return found if isinstance(found, str) else None

    @property
    def context(self) -> Any:
        return self.data.get("context")

    @property
    def error_message(self) -> str:
        """§5.4.1's one untrusted-text field, bounded and de-controlled.

        "``error.message`` is untrusted text, and the only untrusted-text
        field in the document: backends and clients MUST NOT render it
        raw into a context where markup or control characters matter."
        This server relays it inside a JSON envelope, where markup does
        not matter and control characters do, so the control characters
        go and the length is bounded — a program that answers a megabyte
        of message is answering a log, and the log has its own stream.
        """
        error = self.data.get("error")
        raw = error.get("message") if isinstance(error, dict) else None
        if not isinstance(raw, str):
            return ""
        cleaned = "".join(character for character in raw if character.isprintable())
        return cleaned[:_MAX_MESSAGE].strip()

    @property
    def error_details(self) -> dict[str, Any]:
        error = self.data.get("error")
        details = error.get("details") if isinstance(error, dict) else None
        return details if isinstance(details, dict) else {}

    @property
    def error_retryable(self) -> bool | None:
        """§5.4.1's ``error.retryable``, or ``None`` when it is not a bool.

        "The program's promise about its own failure, and about nothing
        else." A backend MUST NOT relay it *as* the session protocol's
        ``retryable``; carrying it under a name that says whose promise
        it is costs nothing and is the only way a client can see the
        program's own opinion at all. Anything that is not a boolean is
        no promise, so it is ``None`` rather than a coerced value.
        """
        error = self.data.get("error")
        found = error.get("retryable") if isinstance(error, dict) else None
        return found if isinstance(found, bool) else None

    @property
    def layers(self) -> dict[str, Any]:
        found = self.data.get("layers")
        return found if isinstance(found, dict) else {}

    @property
    def program(self) -> dict[str, Any]:
        found = self.data.get("program")
        return found if isinstance(found, dict) else {}


#: How much of the program's untrusted ``error.message`` this server
#: carries into an envelope. Not a contract number.
_MAX_MESSAGE = 2000


@dataclass
class InvocationOutcome:
    """What one invocation actually produced, from the backend's side.

    ``successful`` is the seven-part answer of §5.3 and nothing else;
    ``violation`` is the contract violation that §5.3 requires to be
    raised against the image where the exit code and the document
    contradict each other, carried as a value so that a caller can log
    it, relay it and refuse to trust the image without re-deriving it.
    """

    action: str
    exit_code: int | None
    result: ResultDocument | None
    successful: bool = False
    #: The reasons this invocation is not a success, in the order §5.3
    #: lists its conditions. Empty exactly when ``successful``.
    problems: tuple[str, ...] = ()
    #: A contract violation against the image, or ``None``.
    violation: str | None = None
    #: Declared artifacts that survived §9.3's egress check, with the
    #: hashes **re-read from disk**. Filled by
    #: :mod:`mcuhome.buildserver.artifacts`, not here.
    artifacts: tuple[Artifact, ...] = field(default_factory=tuple)

    @property
    def status(self) -> str:
        if self.result is None:
            return STATUS_FAILURE
        return self.result.status

    @property
    def reason(self) -> str | None:
        return None if self.result is None else self.result.reason


# --------------------------------------------------------------------------
# The request document
# --------------------------------------------------------------------------


def write_request(document: dict[str, Any], path: Path) -> None:
    """Place the request document atomically, and durably.

    §5.1 step 1 says atomically and §9.1 repeats it, for a reason that
    is visible from the program's side: the program opens ``argv[2]``
    and parses it, and a half-written document is the one program-caused
    error that cannot produce a result document — precisely the case in
    which the program does not know where a result would go. A temporary
    neighbour, an ``fsync``, a rename, and an ``fsync`` of the directory
    so that the name itself survives.

    UTF-8 without BOM, one JSON object, RFC 8259, and no ``null``
    anywhere: ``null`` never means "absent" in this document, it is
    invalid, and :func:`request_document` omits rather than nulls.
    """
    temporary = path.with_name(path.name + ".tmp")
    payload = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=False)
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


# --------------------------------------------------------------------------
# The result document
# --------------------------------------------------------------------------


def read_static_describe(text: str) -> dict[str, Any] | None:
    """The ``program`` block out of a static self-description (§2.2.1).

    The file's content is "exactly what invoking ``describe`` on this
    image answers, and nothing else" — a §5.4 result document — so it is
    read with the same expectations a live answer meets: one JSON
    object, ``status: "success"``, and a complete ``program`` block.
    ``None`` for anything less, because the caller's fallback (invoking
    ``describe``) was already mandatory and reports its own refusals;
    a half-readable file must not be a third behaviour.
    """
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("status") != "success":
        return None
    program = data.get("program")
    if not isinstance(program, dict) or not _program_block_complete(program):
        return None
    return program


def read_result(
    *,
    path: Path,
    action: str,
    exit_code: int | None,
    session: str,
    context_id: str | None,
    patched_layers: tuple[str, ...] = (),
) -> InvocationOutcome:
    """Read the result document if it exists, and judge it (§5.3).

    "The backend reads the result document **if it exists**, regardless
    of the exit code. An invocation is successful exactly when all of
    the following hold" — and the seven conditions are checked here in
    the order the contract lists them:

    1. the document parses and names an implemented ``result`` version;
    2. it carries every field §5.4 makes mandatory for the invoked
       action;
    3. ``action`` echoes ``argv[1]``, and every echo field the request
       document actually supplied echoes correctly — for a working
       action that is ``session``, which §5.2 makes mandatory;
    4. ``status == "success"``;
    5. the observed exit code, where observed, is 0;
    6. every declared artifact exists as a regular file under its
       declared ``root`` and re-hashes to its declared value;
    7. for a working action, the backend's own context ID matches
       ``result.context``.

    Condition 6 is deliberately **not** here: it is egress (§9.3), it
    needs the filesystem, and it lives in
    :mod:`mcuhome.buildserver.artifacts`. What this function answers is
    everything the document alone can settle, and the caller adds the
    sixth before calling the invocation successful.

    *context_id* is the id **this server computed itself**. Attribution
    always uses it; ``result.context`` exists for comparison only, and
    the comparison is what condition 7 is.

    *patched_layers* is the set the backend derived from the context, and
    it is what makes §5.4's ``layers`` row checkable: the row reads "MUST,
    on success, **for every patched layer**", and §5.4 states the
    backend's use of it in as many words — "the backend compares the
    block against what it expects to have been applied". Without the
    derived set there is nothing to compare against and the row degrades
    into "is it a dict", which a build that applied no patch at all
    satisfies.
    """
    outcome = InvocationOutcome(action=action, exit_code=exit_code, result=None)
    problems: list[str] = []
    data = _load(path)
    if data is None:
        # No document at all. §9.1 is explicit that this is a failed
        # invocation *by definition* — "an `out` directory without a
        # result document at `result` is a failed invocation" — and it is
        # the case a resource limit that aborted the program produces.
        outcome.problems = ("no result document was written at the path the request named",)
        return outcome

    outcome.result = ResultDocument(data)
    document = outcome.result

    if document.version != RESULT_VERSION:
        problems.append(
            f"the result document names result format version {document.version!r} and "
            f"this server implements {RESULT_VERSION}"
        )
    problems.extend(_missing_mandatory(document, action, patched_layers))
    if document.action != action:
        problems.append(
            f"the result echoes action {document.action!r} for an invocation of {action!r}"
        )
    if document.session != session:
        problems.append(f"the result echoes session {document.session!r} for session {session!r}")
    if document.status != STATUS_SUCCESS:
        problems.append(f"the program reported status {document.declared_status!r}")
    if exit_code is not None and exit_code != 0:
        problems.append(f"the program exited {exit_code}")
    if (
        context_id is not None
        and document.status == STATUS_SUCCESS
        and document.context != context_id
    ):
        problems.append(
            "the context id the program computed does not match the one this server "
            f"computed ({document.context!r} against {context_id!r})"
        )

    outcome.violation = _violation(document, exit_code)
    outcome.problems = tuple(problems)
    outcome.successful = not problems
    return outcome


def _load(path: Path) -> dict[str, Any] | None:
    """The document as an object, or ``None`` if there is no usable one.

    A file that is not there, is not readable, is not JSON or is not an
    object are one answer, because they are one fact from the backend's
    side: no result could be addressed. §5.3 already has a code for
    that shape of failure and it is not the document's to name.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _missing_mandatory(
    document: ResultDocument, action: str, patched_layers: tuple[str, ...] = ()
) -> tuple[str, ...]:
    """§5.4's per-action table, as a list of what is wrong with a document.

    Both directions of the table matter, because both are checkable and
    both are the image lying about what it did. A field that MUST be
    present and is not is the obvious one. A field that MUST NOT be
    present and is, is the interesting one: ``layers`` is forbidden in a
    ``verify`` result because "it reports work that was actually done,
    and ``verify`` does not do that work", so a ``verify`` that reports
    one is claiming an application that never happened; and ``context``
    is forbidden in a ``describe`` result because ``describe`` "never
    touches a context — it is not even guaranteed to have been given
    one", so a value there is one the program could not have measured.

    The rows qualified "on success" are the ones that report *measured*
    work, and they are checked only on success for the reason the
    contract gives: "an invocation that failed before it got that far
    reports what it measured and nothing more", and fabricating either
    would be worse than omitting it.
    """
    missing: list[str] = []
    success = document.status == STATUS_SUCCESS
    working = action in (ACTION_VERIFY, ACTION_BUILD)
    if "status" not in document.data:
        missing.append("the result document carries no status")
    if "action" not in document.data:
        missing.append("the result document carries no action")
    if document.status in (STATUS_FAILURE, STATUS_UNSUPPORTED):
        if document.reason is None:
            missing.append(f"a {document.status} result carries no reason")
        if not isinstance(document.data.get("error"), dict):
            missing.append(f"a {document.status} result carries no error object")
    # "A `cancelled` result carries `reason: null` and `error: null`,
    # just as a successful one does" — status cancelled already says
    # everything there is to say, so a classification beside it would be
    # a second spelling of the status.
    if document.status == STATUS_CANCELLED and (
        document.data.get("reason") is not None or document.data.get("error") is not None
    ):
        missing.append("a cancelled result carries a reason or an error, and carries neither")
    if working and success and "context" not in document.data:
        missing.append(f"a successful {action} carries no context id")
    if action == ACTION_BUILD and success:
        if not isinstance(document.data.get("artifacts"), list):
            missing.append("a successful build declares no artifacts, and an absent list is empty")
        if not isinstance(document.data.get("layers"), dict):
            missing.append("a successful build carries no layers block")
        else:
            missing.extend(_layer_problems(document.layers, patched_layers))
    if action == ACTION_VERIFY and "layers" in document.data:
        missing.append("a verify result carries a layers block, which verify may not report")
    if action == ACTION_DESCRIBE:
        # `program` is mandatory unconditionally here — including on a
        # failed describe, which is the case the block exists for: a
        # describe refused with `unsupported.request` is refused because
        # the backend sent a version this program does not parse, and
        # `program.request` is the field that says which to send instead.
        if not isinstance(document.data.get("program"), dict):
            missing.append("a describe result carries no program block")
        forbidden = [name for name in ("context", "artifacts", "layers") if name in document.data]
        if forbidden:
            missing.append(
                f"a describe result carries {', '.join(forbidden)}, which it cannot have measured"
            )
    return tuple(missing)


def _layer_problems(layers: dict[str, Any], patched: tuple[str, ...]) -> tuple[str, ...]:
    """``layers`` against the patch set the backend derived (§5.4).

    Both directions again, and both are the image saying something about
    work rather than reporting it. A patched layer with no entry is a
    build that either did not apply those patches or did not say it did,
    and §5.4 makes the row mandatory "for every patched layer" precisely
    so the two cannot be told apart by omission. An entry for a layer the
    context does not patch is the mirror image: the block "reports work
    that was actually done", and there was no work to report for a layer
    with no ``patches/<layer>/`` in the context.
    """
    problems: list[str] = []
    for layer in patched:
        if layer not in layers:
            problems.append(
                f'a successful build reports no layers entry for "{layer}", whose patches '
                "the context carries"
            )
    for layer in sorted(layers):
        if layer not in patched:
            problems.append(
                f'a successful build reports a layers entry for "{layer}", which this '
                "context does not patch"
            )
    return tuple(problems)


def _violation(document: ResultDocument, exit_code: int | None) -> str | None:
    """The contract violation §5.3 raises against the image, if any.

    "Where exit code and document contradict each other, the pessimistic
    reading wins **and** a contract violation is raised against the
    image." The contradictions are enumerable: exit 0 with a status that
    is not ``success``, a non-zero exit with ``status: "success"``, and
    an exit code outside the frozen set — anything but 0, 1 and 66 means
    the program died, which is undefined forever and is a statement
    about the image rather than about the build.

    A ``program`` block that is present and incomplete is the other one
    (§7.1.1): in a ``verify`` or ``build`` result the whole block is
    optional, and an incomplete one "is a contract violation against the
    image and MUST NOT be used as discovery data".
    """
    if exit_code is not None and exit_code not in (0, 1, 66):
        return f"the program exited {exit_code}, which is outside the frozen set 0, 1 and 66"
    if exit_code == 0 and document.status != STATUS_SUCCESS:
        return f"the program exited 0 and its result says {document.declared_status!r}"
    if exit_code == 1 and document.status == STATUS_SUCCESS:
        return "the program exited 1 and its result says success"
    if exit_code == 66 and document.data:
        return "the program exited 66, which means no result could be addressed, and wrote one"
    if document.program and not _program_block_complete(document.program):
        return "the result carries an incomplete program block, which is not discovery data"
    return None


#: Every field §7.1.1 makes mandatory inside a ``program`` block, except
#: ``trees``, which is mandatory only in a ``describe`` result.
PROGRAM_FIELDS = ("id", "version", "contract", "request", "result", "actions")


def _program_block_complete(program: dict[str, Any]) -> bool:
    return all(field_name in program for field_name in PROGRAM_FIELDS)
