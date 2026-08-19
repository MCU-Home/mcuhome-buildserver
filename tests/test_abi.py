# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The invocation ABI, the event stream and the reason table, up close.

The wire-level tests in ``test_backend.py`` exercise these through a
whole session. What is here is what a session cannot easily produce: a
result document that contradicts its own exit code, an event line of
nine kilobytes, an artifact entry missing one of its four mandatory
fields. Those are the cases contract v1 spends its length on, and they
are cheapest to state directly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcuhome_buildserver import abi, errors, events

# --------------------------------------------------------------------------
# Writing a request document
# --------------------------------------------------------------------------


def test_the_request_document_is_written_atomically_and_as_utf8(
    tmp_path: Path, monkeypatch
) -> None:
    """A half-written document is the one error that has no result path.

    §5.1 step 4: parsing the request document "is the **only**
    program-caused error that cannot produce a result document — and
    precisely the case in which the program does not know where a result
    would go".

    **The mechanism is what is asserted, not the leftovers.** "No
    ``request.json.tmp`` afterwards" is equally true of a plain in-place
    write with no temporary file, no rename and no directory fsync — so
    it said nothing about the word in this test's name. What makes the
    write atomic is the rename of a fully written neighbour, and that is
    what is checked.
    """
    target = tmp_path / "request.json"
    renames: list[tuple[str, str]] = []
    original = Path.replace

    def record(self, other):
        renames.append((str(self), str(other)))
        return original(self, other)

    monkeypatch.setattr(Path, "replace", record)
    abi.write_request({"request": 1, "result": "/x/result.json"}, target)

    assert renames == [(str(tmp_path / "request.json.tmp"), str(target))]
    raw = target.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert json.loads(raw.decode("utf-8"))["request"] == 1
    assert not (tmp_path / "request.json.tmp").exists()


# --------------------------------------------------------------------------
# The result document
# --------------------------------------------------------------------------


def _result(tmp_path: Path, document: dict | None, **kwargs) -> abi.InvocationOutcome:
    path = tmp_path / "result.json"
    if document is not None:
        path.write_text(json.dumps(document))
    arguments = dict(action="build", exit_code=0, session="s-1", context_id="sha256:" + "1" * 64)
    arguments.update(kwargs)
    return abi.read_result(path=path, **arguments)


def _success(**overrides) -> dict:
    document = {
        "result": 1,
        "status": "success",
        "action": "build",
        "session": "s-1",
        "reason": None,
        "error": None,
        "context": "sha256:" + "1" * 64,
        "layers": {},
        "artifacts": [],
    }
    document.update(overrides)
    return document


def test_a_missing_result_document_is_a_failed_invocation_by_definition(tmp_path: Path) -> None:
    """§9.1, in as many words: "an ``out`` directory without a result
    document at ``result`` is a failed invocation by definition"."""
    outcome = _result(tmp_path, None, exit_code=137)
    assert not outcome.successful
    assert outcome.result is None
    assert outcome.status == "failure"


def test_every_echo_field_the_request_supplied_must_echo_back(tmp_path: Path) -> None:
    """§5.3's third condition, and §5.4's echo rule behind it.

    A program echoes what it was given and only that. For a working
    action §5.2 makes ``session`` mandatory, so a result that echoes a
    different one is answering about something else.
    """
    wrong_action = _result(tmp_path, _success(action="verify"))
    assert not wrong_action.successful
    wrong_session = _result(tmp_path, _success(session="s-2"))
    assert not wrong_session.successful


def test_a_result_version_this_server_does_not_implement_is_not_a_success(
    tmp_path: Path,
) -> None:
    """§5.3's first condition. §7.1.1 calls ``program.result`` "the
    advance notice of that, not a second channel for it"."""
    outcome = _result(tmp_path, _success(result=2))
    assert not outcome.successful
    assert any("result format version" in problem for problem in outcome.problems)


def test_the_context_id_is_compared_against_the_one_this_server_computed(
    tmp_path: Path,
) -> None:
    """§5.4: ``context`` "exists **for comparison only**: attribution
    always uses the backend's own independently computed ID"."""
    outcome = _result(tmp_path, _success(context="sha256:" + "9" * 64))
    assert not outcome.successful
    assert any("context id" in problem for problem in outcome.problems)


def test_a_cancelled_result_carries_neither_reason_nor_error(tmp_path: Path) -> None:
    """§5.4: it is "the only status other than ``success`` for which the
    two are null rather than mandatory" — ``status: "cancelled"`` already
    says everything there is to say."""
    clean = _result(
        tmp_path,
        {
            "result": 1,
            "status": "cancelled",
            "action": "build",
            "session": "s-1",
            "reason": None,
            "error": None,
        },
        exit_code=1,
    )
    assert clean.status == "cancelled"
    assert not any("carries a reason" in problem for problem in clean.problems)

    classified = _result(
        tmp_path,
        {
            "result": 1,
            "status": "cancelled",
            "action": "build",
            "session": "s-1",
            "reason": "error.build.failed",
            "error": {"retryable": False, "message": "", "details": {}},
        },
        exit_code=1,
    )
    assert any("carries a reason" in problem for problem in classified.problems)


def test_a_verify_may_not_report_layers(tmp_path: Path) -> None:
    """§5.4: forbidden, "for the same reason ``context`` is forbidden for
    ``describe``: it reports work that was actually done, and ``verify``
    does not do that work"."""
    outcome = _result(
        tmp_path,
        {
            "result": 1,
            "status": "success",
            "action": "verify",
            "session": "s-1",
            "context": "sha256:" + "1" * 64,
            "layers": {"zephyr": {"patchset": "sha256:" + "e" * 64}},
        },
        action="verify",
    )
    assert not outcome.successful
    assert any("layers block" in problem for problem in outcome.problems)


@pytest.mark.parametrize(
    ("what", "action", "document", "fragment"),
    [
        (
            "no status",
            "build",
            {"result": 1, "action": "build", "session": "s-1"},
            "carries no status",
        ),
        (
            "no action",
            "build",
            {"result": 1, "status": "success", "session": "s-1"},
            "carries no action",
        ),
        (
            "a failure with no reason",
            "build",
            {
                "result": 1,
                "status": "failure",
                "action": "build",
                "session": "s-1",
                "reason": None,
                "error": {"retryable": False, "message": "no", "details": {}},
            },
            "carries no reason",
        ),
        (
            "a failure with no error object",
            "build",
            {
                "result": 1,
                "status": "failure",
                "action": "build",
                "session": "s-1",
                "reason": "error.build.failed",
                "error": None,
            },
            "carries no error object",
        ),
        (
            "an unsupported with no reason",
            "build",
            {
                "result": 1,
                "status": "unsupported",
                "action": "build",
                "session": "s-1",
                "error": {"retryable": False, "message": "no", "details": {}},
            },
            "carries no reason",
        ),
        (
            "a successful verify with no context",
            "verify",
            {"result": 1, "status": "success", "action": "verify", "session": "s-1"},
            "carries no context id",
        ),
        (
            "a successful build with no artifacts list",
            "build",
            {
                "result": 1,
                "status": "success",
                "action": "build",
                "session": "s-1",
                "context": "sha256:" + "1" * 64,
                "layers": {},
            },
            "declares no artifacts",
        ),
        (
            "a successful build with no layers block",
            "build",
            {
                "result": 1,
                "status": "success",
                "action": "build",
                "session": "s-1",
                "context": "sha256:" + "1" * 64,
                "artifacts": [],
            },
            "carries no layers block",
        ),
        (
            "a describe with no program block",
            "describe",
            {"result": 1, "status": "success", "action": "describe"},
            "carries no program block",
        ),
        (
            "a describe that reports a context",
            "describe",
            {
                "result": 1,
                "status": "success",
                "action": "describe",
                "program": {},
                "context": "sha256:" + "1" * 64,
            },
            "which it cannot have measured",
        ),
    ],
)
def test_every_row_of_the_per_action_mandatory_table_is_checked(
    tmp_path: Path, what: str, action: str, document: dict, fragment: str
) -> None:
    """§5.4's table is §5.3's second success condition, row by row.

    Both directions of it, because both are the image saying something
    untrue about what it did: a field that MUST be there and is not, and
    a field that MUST NOT be there and is. ``context`` in a ``describe``
    is the second kind — ``describe`` "never touches a context — it is
    not even guaranteed to have been given one", so a value there is one
    the program could not have measured.
    """
    outcome = _result(
        tmp_path, document, action=action, session="s-1", exit_code=None, context_id=None
    )
    assert not outcome.successful, what
    assert any(fragment in problem for problem in outcome.problems), (what, outcome.problems)


def test_the_layers_block_is_compared_against_the_patch_set_the_backend_derived(
    tmp_path: Path,
) -> None:
    """§5.4: ``layers`` is mandatory "for every patched layer", and "the
    backend compares the block against what it expects to have been
    applied".

    Checking only that it is a dict accepts ``layers: {}`` from a build
    on a context full of patches — a build that either did not apply
    them or did not say so, and the two are indistinguishable by
    omission, which is exactly what the row exists to prevent. The
    mirror direction is the same statement: the block "reports work that
    was actually done", so an entry for a layer the context does not
    patch reports work there was none of.
    """
    silent = _result(tmp_path, _success(layers={}), patched_layers=("zephyr",))
    assert not silent.successful
    assert any('no layers entry for "zephyr"' in problem for problem in silent.problems)

    invented = _result(
        tmp_path,
        _success(layers={"chip": {"patchset": "sha256:" + "e" * 64}}),
        patched_layers=(),
    )
    assert not invented.successful
    assert any("does not patch" in problem for problem in invented.problems)

    honest = _result(
        tmp_path,
        _success(layers={"zephyr": {"patchset": "sha256:" + "e" * 64}}),
        patched_layers=("zephyr",),
    )
    assert honest.successful


@pytest.mark.parametrize(
    ("exit_code", "status", "expected"),
    [
        (0, "failure", "exited 0"),
        (1, "success", "exited 1"),
        (2, "success", "outside the frozen set"),
    ],
)
def test_a_contradiction_between_exit_code_and_document_is_a_violation(
    tmp_path: Path, exit_code: int, status: str, expected: str
) -> None:
    """§5.3: "the pessimistic reading wins **and** a contract violation is
    raised against the image".

    The third case is not a contradiction but a statement about the
    image all the same: anything but 0, 1 and 66 means the program died,
    which is "undefined forever".
    """
    document = _success(status=status)
    if status != "success":
        document["reason"] = "error.build.failed"
        document["error"] = {"retryable": False, "message": "no", "details": {}}
    outcome = _result(tmp_path, document, exit_code=exit_code)
    assert not outcome.successful
    assert expected in (outcome.violation or "")


def test_an_incomplete_program_block_is_a_violation_and_not_discovery_data(
    tmp_path: Path,
) -> None:
    """§7.1.1: in a working result the block is optional, and "an
    incomplete one is a contract violation against the image and MUST
    NOT be used as discovery data; the backend asks ``describe``"."""
    outcome = _result(tmp_path, _success(program={"id": "org.example.builder"}))
    assert outcome.violation is not None
    assert "program block" in outcome.violation


def test_the_untrusted_message_loses_its_control_characters(tmp_path: Path) -> None:
    """§5.4.1: ``error.message`` is "the only untrusted-text field", and
    backends "MUST NOT render it raw into a context where markup or
    control characters matter"."""
    outcome = _result(
        tmp_path,
        {
            "result": 1,
            "status": "failure",
            "action": "build",
            "session": "s-1",
            "reason": "error.build.failed",
            "error": {"retryable": True, "message": "bad\x00\x1b[2Jthing", "details": {}},
        },
        exit_code=1,
    )
    assert outcome.result is not None
    assert outcome.result.error_message == "bad[2Jthing"


# --------------------------------------------------------------------------
# The event stream
# --------------------------------------------------------------------------


def test_the_reader_takes_only_complete_lines_and_resumes(tmp_path: Path) -> None:
    """The program appends while the backend reads, so a poll lands
    mid-line — and the fragment has to survive to the next one."""
    path = tmp_path / "events.ndjson"
    path.write_text('{"event": "invocation.started", "seq": 1}\n{"event": "context.che')
    reader = events.EventReader(path=path)
    assert [line["event"] for line in reader.read()] == ["invocation.started"]

    with path.open("a") as handle:
        handle.write('cked", "seq": 2, "context": "sha256:x"}\n')
    assert [line["event"] for line in reader.read()] == ["context.checked"]


def test_an_over_long_line_is_discarded_and_counted(tmp_path: Path) -> None:
    """§8: over 8192 bytes, "discarded and counted by the backend, never
    treated as an abort"."""
    path = tmp_path / "events.ndjson"
    path.write_text(
        json.dumps({"event": "x-huge", "seq": 1, "pad": "z" * 9000})
        + "\n"
        + json.dumps({"event": "invocation.finished", "seq": 2, "status": "success"})
        + "\n"
    )
    reader = events.EventReader(path=path)
    found = reader.read()
    assert [line["event"] for line in found] == ["invocation.finished"]
    assert reader.dropped == 1


def test_a_non_object_line_is_discarded_and_counted(tmp_path: Path) -> None:
    """The other half of the same sentence, and the same answer."""
    path = tmp_path / "events.ndjson"
    path.write_text('["not", "an", "object"]\nnot json at all\n{"event": "generate.written"}\n')
    reader = events.EventReader(path=path)
    assert [line["event"] for line in reader.read()] == ["generate.written"]
    assert reader.dropped == 2


@pytest.mark.parametrize(
    ("name", "relayed"),
    [
        ("invocation.started", True),
        ("x-acme.flashing", True),
        ("build.memory.region", True),
        ("Invocation.Started", False),
        ("", False),
    ],
)
def test_the_name_grammar_decides_what_can_be_relayed(name: str, relayed: bool) -> None:
    """§8: names are dotted, ``[a-z][a-z0-9.-]*``, with ``x-`` for third
    parties — and an unknown name is relayed, not dropped."""
    assert (events.event_name({"event": name, "seq": 1}) is not None) is relayed


def test_replay_starts_at_the_sequence_number_a_client_states(tmp_path: Path) -> None:
    """E46, and §8's "``seq`` is only required to be monotonic".

    The filter is ``>=`` and never "the Nth line": a dropped event
    leaves a gap, and §8 says the gap is harmless.
    """
    path = tmp_path / "events.ndjson"
    path.write_text(
        "".join(
            json.dumps({"event": "build.image.started", "seq": seq}) + "\n" for seq in (1, 2, 5, 9)
        )
    )
    assert [line["seq"] for line in events.replay(path, from_seq=3)] == [5, 9]
    assert [line["seq"] for line in events.replay(path, from_seq=1)] == [1, 2, 5, 9]


# --------------------------------------------------------------------------
# reason -> envelope
# --------------------------------------------------------------------------


def test_every_reason_contract_v1_defines_has_a_mapping() -> None:
    """The table is explicit and complete, and both halves are checked.

    Complete, because a reason with no row would silently take the
    unknown-value path and lose a distinction the contract drew on
    purpose; and only reasons, because a row for a value the contract
    does not define would be this server inventing one.
    """
    assert set(errors.REASON_CODES) == set(abi.REASONS)
    for code in errors.REASON_CODES.values():
        assert code in errors.REGISTRY


def test_an_unknown_reason_is_handled_as_its_status_class() -> None:
    """§11: "unknown values are handled as their class and passed
    through verbatim" — the class of a reason is failure, and a failure
    of the thing that builds is ``builder.failed``."""
    assert errors.from_reason("x-acme.tea-break") == "builder.failed"
    assert errors.from_reason(None) == "builder.failed"


def test_the_two_terminal_reasons_map_to_the_poison() -> None:
    """§6.2 and §6.3 both end with "the backend MUST refuse every further
    working action in that session", and ``session.poisoned`` is that
    refusal on the wire."""
    assert errors.REASON_CODES["error.patch.incomplete"] == "session.poisoned"
    assert errors.REASON_CODES["error.work.foreign"] == "session.poisoned"


def test_retryability_comes_from_this_registry_and_never_from_the_program() -> None:
    """§5.4.1: ``error.retryable`` is "the program's promise about its own
    failure", and a backend "MUST NOT relay it as the session protocol's
    ``retryable`` — that value is the server's, derived from the
    server's own registry precisely so the promise cannot be forged"."""
    for code in errors.REASON_CODES.values():
        envelope = errors.envelope(code, "x")
        assert envelope["retryable"] is errors.REGISTRY[code].retryable
    # And nothing a build container can say about itself is retryable
    # here: every reason it can report is a verdict on work that
    # happened. The one retryable builder code is the one the *server*
    # raises when there was no verdict at all.
    assert not any(errors.REGISTRY[code].retryable for code in errors.REASON_CODES.values())
    assert errors.REGISTRY["builder.crashed"].retryable is True
