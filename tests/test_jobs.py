# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The job engine: the lane, the record, restart recovery and retention.

Every build here is :mod:`tests.conftest`'s fake builder. What is being
tested is the engine around a process, not a compiler.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from mcuhome_buildserver.jobs import Job, JobOptions, JobState, JobStore, new_job_id
from tests.conftest import MODEL, PUBLIC_KEY, auth, call, submit_payload, wait_for_state


async def test_a_job_runs_and_reports_its_manifest(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "submit_job", submit_payload())
        job_id = frame["payload"]["job_id"]
        assert frame["payload"]["job"]["state"] == "queued"
        assert frame["payload"]["job"]["device"] == "bench-node"
        assert frame["payload"]["job"]["board"] == "nrf7002dk/nrf5340/cpuapp"

        job = await wait_for_state(ws, job_id, {"succeeded", "failed"})

    assert job["state"] == "succeeded"
    assert job["exit_code"] == 0
    assert job["manifest"]["device"]["name"] == "bench-node"
    # ADR 0007 decision 3: the build server never signs, so the manifest
    # it hands back says the image is unsigned and the dashboard's own
    # signing step is not optional.
    assert job["manifest"]["signing"]["signed"] is False
    assert job["log_bytes"] > 0


async def test_the_job_record_never_carries_a_credential(client, state) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
        await wait_for_state(ws, job_id, {"succeeded", "failed"})

    record = json.loads(state.store.record_path(job_id).read_text(encoding="utf-8"))
    passcode = str(MODEL["network"]["pairing"]["passcode"])
    assert passcode not in json.dumps(record)
    # And not in the log either — the build log is the file an operator
    # reads and the one most likely to be pasted into a bug report.
    assert passcode not in state.store.log_path(job_id).read_text(encoding="utf-8")


async def test_the_submitted_model_is_deleted_when_the_build_ends(client, state) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
        await wait_for_state(ws, job_id, {"succeeded", "failed"})

    # It held the device's Matter passcode and its only consumer has
    # exited (ADR 0007 decision 2).
    assert not state.store.model_path(job_id).exists()
    assert not state.store.public_key_path(job_id).exists()


async def test_a_job_directory_is_private(client, state) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
        await wait_for_state(ws, job_id, {"succeeded", "failed"})

    assert state.store.directory(job_id).stat().st_mode & 0o077 == 0


async def test_a_failing_build_reports_the_builder_s_own_diagnostics(client, monkeypatch) -> None:
    monkeypatch.setenv("MCUHOME_FAKE_MODE", "fail")
    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
        job = await wait_for_state(ws, job_id, {"succeeded", "failed"})

    assert job["state"] == "failed"
    assert job["exit_code"] == 1
    # The builder's --json error document, not "exit code 1": the same
    # sentence the dashboard would have shown in an editor gutter.
    assert "is not a board MCUHome knows" in job["error"]


async def test_a_build_that_prints_nothing_useful_still_fails_plainly(client, monkeypatch) -> None:
    monkeypatch.setenv("MCUHOME_FAKE_MODE", "crash")
    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
        job = await wait_for_state(ws, job_id, {"succeeded", "failed"})

    assert job["state"] == "failed"
    assert "exit code 3" in job["error"]


async def test_the_compile_lane_is_one(client, state, monkeypatch) -> None:
    """Two jobs submitted at once do not run at once (ADR 0006 decision 5)."""
    monkeypatch.setenv("MCUHOME_FAKE_MODE", "ok")
    monkeypatch.setenv("MCUHOME_FAKE_LINES", "4")
    monkeypatch.setenv("MCUHOME_FAKE_DELAY", "0.05")

    async with client.ws_connect("/ws", headers=auth()) as ws:
        first = (await call(ws, "submit_job", submit_payload(), frame_id="a"))["payload"]["job_id"]
        second = (await call(ws, "submit_job", submit_payload(), frame_id="b"))["payload"]["job_id"]

        seen_together = False
        finished: set[str] = set()
        while len(finished) < 2:
            frame = await ws.receive_json(timeout=25)
            if frame.get("event") != "job_state_changed":
                continue
            job = frame["payload"]["job"]
            running = {item.id for item in state.engine.running()}
            if len(running) > 1:
                seen_together = True
            if job["state"] in {"succeeded", "failed"}:
                finished.add(job["id"])

    assert finished == {first, second}
    assert not seen_together


async def test_queue_status_shows_the_lane_and_the_history(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
        await wait_for_state(ws, job_id, {"succeeded", "failed"})
        status = (await call(ws, "queue_status", frame_id="s"))["payload"]

    assert status["slots"] == 1
    assert status["queued"] == []
    assert status["running"] == []
    assert [job["id"] for job in status["jobs"]] == [job_id]


async def test_options_reach_the_builder(client, state) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = (await call(ws, "submit_job", submit_payload(snippets=["debug-rtt"])))["payload"][
            "job_id"
        ]
        job = await wait_for_state(ws, job_id, {"succeeded", "failed"})

    assert job["state"] == "succeeded"
    assert job["manifest"]["build"]["snippets"] == ["debug-rtt"]


class TestSubmissionRefusals:
    async def test_a_model_version_outside_the_range_is_a_refusal(self, client) -> None:
        payload = submit_payload()
        payload["model_version"] = 99
        async with client.ws_connect("/ws", headers=auth()) as ws:
            frame = await call(ws, "submit_job", payload)

        # ADR 0006 decision 4: a mismatch names both sides' numbers and
        # never becomes a silent fallback.
        assert frame["error"]["code"] == "unsupported"
        assert frame["error"]["received"] == 99
        assert frame["error"]["supported"]["max"] == 1
        assert "99" in frame["error"]["message"]

    async def test_a_private_key_is_refused_loudly(self, client) -> None:
        payload = submit_payload()
        payload["public_key"] = "-----BEGIN PRIVATE KEY-----\nMHc\n-----END PRIVATE KEY-----\n"
        async with client.ws_connect("/ws", headers=auth()) as ws:
            frame = await call(ws, "submit_job", payload)

        assert frame["error"]["code"] == "bad_request"
        assert "private" in frame["error"]["message"].lower()

    async def test_something_that_is_not_a_key_is_refused(self, client) -> None:
        payload = submit_payload()
        payload["public_key"] = "hello"
        async with client.ws_connect("/ws", headers=auth()) as ws:
            frame = await call(ws, "submit_job", payload)
        assert frame["error"]["code"] == "bad_request"

    async def test_asking_this_server_to_sign_is_refused(self, client) -> None:
        payload = submit_payload()
        payload["no_sign"] = False
        async with client.ws_connect("/ws", headers=auth()) as ws:
            frame = await call(ws, "submit_job", payload)

        assert frame["error"]["code"] == "unsupported"
        assert "never signs" in frame["error"]["message"]

    async def test_a_missing_model_is_a_bad_request(self, client) -> None:
        async with client.ws_connect("/ws", headers=auth()) as ws:
            frame = await call(ws, "submit_job", {"public_key": PUBLIC_KEY})
        assert frame["error"]["code"] == "bad_request"

    async def test_an_unknown_command_lists_the_known_ones(self, client) -> None:
        # Answered with the session protocol's typed envelope; the deep
        # envelope assertions live in test_sessions.py.
        async with client.ws_connect("/ws", headers=auth()) as ws:
            frame = await call(ws, "compile_please", {})
        assert frame["error"]["code"] == "version.verb-unknown"
        assert "submit_job" in frame["error"]["details"]["known"]

    async def test_an_unusable_builder_refuses_before_it_queues(
        self, aiohttp_client, config
    ) -> None:
        from mcuhome_buildserver.app import ServerState, create_app
        from mcuhome_buildserver.builder import BuilderFeatures

        state = ServerState(
            config,
            features=BuilderFeatures(
                present=True, model_input=False, detached_signing=True, json_output=True
            ),
        )
        await state.start(probe=False)
        try:
            client = await aiohttp_client(create_app(state))
            async with client.ws_connect("/ws", headers=auth()) as ws:
                frame = await call(ws, "submit_job", submit_payload())
            assert frame["error"]["code"] == "unsupported"
            assert "--model" in frame["error"]["message"]
            assert state.engine.store.all() == []
        finally:
            await state.stop()


class TestStore:
    def make(self, root: Path, **kwargs) -> JobStore:
        return JobStore(root, **kwargs)

    def job(self, store: JobStore, state: JobState, *, finished: float | None = None) -> Job:
        record = Job(
            id=new_job_id(),
            device="bench-node",
            board="nrf7002dk/nrf5340/cpuapp",
            model_version=1,
            options=JobOptions(),
            state=state,
            finished=finished,
        )
        store.create(record)
        store.save(record)
        return record

    def test_a_restart_marks_unfinished_jobs_interrupted(self, tmp_path: Path) -> None:
        store = self.make(tmp_path)
        running = self.job(store, JobState.RUNNING)
        queued = self.job(store, JobState.QUEUED)
        done = self.job(store, JobState.SUCCEEDED, finished=time.time())

        fresh = self.make(tmp_path)
        interrupted = fresh.load()

        assert {job.id for job in interrupted} == {running.id, queued.id}
        # Not "failed": the build did not break, the server did, and a
        # user reading a history should be able to tell those apart.
        assert fresh.get(running.id).state is JobState.INTERRUPTED
        assert fresh.get(done.id).state is JobState.SUCCEEDED
        # …and it is written back, so a second restart says the same.
        assert self.make(tmp_path).load() == []

    def test_an_unreadable_record_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        store = self.make(tmp_path)
        good = self.job(store, JobState.SUCCEEDED, finished=time.time())
        (tmp_path / "broken").mkdir()
        (tmp_path / "broken" / "job.json").write_text("{not json", encoding="utf-8")

        fresh = self.make(tmp_path)
        fresh.load()
        assert [job.id for job in fresh.all()] == [good.id]

    def test_retention_keeps_the_cap_and_never_prunes_a_live_job(self, tmp_path: Path) -> None:
        store = self.make(tmp_path, keep=2, ttl_days=0)
        old = [self.job(store, JobState.SUCCEEDED, finished=time.time()) for _ in range(4)]
        running = self.job(store, JobState.RUNNING)

        removed = store.prune()

        assert set(removed) == {old[0].id, old[1].id}
        assert not (tmp_path / old[0].id).exists()
        assert running.id in {job.id for job in store.all()}

    def test_retention_applies_the_time_to_live(self, tmp_path: Path) -> None:
        store = self.make(tmp_path, keep=100, ttl_days=1)
        stale = self.job(store, JobState.SUCCEEDED, finished=time.time() - 2 * 86400)
        fresh = self.job(store, JobState.SUCCEEDED, finished=time.time())

        assert store.prune() == [stale.id]
        assert [job.id for job in store.all()] == [fresh.id]

    def test_ids_sort_by_time(self) -> None:
        early = new_job_id(1000000000.0)
        late = new_job_id(2000000000.0)
        assert early < late
        # …and the tail is not guessable, because a job id addresses
        # that job's artifacts.
        assert new_job_id(1000000000.0) != early


def test_job_records_round_trip() -> None:
    job = Job(
        id="20260808-101112-abcdef",
        device="bench-node",
        board="nrf7002dk/nrf5340/cpuapp",
        model_version=1,
        options=JobOptions(native=True, image="ghcr.io/x:y", snippets=("a",), jobs=8),
        state=JobState.SUCCEEDED,
        manifest={"images": []},
    )
    assert Job.from_dict(job.to_dict()) == job


def test_a_finished_state_knows_it_is_finished() -> None:
    assert not JobState.QUEUED.finished
    assert not JobState.RUNNING.finished
    for state in (JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED, JobState.INTERRUPTED):
        assert state.finished


@pytest.mark.parametrize("state", list(JobState))
def test_every_state_is_its_own_wire_value(state: JobState) -> None:
    assert str(state) == state.value
