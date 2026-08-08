# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Log sidecars and the resumable follow of ADR 0006 decision 6."""

from __future__ import annotations

import asyncio
from pathlib import Path

from mcuhome_buildserver.logs import MAX_HISTORY_BYTES, JobLog
from tests.conftest import auth, call, submit_payload, wait_for_state


class TestJobLog:
    def test_writing_and_reading_agree_on_offsets(self, tmp_path: Path) -> None:
        log = JobLog(tmp_path / "log.txt")
        log.append(b"first\n")
        log.append(b"second\n")

        assert log.size == len(b"first\nsecond\n")
        assert log.read(0) == ("first\nsecond\n", 13, True)
        assert log.read(6) == ("second\n", 13, True)
        # An offset past the end is a client that is ahead of us, not an
        # error: it gets nothing and the same offset back.
        assert log.read(999) == ("", 13, True)

    def test_history_is_bounded_and_pageable(self, tmp_path: Path) -> None:
        log = JobLog(tmp_path / "log.txt")
        log.append(b"x" * (MAX_HISTORY_BYTES + 100))

        text, next_offset, eof = log.read(0)
        assert len(text) == MAX_HISTORY_BYTES
        assert next_offset == MAX_HISTORY_BYTES
        assert eof is False

        text, next_offset, eof = log.read(next_offset)
        assert len(text) == 100
        assert eof is True

    def test_a_follower_receives_what_is_written_after_it_attached(self, tmp_path: Path) -> None:
        log = JobLog(tmp_path / "log.txt")
        log.append(b"before\n")

        received: list[tuple[int, str]] = []
        mark = log.follow("key", lambda offset, text: received.append((offset, text)))
        log.append(b"after\n")

        assert mark == 7
        assert received == [(7, "after\n")]

        log.unfollow("key")
        log.append(b"later\n")
        assert len(received) == 1

    def test_the_join_between_history_and_live_loses_nothing(self, tmp_path: Path) -> None:
        """The whole point of registering before reading.

        A client at offset 0 gets everything below the mark from the
        history read and everything at or above it as events; the two
        ranges touch and do not overlap.
        """
        log = JobLog(tmp_path / "log.txt")
        log.append(b"aaa")

        live: list[tuple[int, str]] = []
        mark = log.follow("key", lambda offset, text: live.append((offset, text)))
        log.append(b"bbb")
        history, next_offset, _ = log.read(0, mark)

        assert history == "aaa"
        assert next_offset == mark == 3
        assert live == [(3, "bbb")]
        assert history + "".join(text for _, text in live) == "aaabbb"

    def test_a_multibyte_character_split_across_chunks_survives(self, tmp_path: Path) -> None:
        log = JobLog(tmp_path / "log.txt")
        received: list[str] = []
        log.follow("key", lambda offset, text: received.append(text))

        # "ü" is two bytes and a pipe can break anywhere.
        log.append(b"gr")
        log.append(b"\xc3")
        log.append(b"\xb6" + "\xdfer\n".encode())

        assert "".join(received) == "größer\n"

    def test_a_follower_that_raises_does_not_break_the_build(self, tmp_path: Path) -> None:
        log = JobLog(tmp_path / "log.txt")

        def angry(offset: int, text: str) -> None:
            raise RuntimeError("no")

        log.follow("angry", angry)
        log.append(b"still written\n")
        assert log.size == len(b"still written\n")

    def test_reopening_resumes_at_the_end(self, tmp_path: Path) -> None:
        path = tmp_path / "log.txt"
        first = JobLog(path)
        first.append(b"one\n")
        first.close()

        second = JobLog(path)
        assert second.size == 4
        second.append(b"two\n")
        assert path.read_text(encoding="utf-8") == "one\ntwo\n"


async def test_follow_job_streams_a_running_build(client, monkeypatch) -> None:
    monkeypatch.setenv("MCUHOME_FAKE_LINES", "20")
    monkeypatch.setenv("MCUHOME_FAKE_DELAY", "0.02")

    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
        await wait_for_state(ws, job_id, {"running"})

        first = (await call(ws, "follow_job", {"job_id": job_id, "offset": 0}, frame_id="f"))[
            "payload"
        ]
        assert first["live"] is True

        collected = first["text"]
        offset = first["next_offset"]
        while True:
            frame = await ws.receive_json(timeout=20)
            if frame.get("event") == "job_output" and frame["payload"]["job_id"] == job_id:
                assert frame["payload"]["offset"] == offset
                collected += frame["payload"]["text"]
                offset = frame["payload"]["offset"] + len(frame["payload"]["text"].encode("utf-8"))
            if frame.get("event") == "job_state_changed" and frame["payload"]["job"]["state"] in {
                "succeeded",
                "failed",
            }:
                break

    assert "[1/20]" in collected
    assert "[20/20]" in collected


async def test_a_follow_resumes_at_the_offset_it_states(client, state) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
        await wait_for_state(ws, job_id, {"succeeded", "failed"})

        whole = (await call(ws, "follow_job", {"job_id": job_id}, frame_id="a"))["payload"]
        assert whole["live"] is False
        assert whole["eof"] is True
        assert whole["state"] == "succeeded"

        middle = len(whole["text"].encode("utf-8")) // 2
        rest = (await call(ws, "follow_job", {"job_id": job_id, "offset": middle}, frame_id="b"))[
            "payload"
        ]

    assert rest["offset"] == middle
    assert whole["text"].encode("utf-8")[middle:].decode("utf-8") == rest["text"]
    assert rest["next_offset"] == whole["next_offset"]


async def test_following_a_job_that_has_not_started_still_receives_its_output(
    client, state, monkeypatch
) -> None:
    """A client may follow a job while it is still in the queue.

    The engine caches the log object of every unfinished job for exactly
    this: a follower registered before the worker picks the job up has to
    be on the object the worker will write into. A fresh instance per
    call would drop this client's output the moment the build started —
    silently, and only for the client that was quickest.
    """
    monkeypatch.setenv("MCUHOME_FAKE_LINES", "6")
    monkeypatch.setenv("MCUHOME_FAKE_DELAY", "0.03")

    async with client.ws_connect("/ws", headers=auth()) as ws:
        await call(ws, "submit_job", submit_payload(), frame_id="a")
        queued = (await call(ws, "submit_job", submit_payload(), frame_id="b"))["payload"]["job_id"]
        assert state.engine.store.get(queued).state == "queued"

        follow = (await call(ws, "follow_job", {"job_id": queued}, frame_id="f"))["payload"]
        assert follow["live"] is True
        assert follow["text"] == ""

        collected = ""
        while True:
            frame = await ws.receive_json(timeout=30)
            if frame.get("event") == "job_output" and frame["payload"]["job_id"] == queued:
                collected += frame["payload"]["text"]
            if (
                frame.get("event") == "job_state_changed"
                and frame["payload"]["job"]["id"] == queued
                and frame["payload"]["job"]["state"] in {"succeeded", "failed"}
            ):
                break

    assert "[1/6]" in collected
    assert "[6/6]" in collected


async def test_following_an_unknown_job_is_not_found(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "follow_job", {"job_id": "20260101-000000-aaaaaa"})
    assert frame["error"]["code"] == "not_found"


async def test_a_closed_connection_stops_following(client, state, monkeypatch) -> None:
    monkeypatch.setenv("MCUHOME_FAKE_MODE", "hang")
    monkeypatch.setenv("MCUHOME_FAKE_LINES", "2")

    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
        await wait_for_state(ws, job_id, {"running"})
        await call(ws, "follow_job", {"job_id": job_id}, frame_id="f")
        assert state.engine.log_for(job_id).follower_count == 1

    for _ in range(200):
        if state.engine.log_for(job_id).follower_count == 0:
            break
        await asyncio.sleep(0.01)
    assert state.engine.log_for(job_id).follower_count == 0
