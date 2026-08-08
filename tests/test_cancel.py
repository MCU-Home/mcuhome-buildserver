# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Cancellation — the reason the builder runs in its own process group.

The property worth proving is not "the coroutine stopped waiting". It is
that the *compiler* stopped: a job that keeps a machine busy after the
user cancelled it is the exact failure ESPHome's job model exists to
avoid, and the only mechanism that produces it is a signal to a process
group.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import replace

from mcuhome_buildserver.app import ServerState, create_app
from tests.conftest import auth, call, submit_payload, wait_for_state


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover - not our process any more
        return True
    return True


async def _pid_of(state: ServerState, job_id: str) -> int:
    for _ in range(300):
        process = state.engine.process_for(job_id)
        if process is not None:
            return process.pid
        await asyncio.sleep(0.01)
    raise AssertionError(f"job {job_id} never started a process")


async def _wait_gone(pid: int) -> None:
    for _ in range(300):
        if not _alive(pid):
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"pid {pid} is still running")


async def test_cancelling_a_running_build_kills_the_process(client, state, monkeypatch) -> None:
    monkeypatch.setenv("MCUHOME_FAKE_MODE", "hang")
    monkeypatch.setenv("MCUHOME_FAKE_LINES", "1")

    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
        await wait_for_state(ws, job_id, {"running"})
        pid = await _pid_of(state, job_id)

        await call(ws, "cancel_job", {"job_id": job_id}, frame_id="c")
        job = await wait_for_state(ws, job_id, {"cancelled", "failed", "succeeded"})

    assert job["state"] == "cancelled"
    assert "Cancelled while it was running" in job["error"]
    # The build is gone, not merely unwatched.
    await _wait_gone(pid)


async def test_a_cancel_reaches_exactly_one_job(
    aiohttp_client, config, features, monkeypatch
) -> None:
    """Two builds running, one cancelled: the other is untouched.

    This is what ``start_new_session=True`` buys. A server that signalled
    its own process group — the obvious implementation — would stop both,
    and on a machine with the lane raised that is every other user's
    build.
    """
    monkeypatch.setenv("MCUHOME_FAKE_MODE", "hang")
    monkeypatch.setenv("MCUHOME_FAKE_LINES", "1")

    state = ServerState(replace(config, slots=2), features=features)
    await state.start(probe=False)
    try:
        client = await aiohttp_client(create_app(state))
        async with client.ws_connect("/ws", headers=auth()) as ws:
            first = (await call(ws, "submit_job", submit_payload(), frame_id="a"))["payload"][
                "job_id"
            ]
            second = (await call(ws, "submit_job", submit_payload(), frame_id="b"))["payload"][
                "job_id"
            ]
            first_pid = await _pid_of(state, first)
            second_pid = await _pid_of(state, second)

            await call(ws, "cancel_job", {"job_id": first}, frame_id="c")
            job = await wait_for_state(ws, first, {"cancelled", "failed", "succeeded"})

        assert job["state"] == "cancelled"
        await _wait_gone(first_pid)
        assert _alive(second_pid)
    finally:
        await state.stop()


async def test_cancelling_a_queued_job_never_starts_it(client, state, monkeypatch) -> None:
    monkeypatch.setenv("MCUHOME_FAKE_LINES", "3")
    monkeypatch.setenv("MCUHOME_FAKE_DELAY", "0.05")

    async with client.ws_connect("/ws", headers=auth()) as ws:
        await call(ws, "submit_job", submit_payload(), frame_id="a")
        queued = (await call(ws, "submit_job", submit_payload(), frame_id="b"))["payload"]["job_id"]
        frame = await call(ws, "cancel_job", {"job_id": queued}, frame_id="c")
        assert frame["type"] == "result"

    job = state.engine.store.get(queued)
    assert job.state == "cancelled"
    assert job.started is None
    assert "before it started" in job.error


async def test_cancelling_a_finished_job_is_not_an_error(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
        await wait_for_state(ws, job_id, {"succeeded", "failed"})
        frame = await call(ws, "cancel_job", {"job_id": job_id}, frame_id="c")

    # The client asked for a state and that state holds. What comes back
    # is the record, which says what actually happened.
    assert frame["type"] == "result"
    assert frame["payload"]["job"]["state"] == "succeeded"


async def test_cancelling_an_unknown_job_is_not_found(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        frame = await call(ws, "cancel_job", {"job_id": "20260101-000000-aaaaaa"})
    assert frame["error"]["code"] == "not_found"


async def test_a_build_that_outlasts_its_budget_is_stopped(
    aiohttp_client, config, features, monkeypatch
) -> None:
    monkeypatch.setenv("MCUHOME_FAKE_MODE", "hang")
    monkeypatch.setenv("MCUHOME_FAKE_LINES", "1")

    state = ServerState(replace(config, job_timeout=0.5), features=features)
    await state.start(probe=False)
    try:
        client = await aiohttp_client(create_app(state))
        async with client.ws_connect("/ws", headers=auth()) as ws:
            job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
            pid = await _pid_of(state, job_id)
            job = await wait_for_state(ws, job_id, {"failed", "succeeded", "cancelled"})
        assert job["state"] == "failed"
        assert "budget" in job["error"]
        await _wait_gone(pid)
    finally:
        await state.stop()


async def test_shutdown_stops_a_running_build(client, state, monkeypatch) -> None:
    monkeypatch.setenv("MCUHOME_FAKE_MODE", "hang")
    monkeypatch.setenv("MCUHOME_FAKE_LINES", "1")

    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
        await wait_for_state(ws, job_id, {"running"})
        pid = await _pid_of(state, job_id)

    await state.stop()
    await _wait_gone(pid)
    # The fixture stops the engine again on teardown: doing it twice has
    # to be safe, because a signal handler and a `finally` both want to.
    await state.stop()
