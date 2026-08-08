# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Chunked, hashed artifact transfer (ADR 0006 decision 7)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from mcuhome_buildserver.artifacts import DEFAULT_CHUNK_BYTES, read_artifact_set, read_chunk
from tests.conftest import ARTIFACT_BYTES, auth, call, sha256, submit_payload, wait_for_state


async def _finished_job(ws) -> str:
    job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
    job = await wait_for_state(ws, job_id, {"succeeded", "failed"})
    assert job["state"] == "succeeded"
    return job_id


async def test_the_index_is_the_manifest_s_file_set(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = await _finished_job(ws)
        index = (await call(ws, "download_artifacts", {"job_id": job_id}, frame_id="i"))["payload"]

    paths = {item["path"] for item in index["artifacts"]}
    assert paths == {
        "build/app/zephyr/zephyr.bin",
        "build/mcuboot/zephyr/zephyr.hex",
        "build-manifest.json",
    }
    assert index["manifest"]["device"]["name"] == "bench-node"
    assert index["chunk_bytes"] == DEFAULT_CHUNK_BYTES

    # Every artifact the build produced carries the SHA-256 the *build*
    # computed — the anti-substitution anchor of ADR 0010.
    for item in index["artifacts"]:
        if item["role"] == "manifest":
            continue  # a document cannot state its own hash
        assert item["sha256"] == sha256(ARTIFACT_BYTES)
        assert item["size"] == len(ARTIFACT_BYTES)


async def test_an_artifact_transfers_in_verifiable_chunks(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = await _finished_job(ws)
        index = (await call(ws, "download_artifacts", {"job_id": job_id}, frame_id="i"))["payload"]
        entry = next(item for item in index["artifacts"] if item["path"].endswith("zephyr.bin"))

        assembled = b""
        offset = 0
        chunks = 0
        while True:
            chunk = (
                await call(
                    ws,
                    "download_artifacts",
                    {"job_id": job_id, "path": entry["path"], "offset": offset},
                    frame_id=f"c{chunks}",
                )
            )["payload"]
            data = base64.b64decode(chunk["data"])
            # Per-chunk hash: did this piece survive the wire?
            assert chunk["sha256"] == sha256(data)
            assert chunk["length"] == len(data)
            assembled += data
            chunks += 1
            offset = chunk["next_offset"]
            if chunk["eof"]:
                break

    # More than one chunk, or the loop proved nothing.
    assert chunks > 1
    assert assembled == ARTIFACT_BYTES
    # Whole-file hash from the index: are these the bytes the build made?
    assert sha256(assembled) == entry["sha256"]


async def test_the_manifest_itself_is_downloadable(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = await _finished_job(ws)
        chunk = (
            await call(
                ws,
                "download_artifacts",
                {"job_id": job_id, "path": "build-manifest.json"},
                frame_id="m",
            )
        )["payload"]

    manifest = json.loads(base64.b64decode(chunk["data"]))
    assert manifest["signing"]["signed"] is False


async def test_only_indexed_paths_can_be_asked_for(client) -> None:
    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = await _finished_job(ws)
        for path in (
            "../../../etc/passwd",
            "/etc/passwd",
            "build/app/zephyr/../../../../../etc/passwd",
            "device-model.json",  # exists in the build dir, not in the index
        ):
            frame = await call(
                ws, "download_artifacts", {"job_id": job_id, "path": path}, frame_id=path
            )
            assert frame["error"]["code"] == "not_found", path


async def test_a_job_without_artifacts_says_so(client, monkeypatch) -> None:
    monkeypatch.setenv("MCUHOME_FAKE_MODE", "fail")
    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = (await call(ws, "submit_job", submit_payload()))["payload"]["job_id"]
        await wait_for_state(ws, job_id, {"failed", "succeeded"})
        frame = await call(ws, "download_artifacts", {"job_id": job_id}, frame_id="d")

    assert frame["error"]["code"] == "conflict"
    assert "failed" in frame["error"]["message"]


async def test_a_pruned_build_directory_is_an_honest_refusal(client, state) -> None:
    import shutil

    async with client.ws_connect("/ws", headers=auth()) as ws:
        job_id = await _finished_job(ws)
        shutil.rmtree(state.store.build_dir(job_id))
        frame = await call(ws, "download_artifacts", {"job_id": job_id}, frame_id="d")

    # ADR 0008 decision 4 gives artifacts a lifetime, and ADR 0010 needs
    # an expired one to resolve to "expired" rather than to something.
    assert frame["error"]["code"] == "not_found"
    assert "retention" in frame["error"]["message"].lower()


class TestReadChunk:
    def test_a_chunk_carries_its_own_hash_and_the_end_marker(self, tmp_path: Path) -> None:
        path = tmp_path / "blob"
        path.write_bytes(b"0123456789")

        first = read_chunk(path, 0, 4)
        assert base64.b64decode(first["data"]) == b"0123"
        assert first["sha256"] == sha256(b"0123")
        assert (first["next_offset"], first["eof"]) == (4, False)

        last = read_chunk(path, 8, 4)
        assert base64.b64decode(last["data"]) == b"89"
        assert (last["next_offset"], last["eof"]) == (10, True)

    def test_reading_past_the_end_is_an_empty_final_chunk(self, tmp_path: Path) -> None:
        path = tmp_path / "blob"
        path.write_bytes(b"abc")
        chunk = read_chunk(path, 99, 10)
        assert chunk["length"] == 0
        assert chunk["eof"] is True


class TestIndexing:
    def test_a_directory_without_a_manifest_has_no_artifacts(self, tmp_path: Path) -> None:
        assert read_artifact_set(tmp_path) is None

    def test_a_corrupt_manifest_is_not_a_crash(self, tmp_path: Path) -> None:
        (tmp_path / "build-manifest.json").write_text("{not json", encoding="utf-8")
        assert read_artifact_set(tmp_path) is None

    def test_a_manifest_naming_a_missing_file_resolves_to_nothing(self, tmp_path: Path) -> None:
        (tmp_path / "build-manifest.json").write_text(
            json.dumps(
                {
                    "images": [
                        {
                            "name": "app",
                            "role": "application",
                            "files": [{"path": "gone.bin", "size": 1, "sha256": "x"}],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        artifact_set = read_artifact_set(tmp_path)
        assert artifact_set is not None
        assert artifact_set.get("gone.bin") is not None
        assert artifact_set.resolve("gone.bin") is None
