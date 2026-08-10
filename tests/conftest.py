# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures.

**Nothing here fakes a build environment, and that is the point.** The
build server is an orchestrator and is never itself the build
environment (build-container-contract.md §1.2), so there is no build
subprocess to stand in for: what this suite exercises is the transport,
the bearer token and the session protocol, all of which run without a
toolchain anywhere near them.

The fixtures are correspondingly small — a config with a known token, a
server state, and an aiohttp client over the application it produces.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

import pytest
import zstandard

from mcuhome_buildserver.app import ServerState, create_app
from mcuhome_buildserver.config import Config

TOKEN = "test-token-000000000000000000000000"

#: A context.yaml that parses: the format version, the three pin blocks
#: spelled the one legal way (build-container contract §3.3.1), and the
#: informational fields that travel into manifest.yaml with them.
CONTEXT_YAML = f"""\
context: 1
created: 2026-08-09T10:00:00Z
mcuhome:
  constraint: ^2.3.6
  version: 2.4.0
  package:
    url: https://packages.mcuhome.org/mcuhome-sdk-2.4.0.tar.zst
    sha256: {"a" * 64}
container:
  image: ghcr.io/mcu-home/build-container
  tag: zephyr-4.4.0-r4
  digest: sha256:{"b" * 64}
target:
  board: nrf7002dk/nrf5340/cpuapp
"""


@pytest.fixture
def config(tmp_path: Path) -> Config:
    """A server whose per-session directories land in the test's tmp_path.

    Nothing here shrinks a cap: the defaults are what a deployment gets,
    and a suite that quietly ran under different limits would be testing
    a server nobody deploys. Tests that want to see a cap fire build
    their own :class:`Config` with that one number lowered.
    """
    return Config(
        host="127.0.0.1",
        port=0,
        token=TOKEN,
        pair_file=None,
        context_root=tmp_path / "sessions",
    )


@pytest.fixture
def state(config: Config) -> ServerState:
    return ServerState(config)


@pytest.fixture
async def client(aiohttp_client, state: ServerState):
    return await aiohttp_client(create_app(state))


def auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}"}


async def call(ws, command_type: str, payload: dict | None = None, frame_id: str = "1") -> dict:
    """Send one command and return the frame that answers it."""
    await ws.send_json({"id": frame_id, "type": command_type, "payload": payload or {}})
    while True:
        frame = await ws.receive_json(timeout=15)
        if frame.get("id") == frame_id:
            return frame


# --------------------------------------------------------------------------
# Building the thing that goes over the wire
# --------------------------------------------------------------------------


def make_archive(
    entries: dict[str, bytes], *, extras: list[tarfile.TarInfo] | None = None
) -> bytes:
    """A tar.zst carrying *entries*, the format E41 fixed for the wire.

    *extras* takes ready-made ``TarInfo`` objects, which is how the
    unsafe-entry tests state a symlink or a device node: those cannot be
    expressed as a path-and-bytes pair, and building them by hand is the
    only way to send what a real attacker would.
    """
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for info in extras or ():
            tar.addfile(info)
    return zstandard.ZstdCompressor().compress(raw.getvalue())


def make_archive_from(members: list[tuple[str, bytes]]) -> bytes:
    """The same, from a *sequence* of ``(name, bytes)`` pairs.

    A mapping cannot express the two archives the guards in ``unpack``
    are about: one that names the same path twice, and one that names a
    path as a file and then uses it as a directory. Both are ordinary
    tars that any client could build, so the tests that send them need a
    builder that does not deduplicate on the way in.
    """
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return zstandard.ZstdCompressor().compress(raw.getvalue())


def base_context(**files: bytes) -> bytes:
    """The usual base context: a valid ``context.yaml`` plus *files*."""
    return make_archive({"context.yaml": CONTEXT_YAML.encode(), **files})


async def send_archive(ws, verb: str, session_id: str, archive: bytes, **payload) -> dict:
    """Announce *archive*, push it as binary frames, return the answer.

    The two halves of E41's wire shape in one helper, because every test
    that touches the context path needs both and neither is interesting
    on its own. The chunking is deliberate — several frames per archive,
    since "multiple frames allowed" is part of the decided shape and a
    receiver that only ever saw one would not be exercised.
    """
    frame_id = f"u-{verb}"
    await ws.send_json(
        {
            "id": frame_id,
            "type": verb,
            "payload": {
                "session_id": session_id,
                "archive": {"size": len(archive), "sha256": hashlib.sha256(archive).hexdigest()},
                **payload,
            },
        }
    )
    for start in range(0, len(archive), 64):
        await ws.send_bytes(archive[start : start + 64])
    while True:
        frame = await ws.receive_json(timeout=15)
        if frame.get("id") == frame_id:
            return frame
