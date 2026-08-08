# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures — and a builder that is not the builder.

**No test here compiles anything.** A Zephyr+Matter build is ninety
seconds on a good machine and thirteen minutes on a laptop; a suite that
ran one would be a suite nobody runs. What the build server actually
needs to be tested against is a *process*: something that prints a
manifest on stdout, a log on stderr, takes a while, obeys or ignores
signals, and exits with a code.

:func:`fake_builder` is that process — a small Python script written into
``tmp_path`` and pointed at with ``--builder-command``. It understands
the same options ``mcuhome build`` does (including ``--model``, which is
the point: the suite exercises the invocation this server *will* make,
so the day the real builder grows the flag nothing here changes), and it
can be told to fail, to hang, or to produce artifacts.

That the real builder does not have ``--model`` yet is itself tested, in
``test_builder.py``, against the real ``mcuhome build --help``.
"""

from __future__ import annotations

import hashlib
import json
import stat
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from mcuhome_buildserver.app import ServerState, create_app
from mcuhome_buildserver.builder import BuilderFeatures
from mcuhome_buildserver.config import Config

TOKEN = "test-token-000000000000000000000000"

#: A resolved device model, cut down to the fields this server reads.
#: The real thing is `mcuhome`'s `DeviceModel.to_dict()`; the build
#: server never interprets it, it only forwards it — which is why a
#: fixture that mirrored the whole schema would be testing the wrong
#: repository.
MODEL = {
    "model_version": 1,
    "device": {
        "name": "bench-node",
        "friendly_name": "Bench Node",
        "board": "nrf7002dk/nrf5340/cpuapp",
    },
    "network": {
        "transport": "thread",
        "matter_enabled": True,
        # ADR 0007 decision 2: the passcode crosses the wire. Tests
        # assert it never reaches a log or a job record.
        "pairing": {
            "discriminator": 3840,
            "passcode": 20202021,
            "salt": "U1BBS0UyUCBLZXkgU2FsdA==",
            "iterations": 1000,
            "test_credentials": True,
        },
    },
}

PUBLIC_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEexampleexampleexampleexample\n"
    "-----END PUBLIC KEY-----\n"
)

#: What the fake builder writes and the manifest describes. Big enough
#: that a 256 KiB chunk does not cover it, so the chunking loop is
#: actually a loop.
ARTIFACT_BYTES = bytes(range(256)) * 1400

FAKE_BUILDER = '''\
#!/usr/bin/env python3
"""A stand-in for `mcuhome`, controlled by MCUHOME_FAKE_* variables."""
import argparse, hashlib, json, os, sys, time

parser = argparse.ArgumentParser(prog="mcuhome")
sub = parser.add_subparsers(dest="command")
build = sub.add_parser("build")
build.add_argument("device", nargs="?")
build.add_argument("--model")
build.add_argument("--build-dir")
build.add_argument("--public-key")
build.add_argument("--image")
build.add_argument("--snippet", action="append", default=[])
build.add_argument("--no-sign", action="store_true")
build.add_argument("--json", action="store_true")
build.add_argument("--native", action="store_true")
build.add_argument("--no-native", dest="native", action="store_false")
args = parser.parse_args()

mode = os.environ.get("MCUHOME_FAKE_MODE", "ok")
lines = int(os.environ.get("MCUHOME_FAKE_LINES", "5"))
delay = float(os.environ.get("MCUHOME_FAKE_DELAY", "0"))

for index in range(lines):
    print("[%d/%d] Building C object fake/%d.o" % (index + 1, lines, index), file=sys.stderr)
    sys.stderr.flush()
    if delay:
        time.sleep(delay)

if mode == "hang":
    while True:
        time.sleep(0.05)

if mode == "fail":
    print("fake builder: refusing on purpose", file=sys.stderr)
    if args.json:
        print(json.dumps({"ok": False, "errors": [
            {"message": "board \\'nrf99dk\\' is not a board MCUHome knows",
             "file": "devices/bench-node/main.yaml", "line": 3, "column": 10,
             "key": "device.board", "hint": "supported boards: nrf7002dk",
             "kind": "ConfigError"}]}))
    sys.exit(1)

if mode == "crash":
    sys.exit(3)

out = os.path.abspath(args.build_dir)
zephyr = os.path.join(out, "build", "app", "zephyr")
boot = os.path.join(out, "build", "mcuboot", "zephyr")
os.makedirs(zephyr, exist_ok=True)
os.makedirs(boot, exist_ok=True)

payload = bytes(range(256)) * 1400
files = []
for directory, name, role in ((zephyr, "zephyr.bin", "application"),
                              (boot, "zephyr.hex", "bootloader")):
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        handle.write(payload)
    files.append((role, os.path.relpath(path, out).replace(os.sep, "/"), payload))

model = json.load(open(args.model)) if args.model else {}
with open(os.path.join(out, "device-model.json"), "w") as handle:
    json.dump(model, handle)

images = []
for role, relative, blob in files:
    images.append({
        "name": "app" if role == "application" else "mcuboot",
        "role": role,
        "flash_bytes": len(blob),
        "files": [{"path": relative, "size": len(blob),
                   "sha256": hashlib.sha256(blob).hexdigest()}],
    })

manifest = {
    "manifest_version": 1,
    "builder": {"version": "0.1.0.dev0", "model_version": model.get("model_version", 1)},
    "device": {"name": model.get("device", {}).get("name", "unknown"),
               "friendly_name": model.get("device", {}).get("friendly_name", ""),
               "board": model.get("device", {}).get("board", "")},
    "build": {"snippets": args.snippet, "bootloader_snippets": [], "jobs": 2},
    "images": images,
    "merged": None,
    "signing": {"tool": "imgtool", "image": "app", "signed": False,
                "signed_by_the_build": False, "signature_type": "ecdsa-p256",
                "arguments": {"version": "0.0.0+0", "header-size": 512,
                              "align": 4, "slot-size": 786432},
                "inputs": {"bin": "build/app/zephyr/zephyr.bin"},
                "outputs": {"bin": "build/app/zephyr/zephyr.signed.bin"}},
}
with open(os.path.join(out, "build-manifest.json"), "w") as handle:
    json.dump(manifest, handle, indent=2)

if args.json:
    print(json.dumps({"ok": True, "device": manifest["device"]["name"],
                      "build_dir": out, "generated": [],
                      "manifest_path": os.path.join(out, "build-manifest.json"),
                      "manifest": manifest}))
sys.exit(0)
'''


@pytest.fixture
def fake_builder(tmp_path: Path) -> Path:
    """A ``mcuhome``-shaped executable that never compiles anything."""
    path = tmp_path / "fake-mcuhome"
    path.write_text(FAKE_BUILDER, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture
def features() -> BuilderFeatures:
    """A builder that can do everything, which the fake one can."""
    return BuilderFeatures(present=True, model_input=True, detached_signing=True, json_output=True)


@pytest.fixture
def config(tmp_path: Path, fake_builder: Path) -> Config:
    return Config(
        host="127.0.0.1",
        port=0,
        token=TOKEN,
        pair_file=None,
        jobs_root=tmp_path / "jobs",
        workspace=None,
        slots=1,
        native=True,
        job_timeout=30.0,
        builder_command=(sys.executable, str(fake_builder)),
    )


@pytest.fixture
async def state(config: Config, features: BuilderFeatures) -> Iterator[ServerState]:
    server_state = ServerState(config, features=features)
    # `probe=False`: the fixture already said what the fake builder can
    # do, and probing it would only prove that argparse prints options.
    await server_state.start(probe=False)
    yield server_state
    await server_state.stop()


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


async def wait_for_state(ws, job_id: str, states: set[str], timeout: float = 20.0) -> dict:
    """Read events until *job_id* reaches one of *states*."""
    while True:
        frame = await ws.receive_json(timeout=timeout)
        if frame.get("type") != "event" or frame.get("event") != "job_state_changed":
            continue
        job = frame["payload"]["job"]
        if job["id"] == job_id and job["state"] in states:
            return job


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def submit_payload(**options) -> dict:
    return {
        "model": json.loads(json.dumps(MODEL)),
        "model_version": 1,
        "public_key": PUBLIC_KEY,
        "options": options,
    }
