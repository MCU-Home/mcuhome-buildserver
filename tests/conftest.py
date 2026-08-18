# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures.

**Nothing here fakes a build environment, and that is the point.** The
build server is an orchestrator and is never itself the build
environment (build-container-contract.md §1.2), so there is no build to
stand in for: what this suite exercises is the transport, the bearer
token, the session protocol and the *backend* — the argv it composes,
the documents it writes, and what it makes of the documents that come
back.

**Docker is stubbed at the seam and never runs**, which is a hard rule
of this suite rather than a convenience. :class:`FakeDocker` replaces
:func:`mcuhome_buildserver.container.run_docker` and
:func:`~mcuhome_buildserver.container.spawn_docker`, the two impure
functions everything else in that module goes through, and it is
installed by an **autouse** fixture: a test that forgot to ask for it
would otherwise start a real container on the machine running the
suite, which is exactly the failure mode the reference implementation
warns about ("a test that thinks it stubbed docker out but did not is a
test that starts a real build").

The fake is a *conforming program* by default — it answers ``describe``
with a complete ``program`` block, writes real files into ``out``,
declares them with the hashes they actually have and emits the events
contract §8 seeds its registry with. Tests that want a non-conforming
one say so by replacing one attribute, which keeps every test that does
not care about the container from having to know what one looks like.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
import zstandard
from mcuhome.model.buildimage import CONTRACT_LABEL, TOOLCHAIN_LABEL, ZEPHYR_LABEL
from ruamel.yaml import YAML

from mcuhome_buildserver import container
from mcuhome_buildserver.app import ServerState, create_app
from mcuhome_buildserver.config import Config

TOKEN = "test-token-000000000000000000000000"

#: The Zephyr line and revision the build image has — spelled in its label.
#: The client pins the full reference with digest.
ZEPHYR_LINE = "4.4"
IMAGE_REVISION = "r10"
IMAGE_REFERENCE_FORMAT3 = (
    f"ghcr.io/mcu-home/build-container:zephyr-4.4.0-{IMAGE_REVISION}@sha256:{'b' * 64}"
)
CONTEXT_YAML = f"""\
context: 3
created: 2026-08-09T10:00:00Z
mcuhome:
  constraint: ^2.3.6
  version: 2.4.0
  package:
    url: https://packages.mcuhome.org/mcuhome-sdk-2.4.0.tar.zst
    sha256: {"a" * 64}
build_environment: {IMAGE_REFERENCE_FORMAT3}
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

    ``sdk_sources`` names a directory that starts out empty, which is
    the honest default: a server with no SDK package configured refuses
    a working action with ``sdk.unavailable``, and a test that wants a
    build puts a package there with :func:`write_sdk_package`.
    """
    return Config(
        host="127.0.0.1",
        port=0,
        token=TOKEN,
        pair_file=None,
        context_root=tmp_path / "sessions",
        sdk_sources=(tmp_path / "packages",),
    )


#: The image this server matches for the pinned ``build_environment``, and the
#: labels contract §2.1 requires of it. Spelled here so that a test that
#: changes one can see what a conforming image looks like beside it —
#: the ``org.mcuhome.build-environment.zephyr.version`` label above all,
#: which is what matches the pin in :data:`IMAGE_REFERENCE_FORMAT3`.
IMAGE = "ghcr.io/mcu-home/build-container"
IMAGE_DIGEST = "sha256:" + "b" * 64
IMAGE_REFERENCE = f"{IMAGE}@{IMAGE_DIGEST}"
IMAGE_LABELS = {
    CONTRACT_LABEL: "1",
    ZEPHYR_LABEL: "4.4.0",
    TOOLCHAIN_LABEL: "zephyr-sdk-1.0.1",
}

#: A conforming ``describe`` ``program`` block: every field §7.1.1 makes
#: mandatory, ``trees`` included. ``sdk`` reports ``path: null`` — "this
#: tree is not in my image; put it wherever you like and name it in
#: ``trees``" — while the three the image carries report where they are,
#: which is what E47's writable views are asserted at.
PROGRAM = {
    "id": "org.mcuhome.build-container",
    "version": "2.4.0",
    "contract": 1,
    "request": [1],
    "result": [1],
    "actions": ["describe", "verify", "build"],
    "trees": {
        "zephyr": {"path": "/opt/zephyr", "version": "4.4.0"},
        "chip": {"path": "/opt/connectedhomeip", "version": "v1.5.1.0"},
        "mcuboot": {"path": "/opt/bootloader/mcuboot"},
        "sdk": {"path": None},
    },
}


@dataclass
class Invocation:
    """One ``docker exec`` the backend made, as the fake saw it."""

    action: str
    argv: list[str]
    request: dict[str, Any]


class FakeProcess:
    """A ``docker exec`` that has already finished, or refuses to.

    ``ignores_terminate`` is the rung above SIGTERM: a client that does
    not go away is the only reason SIGKILL exists, and a process that
    always died of SIGTERM could never reach it.
    """

    def __init__(self, code: int, *, hang: bool = False, ignores_terminate: bool = False) -> None:
        self._code = code
        self._hang = hang
        self._ignores_terminate = ignores_terminate
        self.terminated = False
        self.killed = False

    async def wait(self) -> int:
        while self._hang:
            await asyncio.sleep(0.01)
        return self._code

    def terminate(self) -> None:
        self.terminated = True
        if not self._ignores_terminate:
            self._hang = False
            self._code = -15

    def kill(self) -> None:
        self.killed = True
        self._hang = False
        self._code = -9

    async def stop(self) -> None:
        """Teardown's escalation, with the grace collapsed to nothing.

        The real one (:meth:`mcuhome_buildserver.processes.ChildProcess.stop`)
        asks the process group, waits a bounded moment and kills what is
        left. The shape a test needs from it is the *ladder* and not the
        clock: a child that goes away on SIGTERM is never killed, and one
        that does not always is.
        """
        self.terminate()
        await asyncio.sleep(0)
        if self._hang:
            self.kill()


@dataclass
class FakeDocker:
    """Docker as this suite has it: argv in, scripted answers out.

    Every command the backend composes lands in :attr:`calls` verbatim,
    which is what makes the composed argv assertable — it is the
    interface between the contract and the runtime, and the only way to
    check it without running anything.
    """

    calls: list[list[str]] = field(default_factory=list)
    invocations: list[Invocation] = field(default_factory=list)
    #: Reference -> the ``docker image inspect`` object for it.
    images: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: What ``docker image ls`` lists, for ``capabilities``.
    listed: list[str] = field(default_factory=list)
    #: ``None`` means "no docker binary at all"; a non-zero status means
    #: "found it, cannot reach the daemon". The two refusals the backend
    #: has to tell apart.
    version_status: int | None = 0
    #: The ``program`` block ``describe`` answers with, or ``None`` for a
    #: describe that writes no result document at all.
    program: dict[str, Any] | None = None
    describe_exit: int = 0
    #: What one invocation does. Replaced by tests that want a failure,
    #: a crash, a hang or a non-conforming answer.
    run_program: Any = None
    containers: list[str] = field(default_factory=list)
    #: ``container target -> host source``, from the mounts of the
    #: ``docker run`` that created the session's container.
    mounts: dict[PurePosixPath, Path] = field(default_factory=dict)
    removed: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        image_tag = f"zephyr-4.4.0-{IMAGE_REVISION}"
        inspected = {
            "Id": "sha256:" + "c" * 64,
            # Both names docker itself reports for one image, because
            # both are what `Docker._inspect` matches its answer back to:
            # the tag `image ls` lists and the repo digest a context pins.
            "RepoTags": [f"{IMAGE}:{image_tag}"],
            "RepoDigests": [f"{IMAGE}@{IMAGE_DIGEST}"],
            "Config": {"Labels": dict(IMAGE_LABELS)},
        }
        # The same image under both names docker resolves it by: the
        # digest a context pins it with, and the tag `image ls` lists.
        self.images.setdefault(IMAGE_REFERENCE, inspected)
        self.images.setdefault(f"{IMAGE}:{image_tag}", inspected)
        self.listed = self.listed or [f"{IMAGE}:{image_tag}"]
        #: §2.2.1's static self-description: the default fake image
        #: carries none, so the backend exercises the invoke-describe
        #: fallback most tests are about. A test of the static path sets
        #: this to a describe result document (JSON text).
        self.static_description: str | None = None
        self.static_reads: list[str] = []
        if self.program is None:
            self.program = json.loads(json.dumps(PROGRAM))
        if self.run_program is None:
            self.run_program = conforming_program

    # -- the two seam functions ------------------------------------

    async def run(self, argv):
        self.calls.append(list(argv))
        rest = list(argv[1:])
        # A runtime that is not there is not there for every command, not
        # only for `docker version`. Faking it per command would let a
        # test pass against a server that probed once and then assumed.
        if self.version_status is None:
            return container.Completed(status=None, output="")
        if self.version_status != 0:
            return container.Completed(status=1, output="Cannot connect to the Docker daemon\n")
        if rest[:1] == ["version"]:
            return container.Completed(status=self.version_status, output="27.0.0\n")
        if rest[:2] == ["image", "ls"]:
            return container.Completed(status=0, output="\n".join(self.listed) + "\n")
        if rest[:2] == ["image", "inspect"]:
            references = [item for item in rest[4:]]
            lines = [
                json.dumps(self.images[reference])
                for reference in references
                if reference in self.images
            ]
            status = 0 if len(lines) == len(references) else 1
            return container.Completed(status=status, output="\n".join(lines))
        if rest[:1] == ["run"] and rest[-2:-1] == ["cat"]:
            # §2.2.1's static self-description read. The default fake
            # image carries none, so the backend falls back to invoking
            # describe — the path most tests exercise.
            self.static_reads.append(rest[-1])
            if self.static_description is None:
                return container.Completed(status=1, output="")
            return container.Completed(status=0, output=self.static_description)
        if rest[:1] == ["run"] and "--rm" in rest:
            return self._describe(rest)
        if rest[:1] == ["run"]:
            identity = f"{len(self.containers):064x}"
            self.containers.append(identity)
            # The session's mounts, learned the way the container learns
            # them. Targets are the same for every session now, so the
            # only way back to a host file is through this map — which is
            # exactly the container's own situation.
            for volume in [rest[i + 1] for i, item in enumerate(rest) if item == "--volume"]:
                source, target = volume.removesuffix(":ro").split(":")
                self.mounts[PurePosixPath(target)] = Path(source)
            return container.Completed(status=0, output=identity + "\n")
        if rest[:1] == ["rm"]:
            self.removed.append(rest[-1])
            return container.Completed(status=0, output="")
        raise AssertionError(f"the fake docker was asked something unexpected: {argv}")

    #: The request-document fields that name a directory the program is
    #: given (§5.2). Everything else that starts with a slash is not a
    #: path: ``required`` holds JSON pointers, and a ``trees`` entry may
    #: name a tree that lives in the image and is mounted by nobody.
    PATH_FIELDS = ("result", "out", "work", "tmp", "context", "events", "cancel")

    def host(self, path: str, *, required: bool = True) -> Path:
        """*path* as the host spells it, through this container's mounts.

        A path no ``--volume`` reaches does not exist inside a real
        container, so resolving it anyway would let the suite pass over
        the one defect this layout is about: a backend naming a directory
        the container cannot see.
        """
        inside = PurePosixPath(path)
        for target, source in self.mounts.items():
            if inside == target:
                return source
            if target in inside.parents:
                return source / inside.relative_to(target)
        if required:
            raise AssertionError(
                f"{path} is in the request document and no --volume of "
                f"{sorted(map(str, self.mounts))} mounts it: inside a real container "
                "that path does not exist"
            )
        return Path(path)

    def host_view(self, document):
        """The request document as the host can act on it.

        Every field of :data:`PATH_FIELDS` has to be reachable through a
        mount; a ``trees`` entry and a shared cache need not be, and are
        translated only when they are.
        """
        view = dict(document)
        for key in self.PATH_FIELDS:
            if key in view:
                view[key] = str(self.host(view[key]))
        if isinstance(view.get("trees"), dict):
            view["trees"] = {
                name: {**entry, "path": str(self.host(entry["path"], required=False))}
                for name, entry in view["trees"].items()
            }
        if isinstance(view.get("ccache"), dict):
            cache = view["ccache"]
            view["ccache"] = {**cache, "path": str(self.host(cache["path"], required=False))}
        return view

    async def spawn(self, argv, *, on_line):
        self.calls.append(list(argv))
        action, request_path = argv[-2], self.host(argv[-1])
        request = json.loads(request_path.read_text())
        self.invocations.append(Invocation(action=action, argv=list(argv), request=request))
        return self.run_program(action, self.host_view(request), on_line)

    # -- the throwaway describe container --------------------------

    def _describe(self, rest: list[str]) -> container.Completed:
        """``docker run --rm … /mcuhome/run describe <request>``.

        **The request document is read the way a container would have to
        read it**: only if a ``--volume`` in the composed argv actually
        makes its path reachable inside the container. The fake used to
        read it straight off the host filesystem, which made the probe
        mount invisible to the suite — it could be deleted with every
        test still green, and a real describe would then find no request
        document at all.
        """
        request = Path(rest[-1])
        volumes = [rest[index + 1] for index, item in enumerate(rest) if item == "--volume"]
        targets = [Path(volume.split(":")[1]) for volume in volumes]
        if not any(target == request or target in request.parents for target in targets):
            raise AssertionError(
                f"describe was given {request}, which no --volume of {volumes} mounts: "
                "inside a real container that path does not exist"
            )
        document = json.loads(request.read_text())
        if self.program is None:
            return container.Completed(status=self.describe_exit, output="")
        Path(document["result"]).write_text(
            json.dumps(
                {
                    "result": 1,
                    "status": "success",
                    "action": "describe",
                    "reason": None,
                    "error": None,
                    "program": self.program,
                }
            )
        )
        return container.Completed(status=self.describe_exit, output="")


def emit(request: dict[str, Any], name: str, seq: int, **fields: Any) -> None:
    """Append one contract §8 event to the invocation's events file."""
    with Path(request["events"]).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"event": name, "seq": seq, **fields}) + "\n")


def write_result(request: dict[str, Any], document: dict[str, Any]) -> None:
    Path(request["result"]).write_text(json.dumps(document))


def manifest_id(request: dict[str, Any]) -> str:
    """The context id, as a conforming program would compute it.

    Read out of ``manifest.yaml`` rather than recomputed: the fake is
    standing in for a program that measures the materialized context and
    arrives at the value the manifest declares, and re-deriving the
    normative rule in a test fixture is exactly the second
    implementation ADR 0020 decision 4 exists to prevent.
    """
    yaml = YAML(typ="safe", pure=True)
    data = yaml.load((Path(request["context"]) / "manifest.yaml").read_text())
    return str(data["id"])


def conforming_program(action: str, request: dict[str, Any], on_line) -> FakeProcess:
    """A build container that does everything contract v1 asks of it."""
    on_line(f"-- MCUHome {action} starting")
    emit(request, "invocation.started", 1, action=action)
    identity = manifest_id(request)
    emit(request, "context.checked", 2, context=identity)
    if action == "verify":
        write_result(
            request,
            {
                "result": 1,
                "status": "success",
                "action": "verify",
                "session": request["session"],
                "reason": None,
                "error": None,
                "context": identity,
            },
        )
        emit(request, "invocation.finished", 3, status="success")
        return FakeProcess(0)

    out = Path(request["out"])
    declared = []
    for name, payload in (
        ("firmware.hex", b":020000040000FA\n"),
        ("firmware.bin", b"\x00\x01\x02\x03"),
        ("build-report.json", json.dumps(BUILD_REPORT).encode()),
    ):
        (out / name).write_bytes(payload)
        declared.append(
            {
                "root": "out",
                "path": name,
                "role": "report" if name.endswith(".json") else "firmware",
                "hashes": {"sha256": hashlib.sha256(payload).hexdigest()},
            }
        )
    for index, entry in enumerate(declared, start=3):
        emit(
            request,
            "artifact.collected",
            index,
            role=entry["role"],
            path=entry["path"],
            size=len(entry["path"]),
        )
    on_line("-- build finished")
    write_result(
        request,
        {
            "result": 1,
            "status": "success",
            "action": "build",
            "session": request["session"],
            "reason": None,
            "error": None,
            "context": identity,
            # §5.4: an entry "for every patched layer", and no others.
            # A conforming program reports what it applied, and what it
            # applied is exactly the set of trees it was handed
            # writable — §4.1's `writable` is the backend saying "this
            # is your view to patch in".
            "layers": {
                layer: {"patchset": "sha256:" + "e" * 64}
                for layer, entry in request.get("trees", {}).items()
                if entry.get("writable")
            },
            "artifacts": declared,
        },
    )
    emit(request, "invocation.finished", 6, status="success")
    return FakeProcess(0)


#: The one artifact whose content the contract fixes (§7.2.1), for the
#: one consumer that needs it: the client that signs detached.
BUILD_REPORT = {
    "report": 1,
    "signing": {
        "signature_type": "ecdsa-p256",
        "arguments": {
            "version": "1.4.0+0",
            "header-size": 512,
            "align": 4,
            "slot-size": 983040,
        },
    },
}


@pytest.fixture(autouse=True)
def docker(monkeypatch) -> FakeDocker:
    """Docker, stubbed at the seam, for **every** test in this suite."""
    fake = FakeDocker()
    monkeypatch.setattr(container, "run_docker", fake.run)
    monkeypatch.setattr(container, "spawn_docker", fake.spawn)
    return fake


def write_sdk_package(directory: Path, version: str, *, entries: dict[str, bytes] | None = None):
    """Put one SDK package where the source list will find it.

    Returns its SHA-256, which is what a context has to pin: the name
    only makes a candidate findable, and the bytes are what make it the
    package (:mod:`mcuhome_buildserver.sdkstore`).
    """
    directory.mkdir(parents=True, exist_ok=True)
    archive = make_archive(entries or {"mcuhome/__init__.py": b"# the SDK\n"})
    path = directory / f"mcuhome-sdk-{version}.tar.zst"
    path.write_bytes(archive)
    return hashlib.sha256(archive).hexdigest()


def context_yaml(
    *,
    sdk_sha256: str = "a" * 64,
    version: str = "2.4.0",
    build_environment: str = IMAGE_REFERENCE_FORMAT3,
) -> bytes:
    """A ``context.yaml`` with the pins a test wants to move.

    *sdk_sha256* names a package that exists; *build_environment* is the
    image the client pinned, which is a hashed identity input — so a test
    that changes it is changing the context's identity, on purpose.
    """
    return (
        CONTEXT_YAML.replace("sha256: " + "a" * 64, f"sha256: {sdk_sha256}")
        .replace("version: 2.4.0", f"version: {version}")
        .replace(
            f"build_environment: {IMAGE_REFERENCE_FORMAT3}",
            f"build_environment: {build_environment}",
        )
        .encode()
    )


def device_model(
    zephyr_line: str = ZEPHYR_LINE, *, board: str = "nrf7002dk/nrf5340/cpuapp"
) -> bytes:
    """A ``model/device-model.json`` this server's model reader accepts.

    Most tests here send a stub under that name, because to this server a
    context file is bytes to hash and nothing else. The ``subprocess``
    profile makes the one exception and it is the reason this exists: it
    cannot honour a pinned image at all — the host *is* the environment —
    so it reads the model's Zephyr line and checks its own against that.
    A stub states no line and is passed over; a readable model is what
    puts the check in play.
    """
    return json.dumps(
        {
            "model_version": 2,
            "device": {
                "name": "test-device",
                "friendly_name": "Test Device",
                "board": board,
                "power_source": "mains",
            },
            "network": {"transport": "thread", "matter_enabled": True},
            "toolchain": {
                "zephyr_line": zephyr_line,
                "zephyr_constraint": f"~={zephyr_line}.0",
                "blob_usage": "auto",
                "blobs": {},
            },
            "sources": {
                "sdk": "sdk/mcuhome-sdk",
                "build_environment": "ghcr.io/mcu-home/build-container",
            },
            "hardware": {"buses": [], "peripherals": []},
            "endpoints": [],
            "channels": [],
            "build": {"snippets": [], "kconfig": []},
        }
    ).encode()


def buildable_context(sdk_sha256: str, **files: bytes) -> bytes:
    """A context this server can actually run a working action against.

    The difference from :func:`base_context` is one field: the SDK pin
    names a package the configured source directory holds. Everything
    else about a context is the same whether it is ever built or not,
    which is why only the tests that build need this one.
    """
    return make_archive({"context.yaml": context_yaml(sdk_sha256=sdk_sha256), **files})


async def collect(ws, *, until: str, timeout: float = 15) -> list[dict]:
    """Read frames until the *until* event, and return all of them.

    Event frames carry no frame id — they belong to an invocation rather
    than to a command — so a test that waits for one waits on its name.

    **The name is enough** since E58. The end of an invocation is
    ``invocation.verdict``, which is this server's own frame and no
    program's: contract §8's frozen registry keeps ``invocation.finished``
    for the program's announcement, so waiting for one can no longer stop
    on the other. Before the rename this helper had to filter on the
    absence of ``seq``, which is exactly the discrimination E58 replaced.
    """
    frames: list[dict] = []
    while True:
        frame = await ws.receive_json(timeout=timeout)
        frames.append(frame)
        if frame.get("type") == "event" and frame.get("event") == until:
            return frames


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
