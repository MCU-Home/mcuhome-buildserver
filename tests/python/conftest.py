# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures.

**Nothing here fakes a build environment, and that is the point.** The
build server is an orchestrator and never the build environment itself,
so there is no build to stand in for: what this suite exercises is the
transport, the bearer token, the session protocol and the *backend* — the
argv it composes, the documents it writes, and what it makes of the
documents that come back.

**The container runtime is stubbed at every seam and never runs**, which
is a hard rule of this suite rather than a convenience.
:class:`FakeDocker` replaces this server's own discovery seam
(:func:`mcuhome.buildserver.container.run_docker`) *and* both halves of
the workbench container profile's seam
(:func:`mcuhome.workbench.buildprocess.run_command` and
:func:`~mcuhome.workbench.buildprocess.spawn_process`, as
:mod:`mcuhome.workbench.containerbuild` resolves them). It is installed
by an **autouse** fixture: a test that forgot to ask for it would
otherwise start a real container on the machine running the suite, which
is exactly the failure mode this guards against.

**And so is the registry.** Choosing a build environment is the one step
that talks to a network — an image is found by its labels, which live in
a registry — so :class:`ScriptedRegistry` answers those questions too,
and the packages a context pins are resolved out of a local index this
suite writes. A test that reached ghcr.io would depend on what is
published there today.

The fake is a *conforming environment* by default: it reads the request
document through the mounts the composed ``docker run`` was given, writes
real files into ``out``, and answers with the result document the build
environment specification §6.2 defines. Tests that want a
non-conforming one replace one attribute.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
import zstandard
from mcuhome.model.buildenvironment import ENVIRONMENT_IMAGE_REPOSITORY, LABEL_PREFIX
from mcuhome.model.context import EnvironmentPin, PackagePin
from mcuhome.workbench import buildenvsession, containerbuild, ociregistry

from mcuhome.buildserver import container
from mcuhome.buildserver.app import ServerState, create_app
from mcuhome.buildserver.config import Config

TOKEN = "test-token-000000000000000000000000"

#: The build environment a context pins under format 4: two packages,
#: each a ``(name, version, sha256)`` triple. The tools entry is the
#: **family**, which is the ordinary pin — it resolves per platform
#: through an index, and its hash covers every platform's package.
WORKSPACE_PACKAGE = "mcuhome-build-workspace"
TOOLS_PACKAGE = "mcuhome-build-tools"
ENVIRONMENT_VERSION = "2.4.0"
WORKSPACE_SHA256 = "7c" * 32
TOOLS_SHA256 = "b9" * 32

#: The same pin as an object, for the tests that recompute a context ID
#: themselves rather than reading the server's answer.
ENVIRONMENT = EnvironmentPin(
    workspace=PackagePin(
        name=WORKSPACE_PACKAGE, version=ENVIRONMENT_VERSION, sha256=WORKSPACE_SHA256
    ),
    tools=PackagePin(name=TOOLS_PACKAGE, version=ENVIRONMENT_VERSION, sha256=TOOLS_SHA256),
)

#: The image that delivers that package set, as this suite's registry
#: publishes it: MCUHome's own repository, one tag, one digest. The tag
#: is a location and the digest is the identity — what a build runs and
#: what a verdict records is the digest.
IMAGE = ENVIRONMENT_IMAGE_REPOSITORY
IMAGE_TAG = f"{ENVIRONMENT_VERSION}-r1"
IMAGE_DIGEST = "sha256:" + "b" * 64
IMAGE_REFERENCE = f"{IMAGE}:{IMAGE_TAG}@{IMAGE_DIGEST}"
#: How the runtime is addressed for those bytes, and how a verdict
#: names them: by digest, never by the tag they were found under.
IMAGE_RUNNABLE = f"{IMAGE}@{IMAGE_DIGEST}"

#: The Zephyr release the image declares, and the generator constraint it
#: accepts contexts under (build environment specification §5).
ZEPHYR_VERSION = "4.4.0"
GENERATOR_CONSTRAINT = "mcuhome-workbench:"

#: The Zephyr line the device model in a context states. It is the
#: model's own field and not a pin: what a build runs is decided by the
#: packages the context names.
ZEPHYR_LINE = "4.4"


def environment_labels(
    *,
    zephyr: str = ZEPHYR_VERSION,
    generation: str = "3",
    constraint: str = GENERATOR_CONSTRAINT,
    workspace: str | None = None,
    tools: str | None = None,
) -> dict[str, str]:
    """The labels an image delivering this suite's package set carries.

    Specification §5.2: an image mirrors every member of the declaration
    as a label, and every ``packages.`` member carries a hash because an
    image is a delivery of exact bytes. *workspace* and *tools* replace a
    member outright, which is how a test states the near miss — the same
    packages under other bytes, which is a different environment.
    """
    labels = {
        f"{LABEL_PREFIX}spec-generation": generation,
        f"{LABEL_PREFIX}zephyr.version": zephyr,
        f"{LABEL_PREFIX}build-context.generator-constraint": constraint,
        f"{LABEL_PREFIX}packages.{WORKSPACE_PACKAGE}": (
            workspace
            if workspace is not None
            else f"{ENVIRONMENT_VERSION}@sha256:{WORKSPACE_SHA256}"
        ),
        f"{LABEL_PREFIX}packages.{TOOLS_PACKAGE}": (
            tools if tools is not None else f"{ENVIRONMENT_VERSION}@sha256:{TOOLS_SHA256}"
        ),
    }
    return {name: value for name, value in labels.items() if value}


IMAGE_LABELS = environment_labels()

CONTEXT_YAML = f"""\
context: 4
created: 2026-08-09T10:00:00Z
mcuhome:
  constraint: ^2.3.6
  version: 2.4.0
  package:
    url: https://packages.mcuhome.org/mcuhome-sdk-2.4.0.tar.zst
    sha256: {"a" * 64}
build_environment:
  workspace:
    name: {WORKSPACE_PACKAGE}
    version: {ENVIRONMENT_VERSION}
    sha256: {WORKSPACE_SHA256}
  tools:
    name: {TOOLS_PACKAGE}
    version: {ENVIRONMENT_VERSION}
    sha256: {TOOLS_SHA256}
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

    ``sdk_sources`` names the package directory :func:`package_source`
    fills: the SDK archive a context pins, and the index that says what
    the two environment packages are. A server with nothing in it
    refuses a build with ``sdk.unavailable``, which is the honest
    default and what the tests of that refusal use.
    """
    return Config(
        host="127.0.0.1",
        port=0,
        token=TOKEN,
        pair_file=None,
        context_root=tmp_path / "sessions",
        sdk_sources=(tmp_path / "packages",),
    )


# --------------------------------------------------------------------------
# The container runtime, as this suite has it
# --------------------------------------------------------------------------


class FakeProcess:
    """A step that has already finished, or refuses to.

    ``ignores_terminate`` is the rung above SIGTERM: a step that does not
    go away is the only reason SIGKILL exists, and one that always died
    of SIGTERM could never reach it.
    """

    output = ""
    started = True

    def __init__(self, code: int, *, hang: bool = False, ignores_terminate: bool = False) -> None:
        self._code = code
        self._hang = hang
        self._ignores_terminate = ignores_terminate
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        """``None`` while the scripted step is still running."""
        return None if self._hang else self._code

    def wait(self) -> int | None:
        while self._hang:
            time.sleep(0.005)
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


@dataclass
class Invocation:
    """One step this suite's runtime played, as the fake saw it."""

    action: str
    argv: list[str]
    request: dict[str, Any]


@dataclass
class FakeDocker:
    """The container runtime as this suite has it: argv in, scripted answers out.

    Every command either half of the seam composes lands in :attr:`calls`
    verbatim, which is what makes the composition assertable — it is the
    interface between the specification and the runtime, and the only way
    to check it without running anything.
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
    #: Which references this host has. ``None`` means "every image this
    #: fake knows about", which is the ordinary case.
    present: set[str] | None = None
    #: What one step does. Replaced by tests that want a failure, a
    #: crash, a hang or a non-conforming answer.
    run_program: Any = None
    #: References this host could fetch. Empty by default: most tests are
    #: about an image that is here or one that is not, and a fake that
    #: fetched anything on request would hide the difference.
    pullable: set[str] = field(default_factory=set)
    pulls: list[str] = field(default_factory=list)
    #: Scripted steps currently running in a container, so that removing
    #: it can end them — which is what a real ``docker rm --force`` does.
    running: list[Any] = field(default_factory=list)
    containers: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    #: ``container target -> host source``, from the mounts of the
    #: ``docker run`` that played the last step.
    mounts: dict[PurePosixPath, Path] = field(default_factory=dict)

    def __post_init__(self) -> None:
        inspected = {
            "Id": "sha256:" + "c" * 64,
            "RepoTags": [f"{IMAGE}:{IMAGE_TAG}"],
            "RepoDigests": [f"{IMAGE}@{IMAGE_DIGEST}"],
            "Config": {"Labels": dict(IMAGE_LABELS)},
        }
        for name in (IMAGE_RUNNABLE, f"{IMAGE}:{IMAGE_TAG}", IMAGE_REFERENCE):
            self.images.setdefault(name, inspected)
        self.listed = self.listed or [f"{IMAGE}:{IMAGE_TAG}"]
        self._lock = threading.Lock()
        #: How many step supervisors have been entered and left. Their
        #: difference is what :func:`no_supervisor_outlives_a_test`
        #: asserts away.
        self.supervisors_entered = 0
        self.supervisors_left = 0
        if self.run_program is None:
            self.run_program = conforming_environment

    # -- the seams -------------------------------------------------

    async def run(self, argv):
        """This server's discovery seam: asked from verb handlers, on the loop."""
        return self.answer(argv)

    def answer(self, argv, on_line=None):
        """The same runtime, answered synchronously.

        The container profile drives a runtime from a worker thread and
        its seam is therefore synchronous, while this server's own
        discovery happens on the event loop and its is not. One fake
        serves both, because they are one runtime.
        """
        argv = list(argv)
        self.calls.append(argv)
        rest = argv[1:]
        # A runtime that is not there is not there for every command, not
        # only for `docker version`. Faking it per command would let a
        # test pass against a server that probed once and then assumed.
        if self.version_status is None:
            return container.Completed(status=None, output="")
        if self.version_status != 0:
            return container.Completed(status=1, output="Cannot connect to the Docker daemon\n")
        if rest[:1] == ["version"]:
            return container.Completed(status=self.version_status, output="29.7.2\n")
        if rest[:2] == ["image", "ls"]:
            return container.Completed(status=0, output="\n".join(self.listed) + "\n")
        if rest[:2] == ["image", "inspect"]:
            return self._inspect(rest)
        if rest[:1] == ["pull"]:
            return self._pull(rest[-1], on_line)
        if rest[:1] == ["rm"]:
            return self._remove(rest[-1])
        raise AssertionError(f"the fake runtime was asked something unexpected: {argv}")

    def spawn(self, argv, on_line=None):
        """The step, which is spawned rather than run.

        It plays the scripted environment synchronously and answers with
        a handle — the shape a supervisor walks over. The request
        document is read **through the mounts** the composed ``docker
        run`` was given: a path no ``--volume`` reaches does not exist
        inside a real container, and resolving one anyway would let this
        suite pass over the one defect the layout is about.
        """
        argv = list(argv)
        self.calls.append(argv)
        assert argv[1] == "run", f"only a step is spawned: {argv}"
        self.mounts = {}
        for volume in [argv[i + 1] for i, item in enumerate(argv) if item == "--volume"]:
            source, target = volume.removesuffix(":ro").rsplit(":", 1)
            self.mounts[PurePosixPath(target)] = Path(source)
        identity = argv[argv.index("--name") + 1] if "--name" in argv else f"{len(self.calls):x}"
        self.containers.append(identity)
        request = json.loads(self.host(containerbuild.REQUEST_TARGET).read_text("utf-8"))
        self.invocations.append(
            Invocation(action=request.get("action", ""), argv=argv, request=request)
        )
        process = self.run_program(request, self.host(containerbuild.OUT_TARGET), on_line)
        with self._lock:
            self.running.append(process)
            removed = identity in self.removed
        if removed:
            process.kill()
        return process

    def host(self, path: str, *, required: bool = True) -> Path:
        """*path* as the host spells it, through this container's mounts."""
        inside = PurePosixPath(path)
        for target, source in self.mounts.items():
            if inside == target:
                return source
            if target in inside.parents:
                return source / inside.relative_to(target)
        if required:
            raise AssertionError(
                f"{path} is reached by no --volume of {sorted(map(str, self.mounts))}: "
                "inside a real container that path does not exist"
            )
        return Path(path)

    def _inspect(self, rest: list[str]) -> container.Completed:
        references = rest[2:]
        # `docker image inspect --format …` puts the format in front of
        # the references; the profile's presence check passes none.
        if references[:1] == ["--format"]:
            references = references[2:]
        known = [name for name in references if name in self.images and self._here(name)]
        lines = [json.dumps(self.images[name]) for name in known]
        status = 0 if len(known) == len(references) and references else 1
        return container.Completed(status=status, output="\n".join(lines))

    def _here(self, reference: str) -> bool:
        return self.present is None or reference in self.present

    def _pull(self, reference: str, on_line) -> container.Completed:
        """``docker pull <reference>``, as scripted by :attr:`pullable`."""
        self.pulls.append(reference)
        relay = on_line if on_line is not None else (lambda _line: None)
        if reference not in self.pullable:
            relay(f"Error response from daemon: manifest for {reference} not found")
            return container.Completed(status=1, output="not found")
        relay("Status: Downloaded newer image")
        if self.present is not None:
            self.present.add(reference)
        return container.Completed(status=0, output="")

    def _remove(self, identity: str) -> container.Completed:
        """Removing a container ends what was running in it.

        Which is the whole reason the ladder's last rung is a teardown
        and not a signal, and what makes it testable at all: a fake that
        let a scripted step outlive its container would hang every test
        that ends a session while a build is still running.
        """
        with self._lock:
            self.removed.append(identity)
            ending = list(self.running)
            self.running.clear()
        for process in ending:
            process.kill()
        return container.Completed(status=0, output="")

    # -- what the suite asserts on -----------------------------------

    @property
    def step(self) -> list[str]:
        """The argv of the run that played the last step."""
        return next(argv for argv in reversed(self.calls) if argv[1:2] == ["run"])

    @property
    def volumes(self) -> list[str]:
        """Every ``--volume`` argument of that run."""
        return [self.step[i + 1] for i, item in enumerate(self.step) if item == "--volume"]

    def supervisor_entered(self) -> None:
        with self._lock:
            self.supervisors_entered += 1

    def supervisor_left(self) -> None:
        with self._lock:
            self.supervisors_left += 1

    @property
    def supervising(self) -> int:
        """How many step supervisors are running right now."""
        with self._lock:
            return self.supervisors_entered - self.supervisors_left


class ScriptedRegistry:
    """A container registry that answers with one image, and counts the asking.

    Choosing an image is the one step of a container build that talks to
    the network — a registry is asked which tags a repository publishes
    and what each one's labels say — and a suite whose promise is one
    second may not.

    The labels are the whole answer: an image serves a context by
    declaring exactly the package set it pins (§5.2), so a test moves the
    *labels* to move the outcome.
    """

    def __init__(
        self,
        *,
        digest: str = IMAGE_DIGEST,
        tags: tuple[str, ...] = (IMAGE_TAG,),
        labels: dict[str, str] | None = None,
        repositories: dict[str, dict[str, str]] | None = None,
    ) -> None:
        self.digest = digest
        self.tags_ = tags
        self.labels_ = IMAGE_LABELS if labels is None else labels
        #: Per-repository labels, for the tests about an allowlist with
        #: more than one entry in it. A repository not named here answers
        #: with :attr:`labels_`.
        self.repositories = repositories or {}
        self.asked: list[str] = []

    def tags(self, reference):
        if self.repositories and reference.repository not in self.repositories:
            from mcuhome.workbench.ociregistry import RegistryError

            raise RegistryError(f"{reference.repository} publishes nothing")
        return self.tags_

    def facts(self, reference, *, platform=None):
        del platform  # one architecture is enough for a suite about a protocol
        self.asked.append(str(reference))
        labels = self.repositories.get(reference.repository, self.labels_)
        return ociregistry.ImageFacts(digest=self.digest, labels=dict(labels))


# --------------------------------------------------------------------------
# A conforming build environment
# --------------------------------------------------------------------------


#: The one artifact whose content the build actions document fixes, for
#: the one consumer that needs it: the client that signs detached.
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


def write_result(request: dict[str, Any], out: Path, document: dict[str, Any]) -> None:
    """Put one result document where §6.2 says it goes."""
    name = f"{buildenvsession.RESULT_PREFIX}{request['invocation_id']}"
    (out / f"{name}{buildenvsession.RESULT_SUFFIX}").write_text(json.dumps(document), "utf-8")


def conforming_environment(request: dict[str, Any], out: Path, on_line) -> FakeProcess:
    """A build environment that does everything the specification asks of it."""
    relay = on_line if on_line is not None else (lambda _line: None)
    relay(f"-- MCUHome {request['action']} starting")
    for name, payload in (
        ("firmware.hex", b":020000040000FA\n"),
        ("firmware.bin", b"\x00\x01\x02\x03"),
        ("build-report.json", json.dumps(BUILD_REPORT).encode()),
    ):
        (out / name).write_bytes(payload)
    relay("-- build finished")
    write_result(
        request,
        out,
        {
            "spec_generation": buildenvsession.SPEC_GENERATION,
            "invocation_id": request["invocation_id"],
            "status": "success",
            "message": "",
            "artifacts": ["build-report.json", "firmware.bin", "firmware.hex"],
        },
    )
    return FakeProcess(0)


def failing_environment(request: dict[str, Any], out: Path, on_line) -> FakeProcess:
    """One that ran and did not produce what it was asked for."""
    relay = on_line if on_line is not None else (lambda _line: None)
    relay("-- the compiler said no")
    write_result(
        request,
        out,
        {
            "spec_generation": buildenvsession.SPEC_GENERATION,
            "invocation_id": request["invocation_id"],
            "status": "failure",
            "message": "the build failed",
            "artifacts": [],
        },
    )
    return FakeProcess(1)


def silent_environment(request: dict[str, Any], out: Path, on_line) -> FakeProcess:
    """One that ends without writing a result document at all."""
    del request, out, on_line
    return FakeProcess(1)


def hanging_environment(request: dict[str, Any], out: Path, on_line) -> FakeProcess:
    """One that never ends by itself, so a ladder has something to walk."""
    del request, out, on_line
    return FakeProcess(0, hang=True)


@pytest.fixture(autouse=True)
def docker(monkeypatch) -> FakeDocker:
    """The container runtime, stubbed at **every** seam, for every test.

    Three of them, because two different things drive one runtime: this
    server's own discovery (asynchronous, on the event loop) and the
    workbench container profile's driving of a step (synchronous, in a
    worker thread). A suite that stubbed only its own would have the
    profile start real containers.
    """
    fake = FakeDocker()
    monkeypatch.setattr(container, "run_docker", fake.run)
    monkeypatch.setattr(containerbuild, "run_command", fake.answer)
    monkeypatch.setattr(containerbuild, "spawn_process", _spawner(fake))

    # And a fourth seam, which fakes nothing: `Step.run` is what the
    # backend hands to `asyncio.to_thread`, so entering and leaving it is
    # exactly "a worker thread of the loop's default executor is
    # supervising a build". Counting it is the only way a test can see
    # that thread at all — a pool thread stays alive between work items,
    # so `threading.enumerate` cannot tell a busy one from an idle one.
    supervise = buildenvsession.Step.run

    def counted(step, **kwargs):
        fake.supervisor_entered()
        try:
            return supervise(step, **kwargs)
        finally:
            fake.supervisor_left()

    monkeypatch.setattr(buildenvsession.Step, "run", counted)
    return fake


def _spawner(fake: FakeDocker):
    """``spawn_process``' keyword shape over the fake's positional one."""

    def spawn(argv, *, env=None, cwd=None, on_line=None):
        del env, cwd
        return fake.spawn(argv, on_line)

    return spawn


@pytest.fixture(autouse=True)
def registry(monkeypatch) -> ScriptedRegistry:
    """No test of this suite reaches a container registry.

    The same safety net as :func:`docker` and for the same reason:
    resolving a build environment goes over HTTPS, and a test that forgot
    to stub it would quietly depend on ghcr.io being up and on what is
    published there today.
    """
    scripted = ScriptedRegistry()
    monkeypatch.setattr(ociregistry.Registry, "tags", scripted.tags)
    monkeypatch.setattr(ociregistry.Registry, "facts", scripted.facts)
    return scripted


@pytest.fixture(autouse=True)
def no_package_registry(monkeypatch):
    """And none reaches the package registry either.

    A build server resolves the packages a context pins out of its
    operator's own directories first and falls through to
    ``packages.mcuhome.org`` behind them. Every test that means to
    succeed writes what it pins into the configured package directory,
    so the fall-through is the path of a test about **not** finding
    something — and it answers the way an unreachable registry does,
    which is what the server's own refusal is built on.
    """

    from mcuhome.workbench import packageregistry

    def refuse(*_args, **_kwargs):
        raise packageregistry.PackageRegistryError(
            "no package registry is reachable from this suite",
            hint="write what a context pins into the configured package directory",
        )

    monkeypatch.setattr(packageregistry, "registry_for", refuse)


@pytest.fixture(autouse=True)
def no_supervisor_outlives_a_test(docker: FakeDocker):
    """Fail the test that leaves an invocation supervisor running.

    A session is released when its container is gone **and** the thread
    supervising it has returned; the second half used to be nobody's
    job, and what it cost was not a failing test but a passing suite
    that would not exit — asyncio waits five minutes for the default
    executor at interpreter exit and then says so in a warning, long
    after the test that caused it is out of sight.

    So it is stated here, once, for every test: at teardown the last
    session is over — closed by the test, reaped by admission or taken
    away by the app's own cleanup — and no supervisor of it may still be
    running. The assertion is immediate and names the test that did it.
    """
    yield
    running = docker.supervising
    assert running == 0, (
        f"{running} invocation supervisor(s) still running when the test ended: a worker "
        "thread of the event loop's default executor outlived the session it belonged to, "
        "which is what makes the suite hang at interpreter exit instead of failing here"
    )


def write_sdk_package(directory: Path, version: str, *, entries: dict[str, bytes] | None = None):
    """Put one SDK package where the source list will find it.

    Returns its SHA-256, which is what a context has to pin: the name
    only makes a candidate findable, and the bytes are what make it the
    package.

    The index of the two **environment** packages goes in beside it
    (:func:`write_package_index`), because a context pins those by name
    and hash and the tools entry is a family: resolving it to this host's
    concrete package is what an index is for, and a directory without one
    would send the resolution to the registry this suite forbids.
    """
    directory.mkdir(parents=True, exist_ok=True)
    archive = make_archive(entries or {"mcuhome/__init__.py": b"# the SDK\n"})
    path = directory / f"mcuhome-sdk-{version}.tar.zst"
    path.write_bytes(archive)
    write_package_index(directory)
    return hashlib.sha256(archive).hexdigest()


def write_package_index(directory: Path) -> None:
    """The index that says what this suite's environment packages are.

    Only the two environment packages, and deliberately not the SDK: the
    SDK is found by its conventional filename, and an index that named it
    would have to state its hash, which every test that writes one picks
    itself. One document, one job.
    """
    directory.mkdir(parents=True, exist_ok=True)
    packages = {}
    for name, digest in ((WORKSPACE_PACKAGE, WORKSPACE_SHA256), (TOOLS_PACKAGE, TOOLS_SHA256)):
        filename = f"{name}-{ENVIRONMENT_VERSION}.tar.zst"
        (directory / filename).write_bytes(f"{name} {ENVIRONMENT_VERSION}\n".encode())
        packages[name] = {
            ENVIRONMENT_VERSION: {
                "file": filename,
                "sha256": digest,
                "size": len(f"{name} {ENVIRONMENT_VERSION}\n"),
            }
        }
    (directory / "index.json").write_text(json.dumps({"packages": packages}), encoding="utf-8")


@pytest.fixture
def package_source(config: Config) -> Path:
    """The operator's package directory, with the environment index in it.

    Every test that reaches image selection needs it, because that is
    where the tools family is resolved to a concrete package. Tests that
    also need an SDK package add one with :func:`write_sdk_package`.
    """
    directory = config.sdk_sources[0]
    write_package_index(directory)
    return directory


def context_yaml(
    *,
    sdk_sha256: str = "a" * 64,
    version: str = "2.4.0",
    tools_sha256: str = TOOLS_SHA256,
    build_environment: str | None = None,
) -> bytes:
    """A ``context.yaml`` with the pins a test wants to move.

    *sdk_sha256* names a package that exists; *tools_sha256* is one of
    the six hashed members of the environment pin, so a test that changes
    it is changing the context's identity, on purpose.
    *build_environment* replaces the whole block verbatim, for the tests
    that need a document the format does not describe.
    """
    text = CONTEXT_YAML.replace("sha256: " + "a" * 64, f"sha256: {sdk_sha256}").replace(
        "version: 2.4.0", f"version: {version}"
    )
    text = text.replace(f"sha256: {TOOLS_SHA256}", f"sha256: {tools_sha256}")
    if build_environment is not None:
        head, _, tail = text.partition("build_environment:")
        _, _, rest = tail.partition("target:")
        text = f"{head}build_environment: {build_environment}\ntarget:{rest}"
    return text.encode()


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
                "build_workspace": "build-workspace/mcuhome-build-workspace",
                "build_tools": "build-tools/mcuhome-build-tools",
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
    which is why only the tests that build need this one — and the
    generator declaration is here for the same reason it is in every
    context a workbench writes: without it there is no build context at
    all (build environment specification §9), and this server refuses one.
    """
    return make_archive(
        {
            "build-context.json": BUILD_CONTEXT_JSON.encode(),
            "context.yaml": context_yaml(sdk_sha256=sdk_sha256),
            **files,
        }
    )


async def collect(ws, *, until: str, timeout: float = 15) -> list[dict]:
    """Read frames until the *until* event, and return all of them.

    Event frames carry no frame id — they belong to an invocation rather
    than to a command — so a test that waits for one waits on its name.

    **The name is enough.** The end of an invocation is
    ``invocation.verdict``, which is this server's own frame and no
    program's: the program's own frozen event vocabulary keeps
    ``invocation.finished`` for its own announcement, so waiting for one
    can no longer stop on the other. Before the rename this helper had to
    filter on the absence of ``seq``, which is exactly the discrimination
    the rename replaced.
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


#: The generator declaration every context created by a workbench
#: carries. Part of the base fixture rather than an extra, so what the
#: tests push at the server has the shape a real client sends.
BUILD_CONTEXT_JSON = '{\n  "generator": "mcuhome-workbench:0.1.0.dev0"\n}\n'
BUILD_CONTEXT_BYTES = BUILD_CONTEXT_JSON.encode()


def base_context(**files: bytes) -> bytes:
    """The usual base context: ``context.yaml``, the generator, plus *files*."""
    return make_archive(
        {
            "build-context.json": BUILD_CONTEXT_JSON.encode(),
            "context.yaml": CONTEXT_YAML.encode(),
            **files,
        }
    )


#: The typed code a refusal to serve a context comes back under.
BUILDER_UNSATISFIABLE = "version.builder-unsatisfiable"

#: And the one an image from a repository this operator does not allow
#: comes back under.
ENVIRONMENT_DENIED = "policy.environment-denied"


def refused_with(frame: dict, code: str) -> bool:
    """Whether *frame* is this server refusing with *code*."""
    return frame.get("type") == "error" and frame.get("error", {}).get("code") == code


async def send_archive(
    ws,
    verb: str,
    session_id: str,
    archive: bytes,
    *,
    seen: list | None = None,
    **payload,
) -> dict:
    """Announce *archive*, push it as binary frames, return the answer.

    The two halves of the wire shape in one helper, because every test
    that touches the context path needs both and neither is interesting
    on its own. The chunking is deliberate — several frames per archive,
    since "multiple frames allowed" is part of the decided shape and a
    receiver that only ever saw one would not be exercised.

    *seen* collects every frame read on the way, for the tests that are
    about what arrives **while** a verb is still in flight rather than
    about its answer.
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
        if seen is not None:
            seen.append(frame)
        if frame.get("id") == frame_id:
            return frame
