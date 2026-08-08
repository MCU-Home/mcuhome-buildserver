# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The queue, the job records, and the process that does the work.

Three decisions shape this module and all three come from ADR 0006 or
from the measurement behind it.

**Compile lane = 1, as a hard default** (ADR 0006 decision 5). A cold
Zephyr+Matter build takes 1:23 at ``-j12`` and 1:12 at ``-j24`` on the
same sixteen-core machine: eleven seconds, because the serial
CMake/configure/link phases dominate. A build already owns the machine,
so running two at once trades every job's latency for no throughput.
``--slots`` raises it for an operator who knows better, and says so in
the log when it does — never silently.

**A job is a directory.** Everything about one build lives under
``<jobs root>/<job id>/``: the record, the model that was submitted, the
public key it was built against, the log sidecar and the build tree.
Retention is therefore ``rmtree`` and nothing else, restart recovery is a
directory scan, and there is no database to keep consistent with a
filesystem that a build writes to anyway.

**Nothing about the device is in the record.** ADR 0007 decision 2 is
honest that this server sees a device's commissioning passcode; that is
not a reason to leave copies of it around. The passcode arrives inside
``device-model.json``, which is written mode 0600 and **deleted the
moment the build process exits**. The job record keeps the device name,
the board and the versions — what a queue view needs and nothing a
credential could hide in. The log never sees the model, and neither does
a command line (:func:`mcuhome_buildserver.builder.build_environment`
explains why that matters).

The build directory keeps its own copy of the model, because the builder
writes one there as part of stage 4. That is the builder's file in the
builder's output, it is covered by the same retention, and it is the
reason the operating instruction of ADR 0007 decision 2 —
*operate build servers as trusted machines* — is in the README rather
than in a footnote.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import json
import logging
import os
import shutil
import signal
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from secrets import token_hex
from typing import Any

from mcuhome_buildserver import builder
from mcuhome_buildserver.logs import LOG_FILE, JobLog

__all__ = [
    "BUILD_DIR",
    "JOB_RECORD",
    "MODEL_FILE",
    "PUBLIC_KEY_FILE",
    "EngineSettings",
    "Job",
    "JobEngine",
    "JobOptions",
    "JobState",
    "JobStore",
    "new_job_id",
]

logger = logging.getLogger(__name__)

#: Names inside a job directory.
JOB_RECORD = "job.json"
MODEL_FILE = "device-model.json"
PUBLIC_KEY_FILE = "signing.pub"
BUILD_DIR = "build"

#: How long a killed build gets to die politely before it is killed
#: rudely. Long enough for ninja to reap its compilers, short enough that
#: a user pressing cancel sees something happen.
KILL_GRACE_SECONDS = 10.0

#: Largest ``--json`` document a build may print. The manifest is a few
#: kilobytes; anything approaching this is a builder that lost its way,
#: and reading it into memory unbounded is how a build server dies.
MAX_JSON_BYTES = 16 * 1024 * 1024

#: Pipe read size. Big enough not to wake the loop per line, small
#: enough that a follower sees output while the build is still running.
_READ_CHUNK = 64 * 1024


class JobState(enum.StrEnum):
    """Where a job is. A ``StrEnum`` because it is also the wire value."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    #: The server stopped while this job was queued or running. Not a
    #: failure of the build — a fact about the server — and kept as its
    #: own state so that a restart never reports a compile that never
    #: happened as one that broke.
    INTERRUPTED = "interrupted"

    @property
    def finished(self) -> bool:
        return self not in (JobState.QUEUED, JobState.RUNNING)


@dataclass(frozen=True)
class JobOptions:
    """The build options one job carries, after validation."""

    #: ADR 0003 decision 3: the container is the build environment.
    #: ``--native`` is the developer escape hatch, passed through.
    native: bool = False
    image: str | None = None
    snippets: tuple[str, ...] = ()
    #: Parallel compile jobs, or ``None`` for the server's own setting.
    jobs: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "native": self.native,
            "image": self.image,
            "snippets": list(self.snippets),
            "jobs": self.jobs,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> JobOptions:
        return JobOptions(
            native=bool(data.get("native", False)),
            image=data.get("image") or None,
            snippets=tuple(data.get("snippets") or ()),
            jobs=data.get("jobs"),
        )


@dataclass
class Job:
    """One build, from submission to artifacts.

    Serialized to ``job.json`` verbatim: what a client sees in a
    ``job_state_changed`` event is what is on disk, so a restart cannot
    show a different history than the live stream did.
    """

    id: str
    device: str
    board: str
    model_version: int
    options: JobOptions
    state: JobState = JobState.QUEUED
    created: float = field(default_factory=time.time)
    started: float | None = None
    finished: float | None = None
    exit_code: int | None = None
    #: A plain-language reason when the job did not succeed.
    error: str | None = None
    #: Bytes in the log sidecar, so a client knows what to ask for.
    log_bytes: int = 0
    #: ``build-manifest.json`` of the finished build, or ``None``.
    manifest: dict[str, Any] | None = None
    builder_version: str = builder.VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "device": self.device,
            "board": self.board,
            "model_version": self.model_version,
            "options": self.options.to_dict(),
            "state": str(self.state),
            "created": self.created,
            "started": self.started,
            "finished": self.finished,
            "exit_code": self.exit_code,
            "error": self.error,
            "log_bytes": self.log_bytes,
            "manifest": self.manifest,
            "builder_version": self.builder_version,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> Job:
        return Job(
            id=str(data["id"]),
            device=str(data.get("device", "")),
            board=str(data.get("board", "")),
            model_version=int(data.get("model_version", 0)),
            options=JobOptions.from_dict(data.get("options") or {}),
            state=JobState(data.get("state", JobState.INTERRUPTED)),
            created=float(data.get("created", 0.0)),
            started=data.get("started"),
            finished=data.get("finished"),
            exit_code=data.get("exit_code"),
            error=data.get("error"),
            log_bytes=int(data.get("log_bytes", 0)),
            manifest=data.get("manifest"),
            builder_version=str(data.get("builder_version", "")),
        )


def new_job_id(now: float | None = None) -> str:
    """A sortable, unguessable job id.

    Sortable because ``queue_status`` and the directory listing should
    agree about what "recent" means without parsing a timestamp field;
    unguessable in its tail because a job id addresses a job's artifacts
    and a predictable one is an invitation to enumerate.
    """
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now or time.time()))
    return f"{stamp}-{token_hex(3)}"


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------


class JobStore:
    """Job directories on disk, and the index over them."""

    def __init__(self, root: Path, *, keep: int = 20, ttl_days: float = 14.0) -> None:
        self.root = root
        self.keep = keep
        self.ttl_seconds = ttl_days * 86400.0
        self._jobs: dict[str, Job] = {}

    # -- paths -------------------------------------------------------

    def directory(self, job_id: str) -> Path:
        return self.root / job_id

    def record_path(self, job_id: str) -> Path:
        return self.directory(job_id) / JOB_RECORD

    def model_path(self, job_id: str) -> Path:
        return self.directory(job_id) / MODEL_FILE

    def public_key_path(self, job_id: str) -> Path:
        return self.directory(job_id) / PUBLIC_KEY_FILE

    def build_dir(self, job_id: str) -> Path:
        return self.directory(job_id) / BUILD_DIR

    def log_path(self, job_id: str) -> Path:
        return self.directory(job_id) / LOG_FILE

    # -- index -------------------------------------------------------

    def __contains__(self, job_id: object) -> bool:
        return job_id in self._jobs

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def all(self) -> list[Job]:
        """Every job, oldest first — which is also job-id order."""
        return [self._jobs[key] for key in sorted(self._jobs)]

    def load(self) -> list[Job]:
        """Read every job directory, and mark the unfinished ones.

        A job that was ``queued`` or ``running`` when the process died
        did not fail; the server did. ADR 0006 has no frame for "we lost
        it", so the record says :attr:`JobState.INTERRUPTED` and a client
        can tell the two apart.
        """
        self.root.mkdir(parents=True, exist_ok=True)
        interrupted: list[Job] = []
        for record in sorted(self.root.glob(f"*/{JOB_RECORD}")):
            try:
                data = json.loads(record.read_text(encoding="utf-8"))
                job = Job.from_dict(data)
            except (OSError, ValueError, KeyError):
                logger.warning("ignoring an unreadable job record: %s", record)
                continue
            self._jobs[job.id] = job
            if not job.state.finished:
                job.state = JobState.INTERRUPTED
                job.finished = job.finished or time.time()
                job.error = "The build server stopped while this job was still in the queue."
                interrupted.append(job)
                self.save(job)
        return interrupted

    def create(self, job: Job) -> Job:
        """Make the job's directory and write its first record."""
        directory = self.directory(job.id)
        directory.mkdir(parents=True, exist_ok=False)
        # The model inside carries commissioning credentials; nothing
        # else on the machine has any business reading them.
        with contextlib.suppress(OSError):
            directory.chmod(0o700)
        self._jobs[job.id] = job
        self.save(job)
        return job

    def save(self, job: Job) -> None:
        """Write ``job.json``, replaced in one step.

        A reader (a restart, an operator) must never catch a truncated
        record; a sibling plus ``os.replace`` makes that impossible.
        """
        path = self.record_path(job.id)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(json.dumps(job.to_dict(), indent=2) + "\n", encoding="utf-8")
            os.replace(temporary, path)
        except OSError:
            temporary.unlink(missing_ok=True)
            logger.exception("could not persist job %s", job.id)

    def forget_inputs(self, job_id: str) -> None:
        """Delete the submitted model and public key.

        Called as soon as the build process exits. Their only consumer
        was that process, and the model is the one file here that holds
        a device's Matter passcode.
        """
        for path in (self.model_path(job_id), self.public_key_path(job_id)):
            with contextlib.suppress(OSError):
                path.unlink(missing_ok=True)

    def prune(self, *, now: float | None = None) -> list[str]:
        """Apply ADR 0008 decision 4: a per-server cap and a time-to-live.

        Artifacts are large and fully reproducible, and the reference
        deployment writes them to an SD card. Keeping them forever buys
        nothing and wears the card out.

        Unfinished jobs are never pruned, whatever the cap says.
        """
        now = now or time.time()
        # By finish time, not by id: two jobs created in the same second
        # differ only in the random tail of their id, so id order is not
        # time order at the resolution retention cares about.
        finished = sorted(
            (job for job in self.all() if job.state.finished),
            key=lambda job: (job.finished or job.created, job.id),
        )
        doomed: list[Job] = []
        if self.ttl_seconds > 0:
            doomed += [
                job for job in finished if now - (job.finished or job.created) > self.ttl_seconds
            ]
        if self.keep >= 0:
            survivors = [job for job in finished if job not in doomed]
            doomed += survivors[: max(0, len(survivors) - self.keep)]

        removed: list[str] = []
        for job in doomed:
            try:
                shutil.rmtree(self.directory(job.id))
            except OSError:
                logger.warning("could not remove the job directory of %s", job.id)
                continue
            self._jobs.pop(job.id, None)
            removed.append(job.id)
        if removed:
            logger.info("retention removed %d job directories", len(removed))
        return removed


# --------------------------------------------------------------------------
# The engine
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class EngineSettings:
    """What the engine needs to know that is not part of a job."""

    #: Concurrent compiles. One, unless an operator raised it (ADR 0006
    #: decision 5).
    slots: int = 1
    #: Working directory for the builder — the west workspace top
    #: directory (ADR 0003: baked into the build-server image). ``None``
    #: lets the builder discover it the way the CLI does.
    workspace: Path | None = None
    #: ``MCUHOME_JOBS`` for the child. A dedicated build machine knows
    #: better than the builder's RAM heuristic (REMOTE-BUILD.md).
    build_jobs: int | None = None
    #: Default for jobs that do not ask: container (ADR 0003) unless a
    #: developer deployment says otherwise.
    native: bool = False
    #: Builder container image tag, or ``None`` for the builder's own
    #: default.
    image: str | None = None
    #: Seconds a single build may take before it is killed.
    timeout: float = 3600.0
    #: The builder command, so a wrapper can be put in front of it.
    command: tuple[str, ...] = builder.BUILDER_COMMAND


class JobEngine:
    """The queue, the workers, and the registry of running processes.

    Cancellation is why the registry exists. ``asyncio`` can cancel the
    coroutine that is *waiting* for a build, which leaves the build
    running and the machine busy; the only thing that stops a compile is
    a signal to the process group it owns. Each job's process is started
    in its own session (``start_new_session=True``) so that its group is
    exactly the job — ``cancel_job`` kills one build and cannot touch a
    neighbour, whatever the sub-make did with its children.
    """

    def __init__(
        self,
        store: JobStore,
        settings: EngineSettings,
        features: builder.BuilderFeatures,
        *,
        on_state_change: Callable[[Job], None] | None = None,
    ) -> None:
        self.store = store
        self.settings = settings
        self.features = features
        self._on_state_change = on_state_change
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._workers: list[asyncio.Task[None]] = []
        self._processes: dict[str, asyncio.subprocess.Process] = {}
        self._cancelled: set[str] = set()
        self._logs: dict[str, JobLog] = {}
        self._running = False

    # -- lifecycle ---------------------------------------------------

    async def start(self) -> None:
        interrupted = await asyncio.to_thread(self.store.load)
        for job in interrupted:
            logger.warning("job %s was interrupted by a restart", job.id)
            self._publish(job)
        await asyncio.to_thread(self.store.prune)
        self._running = True
        for index in range(max(1, self.settings.slots)):
            self._workers.append(
                asyncio.create_task(self._worker(), name=f"mcuhome-build-lane-{index}")
            )
        if self.settings.slots > 1:
            logger.warning(
                "compile lane raised to %d. One compile already owns a machine "
                "(ADR 0006 decision 5): measured 1:23 at -j12 against 1:12 at -j24 on "
                "sixteen cores, so parallel builds trade latency for no throughput.",
                self.settings.slots,
            )

    async def stop(self) -> None:
        self._running = False
        for job_id in list(self._processes):
            self._kill(job_id)
        for task in self._workers:
            task.cancel()
        for task in self._workers:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._workers.clear()
        for log in self._logs.values():
            log.close()
        self._logs.clear()

    # -- queue -------------------------------------------------------

    @property
    def slots(self) -> int:
        return max(1, self.settings.slots)

    def queued(self) -> list[Job]:
        return [job for job in self.store.all() if job.state is JobState.QUEUED]

    def running(self) -> list[Job]:
        return [job for job in self.store.all() if job.state is JobState.RUNNING]

    def submit(self, *, model: dict[str, Any], public_key: str, options: JobOptions) -> Job:
        """Queue a build for *model*. Writes the inputs, returns the record."""
        device = str(((model.get("device") or {}).get("name")) or "unnamed")
        board = str(((model.get("device") or {}).get("board")) or "")
        job = Job(
            id=new_job_id(),
            device=device,
            board=board,
            model_version=int(model.get("model_version", 0)),
            options=options,
        )
        self.store.create(job)
        self._write_inputs(job, model=model, public_key=public_key)
        self._queue.put_nowait(job.id)
        logger.info("queued job %s: %s for %s", job.id, job.device, job.board or "?")
        self._publish(job)
        return job

    def _write_inputs(self, job: Job, *, model: dict[str, Any], public_key: str) -> None:
        model_path = self.store.model_path(job.id)
        model_path.write_text(json.dumps(model, indent=2) + "\n", encoding="utf-8")
        with contextlib.suppress(OSError):
            model_path.chmod(0o600)
        self.store.public_key_path(job.id).write_text(
            public_key if public_key.endswith("\n") else public_key + "\n", encoding="utf-8"
        )

    def cancel(self, job_id: str) -> Job | None:
        """Stop one job. Returns the record, or ``None`` if there is none.

        A queued job is simply marked: the worker that eventually picks
        it up sees the state and skips it, which is cheaper and less
        racy than reaching into the queue.
        """
        job = self.store.get(job_id)
        if job is None or job.state.finished:
            return job
        if job.state is JobState.RUNNING:
            self._cancelled.add(job_id)
            self._kill(job_id)
            # The worker finishes the record when the process is reaped.
            return job
        self._finish(job, JobState.CANCELLED, error="Cancelled before it started.")
        return job

    # -- workers -----------------------------------------------------

    async def _worker(self) -> None:
        while True:
            job_id = await self._queue.get()
            try:
                job = self.store.get(job_id)
                # A job cancelled while it waited is already finished:
                # `cancel` marks it rather than reaching into the queue,
                # which is both cheaper and impossible to race.
                if job is None or job.state is not JobState.QUEUED:
                    continue
                await self._run(job)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("job %s crashed the lane it ran in", job_id)
                job = self.store.get(job_id)
                if job is not None and not job.state.finished:
                    self._finish(
                        job,
                        JobState.FAILED,
                        error="The build server failed while running this job; its log has more.",
                    )
            finally:
                self._queue.task_done()

    async def _run(self, job: Job) -> None:
        if not self.features.usable:
            self._finish(job, JobState.FAILED, error=self.features.refusal())
            return

        build_dir = self.store.build_dir(job.id)
        argv = builder.build_argv(
            model_file=self.store.model_path(job.id),
            build_dir=build_dir,
            public_key=self.store.public_key_path(job.id),
            native=job.options.native or self.settings.native,
            image=job.options.image or self.settings.image,
            snippets=job.options.snippets,
            command=self.settings.command,
        )
        env = builder.build_environment(
            jobs=job.options.jobs or self.settings.build_jobs,
            image=job.options.image or self.settings.image,
        )
        log = self.log_for(job.id)
        log.open()

        job.state = JobState.RUNNING
        job.started = time.time()
        self._persist(job)
        logger.info("job %s started: %s", job.id, " ".join(argv))

        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(self.settings.workspace) if self.settings.workspace else None,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Its own process group, so that killing this job cannot
                # reach any other process on the machine — and so that
                # killing it reaches every compiler it spawned.
                start_new_session=True,
            )
        except OSError as error:
            self._finish(
                job,
                JobState.FAILED,
                error=f"The build server could not start the builder: {error}.",
            )
            return

        self._processes[job.id] = process
        if job.id in self._cancelled:
            # Cancelled in the window between "queued" and "there is a
            # pid to signal". Without this the build would run to
            # completion and only *then* be reported as cancelled.
            self._kill(job.id)
        document = bytearray()
        try:
            await asyncio.wait_for(
                asyncio.gather(
                    self._pump(process.stdout, document.extend),
                    self._pump(process.stderr, log.append),
                    process.wait(),
                ),
                timeout=self.settings.timeout,
            )
        except TimeoutError:
            self._kill(job.id)
            with contextlib.suppress(Exception):
                await process.wait()
            self._reap(job, log, exit_code=None, document=b"", timed_out=True)
            return
        finally:
            # Whatever went wrong above, the compiler must not outlive
            # the coroutine that was supposed to be watching it.
            if process.returncode is None:
                self._kill(job.id)
            self._processes.pop(job.id, None)
            self.store.forget_inputs(job.id)

        self._reap(job, log, exit_code=process.returncode, document=bytes(document))

    async def _pump(self, stream: asyncio.StreamReader | None, sink: Any) -> None:
        """Move one pipe into *sink* until it closes.

        ``read`` rather than ``readline``: a compiler writes progress
        without newlines, and a follower that only saw whole lines would
        watch a still screen through the longest part of a build.
        """
        if stream is None:  # pragma: no cover - both pipes are always requested
            return
        total = 0
        overflowed = False
        while True:
            chunk = await stream.read(_READ_CHUNK)
            if not chunk:
                return
            total += len(chunk)
            if total > MAX_JSON_BYTES:
                # Only ever reachable for stdout: the log sidecar is a
                # file and has no such bound. Keep draining anyway — a
                # child that blocks on a full pipe never exits, and a
                # build that hangs is worse than one that is truncated.
                if not overflowed:
                    logger.warning(
                        "a build printed more than %d bytes on stdout; truncating",
                        MAX_JSON_BYTES,
                    )
                    overflowed = True
                continue
            sink(chunk)

    def _reap(
        self,
        job: Job,
        log: JobLog,
        *,
        exit_code: int | None,
        document: bytes,
        timed_out: bool = False,
    ) -> None:
        job.log_bytes = log.size
        job.exit_code = exit_code

        if timed_out:
            self._finish(
                job,
                JobState.FAILED,
                error=(
                    f"This build ran longer than the {self.settings.timeout:.0f} second "
                    "budget and was stopped."
                ),
            )
            return
        if job.id in self._cancelled:
            self._cancelled.discard(job.id)
            self._finish(job, JobState.CANCELLED, error="Cancelled while it was running.")
            return

        parsed = self._parse(document)
        if exit_code == 0 and isinstance(parsed, dict) and parsed.get("ok"):
            job.manifest = parsed.get("manifest")
            self._finish(job, JobState.SUCCEEDED)
            return
        self._finish(job, JobState.FAILED, error=self._failure_message(exit_code, parsed))

    @staticmethod
    def _parse(document: bytes) -> dict[str, Any] | None:
        if not document.strip():
            return None
        try:
            data = json.loads(document.decode("utf-8", errors="replace"))
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    @staticmethod
    def _failure_message(exit_code: int | None, parsed: dict[str, Any] | None) -> str:
        """What went wrong, in the builder's own words where there are any.

        ``mcuhome build --json`` prints the same error documents the
        dashboard renders in an editor gutter, so a configuration the
        build server rejects says the same thing it would have said
        locally — file, line, key and fix hint included.
        """
        if parsed is not None:
            errors = parsed.get("errors")
            if isinstance(errors, list) and errors:
                first = errors[0]
                message = first.get("message") if isinstance(first, dict) else None
                if message:
                    extra = f" (and {len(errors) - 1} more)" if len(errors) > 1 else ""
                    return f"{message}{extra}"
        return (
            f"The build failed (exit code {exit_code}). Its log has the compiler output."
            if exit_code is not None
            else "The build failed before it produced a result."
        )

    # -- state -------------------------------------------------------

    def _finish(self, job: Job, state: JobState, *, error: str | None = None) -> None:
        job.state = state
        job.finished = time.time()
        job.error = error
        # The live log is done: close its handle and forget it. A client
        # that wants the tail asks `follow_job` again and gets it from
        # the file, which is where it has been all along.
        log = self._logs.pop(job.id, None)
        if log is not None:
            job.log_bytes = log.size
            log.close()
        self._persist(job)
        logger.info("job %s %s%s", job.id, state, f": {error}" if error else "")
        with contextlib.suppress(Exception):
            self.store.prune()

    def _persist(self, job: Job) -> None:
        self.store.save(job)
        self._publish(job)

    def _publish(self, job: Job) -> None:
        if self._on_state_change is None:
            return
        try:
            self._on_state_change(job)
        except Exception:  # pragma: no cover - a listener must not break a build
            logger.exception("a job-state listener raised")

    # -- processes ---------------------------------------------------

    def process_for(self, job_id: str) -> asyncio.subprocess.Process | None:
        """The process running *job_id*, if one is. For diagnostics and tests."""
        return self._processes.get(job_id)

    def _kill(self, job_id: str) -> None:
        """Signal one job's whole process tree, and mean it.

        ``docker run`` without ``-d`` proxies signals to the container's
        first process, so this reaches a containerized build too; the
        escalation to ``SIGKILL`` is what covers the case where it does
        not.
        """
        process = self._processes.get(job_id)
        if process is None or process.returncode is not None:
            return
        logger.info("stopping job %s (pid %d)", job_id, process.pid)
        self._signal(process, signal.SIGTERM)
        asyncio.get_running_loop().call_later(KILL_GRACE_SECONDS, self._force_kill, job_id, process)

    def _force_kill(self, job_id: str, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        logger.warning("job %s ignored SIGTERM for %.0fs; killing", job_id, KILL_GRACE_SECONDS)
        self._signal(process, signal.SIGKILL)

    @staticmethod
    def _signal(process: asyncio.subprocess.Process, number: int) -> None:
        try:
            os.killpg(os.getpgid(process.pid), number)
        except (ProcessLookupError, PermissionError):
            with contextlib.suppress(ProcessLookupError):
                process.send_signal(number)
        except OSError:  # pragma: no cover - platforms without process groups
            with contextlib.suppress(ProcessLookupError):
                process.send_signal(number)

    # -- logs --------------------------------------------------------

    def log_for(self, job_id: str) -> JobLog:
        """The log of *job_id* — the same object for as long as it can grow.

        A job that has not finished gets a **cached** log, and that is
        load-bearing rather than an optimization: a client may follow a
        job while it is still queued, and its follower has to be
        registered on the object the worker will later write into. A
        fresh instance per call would have silently dropped that
        client's output the moment the build started.

        A finished job's log cannot grow, so it needs no identity: a
        throwaway reader over the file is exactly right, and it is why
        :meth:`_finish` drops the cached one instead of keeping a file
        handle open for every job in the history.
        """
        log = self._logs.get(job_id)
        if log is not None:
            return log
        log = JobLog(self.store.log_path(job_id))
        job = self.store.get(job_id)
        if job is not None and not job.state.finished:
            self._logs[job_id] = log
        return log

    # -- introspection -----------------------------------------------

    def status(self, *, limit: int = 50) -> dict[str, Any]:
        """What ``queue_status`` answers with."""
        jobs = self.store.all()
        active = [job for job in jobs if not job.state.finished]
        finished = [job for job in jobs if job.state.finished]
        # `[-0:]` is the whole list, which is the opposite of what a
        # caller asking for no history means.
        history = finished[-limit:] if limit > 0 else []
        return {
            "slots": self.slots,
            "queued": [job.id for job in jobs if job.state is JobState.QUEUED],
            "running": [job.id for job in jobs if job.state is JobState.RUNNING],
            "jobs": [job.to_dict() for job in (*active, *reversed(history))],
        }
