# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Child processes: the two impure functions both backend profiles use.

Every backend of build-container contract §1.2 ends up starting a child
process. In the ``container`` profile that child is a ``docker`` client
(:mod:`mcuhome_buildserver.container`); in the ``subprocess`` profile it
is the program itself (:mod:`mcuhome_buildserver.program`). What the two
share is *how* a child is run, and it is exactly two shapes:

* :func:`run_command` runs a short command to completion and answers its
  exit status and its merged output;
* :func:`spawn_command` starts a long one and hands back a
  :class:`Process` that streams its merged output line by line and stays
  addressable, so liveness policy can reach it.

The two are here rather than in either profile's module because a second
copy of them is a second place for the log pump, the line cap and the
"signalling a process that already exited is not news" rule to drift.
Each profile keeps its **own** seam function on top (``run_docker`` /
``spawn_docker``, ``run_program`` / ``spawn_program``), because a test
stubs a *profile* out and must not have to stub the other one with it.

**A spawned child is a process group, and a signal goes to the group.**
:func:`spawn_command` starts the child with ``start_new_session=True``,
so the child is a session and process-group leader and its pid *is* its
process-group id; :meth:`Process.terminate`, :meth:`Process.kill` and
:meth:`Process.stop` then signal that group rather than that one pid.
Signalling one pid is only ever right for a child with no children, and
in the ``subprocess`` profile the immediate child is the program — the
compile it starts (west, cmake, ninja, the compilers) hangs off it. A
SIGKILL that reached only the program would leave that tree running,
unreaped, against a session directory this server is about to delete;
§1.2 makes cancellability one of the two promises the ``subprocess``
profile keeps, and it is kept here or nowhere. The ``container`` profile
is unaffected by construction: its child is a short-lived ``docker exec``
client with no descendants of its own, so a group of one behaves exactly
as the single pid did.

**Merged output, always.** Contract §8 says the two streams *are* one
stream: "standard output and standard error together are one raw, opaque
log stream". A backend that split them would have to put them back
together to relay them.

**The environment is stated, never inherited.** Both functions take an
``env`` and hand it to the child; ``None`` means "this process's own
environment", which is what a ``docker`` client wants — it is this
server's own tool and reads this server's own ``DOCKER_HOST``. The
``subprocess`` profile never passes ``None``: what the *program* is
started with is composed on purpose
(:func:`mcuhome_buildserver.program.stated_environment`), because there
the child is not this server's tool but a build. What neither function
does is let a caller be vague about which of the two it meant.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

__all__ = [
    "MAX_LOG_LINE",
    "Completed",
    "LineSink",
    "Process",
    "run_command",
    "spawn_command",
]

logger = logging.getLogger(__name__)

#: The longest log line this server carries in one frame. Not a contract
#: number: §8 makes the log stream raw and opaque, so this is only how
#: much of one line is worth relaying before it stops being readable.
MAX_LOG_LINE = 64 * 1024

#: How long the log pump may still run after the child has exited. The
#: pump ends on EOF, and EOF needs *every* write end of the pipe closed —
#: which a descendant that inherited the child's stdout does not do when
#: the child dies. Long enough that the last lines of a build never race
#: the frame that says it ended, short enough that a descendant holding
#: fd 1 cannot make an invocation unfinishable.
_PUMP_GRACE_SECONDS = 2.0

#: How often the child is asked whether it has exited while something
#: still holds its log pipe. Not a busy-wait in the ordinary case: the
#: first rung of :meth:`ChildProcess._exited` is the transport's own
#: notification, and this interval only decides how quickly the fallback
#: notices an exit that notification is never going to report. It
#: matches the supervisor's own poll, which already quantizes the end of
#: an invocation to the same interval.
_EXIT_POLL_SECONDS = 0.2

#: How long the group has to stop itself between SIGTERM and SIGKILL in
#: :meth:`ChildProcess.stop`. Short, because by the time teardown runs
#: the cooperative path has already been offered (the cancel sentinel)
#: and a client is waiting on ``close-session`` — but not zero, because
#: ninja on SIGTERM stops its own edges, and a build tree that unwinds
#: itself leaves no half-written object files behind.
_STOP_GRACE_SECONDS = 2.0

#: How often :meth:`ChildProcess.stop` looks whether the group is gone.
#: It is a poll rather than a wait because what has to disappear is the
#: whole group and not the leader: the leader may exit long before the
#: compile it started does.
_STOP_POLL_SECONDS = 0.05


@dataclass(frozen=True)
class Completed:
    """One finished command.

    ``status`` is ``None`` when the program does not exist at all, which
    is the one failure that has to be told apart from a non-zero exit:
    "it is not installed" and "it said no" have different fixes.
    """

    status: int | None
    output: str

    @property
    def ok(self) -> bool:
        return self.status == 0


class Process(Protocol):
    """A command that is still running.

    Four operations and no more: three are what liveness policy needs
    (:mod:`mcuhome_buildserver.backend`) — wait for the exit status, ask
    politely, insist — and the fourth is what *teardown* needs, which is
    the two of them in order with a bounded wait in between. The ladder
    in :meth:`~mcuhome_buildserver.backend.SessionBackend._supervise` is
    driven by a clock it already owns and so spells its own escalation
    out; ``release`` has no clock of its own and must not grow one, since
    what it is escalating over is a process group only this object knows
    the id of.
    """

    async def wait(self) -> int: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    async def stop(self) -> None: ...


#: Where a command's merged output goes, line by line, as it arrives.
LineSink = Callable[[str], None]

#: What signalling a process that already exited raises. It is not news
#: and it is the ordinary end of the liveness ladder: SIGTERM goes out
#: on a timer, and the timer does not know the child finished a
#: millisecond earlier.
_ALREADY_GONE = (ProcessLookupError, OSError)


class ChildProcess:
    """The default :class:`Process`: one ``asyncio`` child, streamed.

    The child is a session leader (:func:`spawn_command` starts it with
    ``start_new_session=True``), so its pid *is* the id of the process
    group it and everything it starts belong to. That is the address
    every signal below uses.
    """

    def __init__(self, process: asyncio.subprocess.Process, pump: asyncio.Task[None]) -> None:
        self._process = process
        self._pump = pump
        #: The process group, which ``setsid`` made equal to the child's
        #: own pid. Read once, here, because after the child is reaped
        #: ``os.getpgid`` has nothing left to ask.
        self._pgid = process.pid

    async def wait(self) -> int:
        """The exit status, once the child has one — never later than that.

        **The child first, the pump second.** The pump ends on EOF and
        EOF means every write end of the pipe is closed, which is not the
        same event as the child exiting: a descendant that inherited fd 1
        holds the pipe open after its parent is gone, and awaiting the
        pump first would make an invocation whose child is provably dead
        wait forever for a verdict. So the status is taken from the
        child, and the pump is then given a bounded grace to hand over
        the last lines it has — which is all the ordering was ever for.
        """
        status = await self._exited()
        await self._drain()
        return status

    async def _exited(self) -> int:
        """The child's exit status, at the moment it has one.

        ``asyncio.subprocess.Process.wait()`` alone is *not* that moment,
        which is the part of this that has to be said out loud: asyncio
        resolves it once the child has exited **and** every pipe of its
        transport has been closed, and a descendant holding the inherited
        stdout keeps the second half from ever happening. So the wait is
        the fast path and ``returncode`` — set as soon as the child is
        reaped, whatever the pipes are doing — is what is asked whenever
        the transport has not answered yet.
        """
        waiter = asyncio.ensure_future(self._process.wait())
        try:
            while True:
                with contextlib.suppress(TimeoutError):
                    return await asyncio.wait_for(asyncio.shield(waiter), _EXIT_POLL_SECONDS)
                status = self._process.returncode
                if status is not None:
                    return status
        finally:
            waiter.cancel()

    async def _drain(self) -> None:
        """Let the pump finish, for at most :data:`_PUMP_GRACE_SECONDS`."""
        if self._pump.done():
            return
        try:
            await asyncio.wait_for(asyncio.shield(self._pump), _PUMP_GRACE_SECONDS)
        except TimeoutError:
            # Worth an operator's attention rather than a debug line: a
            # pipe still open after its owner died means some descendant
            # of the program outlived it, which is exactly the state the
            # process group above exists to prevent.
            logger.warning(
                "pid %d exited but its log pipe is still held after %.1fs; "
                "the rest of that output is dropped",
                self._process.pid,
                _PUMP_GRACE_SECONDS,
            )
            self._pump.cancel()

    def terminate(self) -> None:
        self._signal(signal.SIGTERM)

    def kill(self) -> None:
        self._signal(signal.SIGKILL)

    async def stop(self) -> None:
        """SIGTERM the group, wait a bounded moment, SIGKILL what is left.

        Teardown's own escalation, and the reason it is a group and not a
        pid: the program is not the build, it is what *started* the
        build. SIGTERM gives ninja the chance to stop its own edges;
        whatever is still in the group when the grace runs out is killed,
        because by then its session directory is being deleted under it.
        """
        self.terminate()
        deadline = time.monotonic() + _STOP_GRACE_SECONDS
        while self._group_alive():
            if time.monotonic() >= deadline:
                self.kill()
                return
            await asyncio.sleep(_STOP_POLL_SECONDS)

    def _signal(self, number: int) -> None:
        """One signal to the whole process group. Never raises.

        Suppressed for the reason :data:`_ALREADY_GONE` states: the
        liveness ladder signals on a timer, and the timer does not know
        the group emptied a millisecond earlier. A group id cannot be
        reused while any member of it lives, so the suppressed case is
        the group being gone and never a stranger being signalled.
        """
        with contextlib.suppress(*_ALREADY_GONE):
            os.killpg(self._pgid, number)

    def _group_alive(self) -> bool:
        """Is anything still in the group? Signal 0 asks without sending."""
        try:
            os.killpg(self._pgid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:  # pragma: no cover - the pgid is not ours any more
            # The group this object named is gone and the id has been
            # reused by a group that is somebody else's. Nothing to wait
            # for, and nothing that may be signalled.
            return False
        return True


async def run_command(argv: Sequence[str], *, env: Mapping[str, str] | None = None) -> Completed:
    """Run *argv* to completion, capturing its merged output.

    Everything that is not a build — probing a runtime, inspecting an
    image, asking a program to describe itself — is short, bounded and
    wants its output as a value, so it comes through here.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=None if env is None else dict(env),
        )
    except OSError:
        return Completed(status=None, output="")
    output, _ = await process.communicate()
    return Completed(status=process.returncode, output=output.decode("utf-8", errors="replace"))


async def spawn_command(
    argv: Sequence[str], *, on_line: LineSink, env: Mapping[str, str] | None = None
) -> Process:
    """Start *argv* and stream its merged output into *on_line*.

    Separate from :func:`run_command` because an invocation is neither
    short nor bounded: its output is the build log, which has to reach
    the client while the build runs rather than as a value at the end,
    and the process has to stay addressable so that liveness policy can
    reach it.

    Lines longer than :data:`MAX_LOG_LINE` are cut rather than buffered.
    A compiler that emits a megabyte on one line is not news worth
    holding memory for, and the frame cap on the wire would refuse it
    anyway.

    ``start_new_session=True`` is what makes the handle address the
    *build* and not only the process this server exec'd — see this
    module's docstring. It is unconditional rather than a parameter,
    because a caller choosing it per profile would be a caller able to
    get it wrong, and there is no child of this server that wants to
    share this server's own process group: a signal aimed at one would
    then reach the other.
    """
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        limit=MAX_LOG_LINE,
        env=None if env is None else dict(env),
        start_new_session=True,
    )
    pump = asyncio.ensure_future(_pump(process, on_line))
    return ChildProcess(process, pump)


async def _pump(process: asyncio.subprocess.Process, on_line: LineSink) -> None:
    """Read the child's merged output until it closes, line by line."""
    stream = process.stdout
    if stream is None:  # pragma: no cover - stdout is a PIPE above
        return
    while True:
        try:
            raw = await stream.readline()
        except (ValueError, asyncio.LimitOverrunError):  # pragma: no cover - very long line
            # `readline` raises rather than truncating once the buffer
            # limit is passed. The partial line is dropped, which is what
            # a raw opaque stream permits and what memory requires.
            continue
        if not raw:
            return
        on_line(raw.decode("utf-8", errors="replace").rstrip("\n"))
