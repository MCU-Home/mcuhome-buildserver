# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The program, and the one seam every start of it goes through.

This module is to the ``subprocess`` profile what
:mod:`mcuhome_buildserver.container` is to the ``container`` profile: it
composes argv, it starts it, and it says what came back; it knows nothing
about sessions, contexts or the invocation ABI. The split is what makes
:class:`~mcuhome_buildserver.subprocessbackend.SubprocessBackend` testable
without ever running a compiler.

**There is no image here and no runtime to probe.** Contract §2 says so
in as many words — "In the ``subprocess`` profile there is no image; the
backend knows its own program's path and its own identity, and answers
the same questions from ``describe``" — and §2.2 says what is left of
§2's requirements: "the backend invokes its own program by a path it
configures. The argv shape, the request document, the result document and
the exit codes are identical; only the path is the backend's business."

So this module has exactly two jobs.

**The path.** By default the program is the installed MCUHome compiler,
reached through the interpreter this server itself runs on:
``<sys.executable> -m mcuhome.compiler.abi``. That is the same entry point
``containers/builder/run`` execs inside the image, which is the whole
reason the launcher there is three lines — the ABI lives in the module,
"because the ``subprocess`` profile (§1.2) runs the same code with no
image and no launcher around it" (that file's own comment). An operator
who has a different program says so with ``--program``, and it is then
invoked as ``<path> <action> <request>`` with nothing in front of it: a
third party may write the program in any language, and a configured path
that had to be a Python module would be that promise broken at the first
Go binary.

**The environment.** The child is started with a **stated** environment
and never with an implicitly inherited one. That is not ceremony: the
program assembles its own build environment (§6.1) out of the paths the
request document names, and the only thing the backend owes it is the
environment it is to start its children from. In this profile that
statement is *composed*, out of a named list of this server's own
variables — see :func:`stated_environment` for which and why. It is
made **once**, when this object is built, for the reason
``mcuhome.compiler.abi`` states about its own modules: one process serves
several sessions, and a call-time ``os.environ`` is what makes two of
them answer each other's questions.

What this module deliberately does **not** do is any of the container
profile's mechanics. There is no ``--network=none`` to pass, because
there is no namespace to take the network away from; there are no
``--memory`` or ``--pids-limit`` flags, because there is no cgroup this
server creates; and there is no ``--user``, because the program already
runs as this server's own user — which is what makes everything it writes
readable back. §1.2 names those three absences as the profile's reduced
promises, and this module is where two of them stop being available at
all rather than being quietly skipped.

There is a **fourth** thing this module does deliberately, and it
belongs next to those three because it is the one place this profile is
*narrower* than what the shared filesystem would allow: the program does
not get this server's environment. The container profile never had to
decide it — ``docker exec`` passes no ``-e``, so the server's
environment reaches the docker client and stops there — and here the
whole environment would reach west, cmake, ninja and every compiler
child, ``MCUHOME_BUILDSERVER_TOKEN`` included. That token authenticates
every client of this server, this server's own ``--help`` recommends the
environment as the channel to supply it through, and a build step that
prints its environment would put it in a raw log stream a client
persists. §5.1 says "no environment variable carries information the
program needs", so nothing conforming can miss what is left out.
"""

from __future__ import annotations

import logging
import os
import shlex
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from mcuhome_buildserver.processes import (
    Completed,
    LineSink,
    Process,
    run_command,
    spawn_command,
)

__all__ = [
    "DEFAULT_PROGRAM",
    "STATED_NAMES",
    "STATED_PREFIXES",
    "Program",
    "invocation_command",
    "program_argv",
    "run_program",
    "spawn_program",
    "stated_environment",
]

logger = logging.getLogger(__name__)

#: The program this server invokes when an operator names none: the
#: installed MCUHome compiler, through the interpreter this server runs
#: on. ``sys.executable`` rather than ``python3`` on ``PATH``, because a
#: build server installed in a virtual environment must reach *its own*
#: compiler and not whichever interpreter the operator's shell resolves
#: — the same argument §2.2 makes for not looking ``/mcuhome/run`` up on
#: ``PATH`` inside an image.
DEFAULT_PROGRAM: tuple[str, ...] = (sys.executable, "-m", "mcuhome.compiler.abi")


def program_argv(configured: Path | None) -> tuple[str, ...]:
    """What starts the program: the operator's path, or the default.

    A configured program is invoked **as itself**, with no interpreter in
    front of it and nothing looked up on ``PATH``. Both halves of that
    are §2.2's rule about ``/mcuhome/run`` read in the profile where
    there is no image to fix a path: a bare name would be a promise about
    somebody else's filesystem, and an interpreter this server chose
    would make MCUHome's implementation language a requirement on a
    program the contract lets a third party write in any language.
    """
    return DEFAULT_PROGRAM if configured is None else (str(configured),)


def invocation_command(program: Sequence[str], action: str, request: Path) -> list[str]:
    """The whole invocation of contract §5.1, as an argv.

    ``<program> <action> <absolute path of the request document>`` —
    "exactly two positional operands, both mandatory, **never a flag**".
    This argv is frozen and never grows: extensibility runs through the
    request document, because an unknown JSON field costs an older
    program nothing while a new operand breaks every program that does
    not know it.

    Separate from :class:`Program` so that the composed command can be
    asserted without running anything, which is the same reason
    :func:`~mcuhome_buildserver.container.session_run_command` is
    separate from the object that runs it: the composed argv is the
    interface between the contract and the host, and it is worth pinning
    line by line.
    """
    return [*program, action, str(request)]


#: The variables of this server's environment the program is started
#: with, by exact name. Every one of them is a property of *the host as a
#: build environment* rather than of this server as a service, which is
#: the line the list is drawn on:
#:
#: * ``PATH`` — how west, gn, zap and the compilers are reached at all;
#:   §6.1's worked example assumes the toolchain is *findable*, and on a
#:   host that is what ``PATH`` means.
#: * ``HOME`` — git, west and ccache all read a per-user configuration,
#:   and ``mcuhome.compiler.workspace`` names losing it as a bug it
#:   already had once.
#: * ``USER`` / ``LOGNAME`` — the identity tools quote in their own
#:   messages; absent, some of them refuse rather than guess.
#: * ``TMPDIR`` — the program overrides it per invocation with the
#:   contract's own ``tmp`` (§4), so what is stated here is only what a
#:   child that runs before that would use.
#: * ``TZ`` and ``LANG`` (with the ``LC_`` prefix below) — timestamps
#:   and the codec every tool decodes paths with.
#: * ``PYTHONPATH`` — the interpreter that runs the server is the
#:   interpreter that runs the program (:data:`DEFAULT_PROGRAM`), so
#:   dropping it would change which packages the program itself resolves.
STATED_NAMES: tuple[str, ...] = (
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "TZ",
    "LANG",
    "PYTHONPATH",
)

#: The namespaces passed whole, because their members are inputs to the
#: build and are named by the tools rather than by this server:
#: ``LC_*`` (the locale, which is not one variable), ``ZEPHYR_*``
#: (``ZEPHYR_BASE``, ``ZEPHYR_SDK_INSTALL_DIR``,
#: ``ZEPHYR_TOOLCHAIN_VARIANT`` and the vendor variants' companions),
#: ``ZAP_*`` (``ZAP_INSTALL_PATH``, which MCUHome's own tool check
#: accepts *instead of* a ``PATH`` entry) and ``CMAKE_*``
#: (``CMAKE_PREFIX_PATH`` above all, which is how a Zephyr SDK outside
#: its default location is found).
STATED_PREFIXES: tuple[str, ...] = ("LC_", "ZEPHYR_", "ZAP_", "CMAKE_")


def stated_environment(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment the program's children start from (§6.1).

    A **composed** environment and not a copy of this server's own:
    :data:`STATED_NAMES` and :data:`STATED_PREFIXES` are the whole of it,
    and everything else this process happens to hold is left behind. Two
    reasons, and only the first is about secrets.

    *What must not travel.* This server's bearer token arrives through
    ``MCUHOME_BUILDSERVER_TOKEN`` — the channel its own ``--help``
    recommends over a command line — and a copied environment would put
    it in ``/proc/<pid>/environ`` of west, ninja and every compiler
    child, and in the output of any build step that dumps its
    environment. That output is relayed verbatim as the raw log stream
    (§8) into something a client may persist or export. Nothing
    conforming can miss it: §5.1 says "no environment variable carries
    information the program needs".

    *What must.* The build environment **is** this filesystem here, so
    the variables that say where the toolchain on this host lives are
    genuinely part of it and are stated on purpose rather than inherited
    by accident. It is the same decision MCUHome's own ``docker run``
    makes for the other profile — "deliberately not the caller's
    environment" — with the opposite answer for ``PATH``, and for the
    same reason: there the toolchain is the image's, here it is the
    host's.

    The result is a fresh ``dict`` either way, so nothing the server does
    to its own environment later can reach a child it already promised
    something else. Passing *env* explicitly composes from that mapping
    instead of from :data:`os.environ`, which is how a test states a
    server environment without touching the process's.
    """
    source = os.environ if env is None else env
    return {
        name: value
        for name, value in source.items()
        if name in STATED_NAMES or name.startswith(STATED_PREFIXES)
    }


async def run_program(argv: Sequence[str], *, env: Mapping[str, str]) -> Completed:
    """Run *argv* to completion, capturing its merged output.

    This profile's own seam, and one of exactly two. It is a name of its
    own rather than :func:`~mcuhome_buildserver.processes.run_command`
    for the reason that module states: a suite stubs a *profile* out, and
    a shared function would be one seam for two things nobody ever wants
    replaced together.
    """
    return await run_command(argv, env=env)


async def spawn_program(
    argv: Sequence[str], *, on_line: LineSink, env: Mapping[str, str]
) -> Process:
    """Start *argv*, stream its merged output, and stay addressable.

    The handle that comes back is the **build itself** in this profile,
    which is the one place the two profiles differ in what a signal
    reaches: in the ``container`` profile SIGTERM goes to a ``docker
    exec`` client and never to the process inside the container, and here
    it goes to the program **and to everything the program started** —
    the handle addresses the child's process group, which is what makes
    that sentence true of the compile and not only of its entry point
    (:func:`mcuhome_buildserver.processes.spawn_command`). That is what
    contract §1.2 keeps when it gives up isolation — "cancellability and
    process-level isolation remain (the program is a separate process)".
    """
    return await spawn_command(argv, on_line=on_line, env=env)


class Program:
    """The build environment's program, as this server invokes it.

    One object per server process, holding the argv it starts, the
    environment it states and the two seam functions. Both seams are
    resolved **at call time** through the optional constructor arguments,
    for the reason :mod:`mcuhome_buildserver.container` gives about its
    own: a default bound at definition time cannot be replaced by
    monkeypatching the module, and a test that thinks it stubbed the
    program out but did not is a test that starts a real build.
    """

    def __init__(
        self,
        program: Sequence[str] = DEFAULT_PROGRAM,
        *,
        env: Mapping[str, str] | None = None,
        runner: object | None = None,
        spawner: object | None = None,
    ) -> None:
        self.argv = tuple(program)
        #: Stated once, at construction — see :func:`stated_environment`.
        self.env = stated_environment(env)
        self._runner = runner
        self._spawner = spawner

    @property
    def display(self) -> str:
        """How this program is named in a refusal an operator has to act on."""
        return shlex.join(self.argv)

    async def describe(self, *, request: Path) -> Completed:
        """Ask the program what it is (§7.1).

        The same invocation as any other — action plus request path — and
        it is the only discovery channel this profile has: §7.1 says so
        ("the only discovery channel that exists in the ``subprocess``
        profile, where there is no image and therefore no labels"), and
        §2.2.1's static self-description explicitly "has no meaning in
        the ``subprocess`` profile".

        It comes through :func:`run_program` rather than
        :func:`spawn_program` because ``describe`` "needs only the
        preamble, never touches the context, writes nothing but the
        result document" — short, bounded, and its output is wanted as a
        value.
        """
        argv = invocation_command(self.argv, "describe", request)
        logger.debug("program: %s", shlex.join(argv))
        runner = run_program if self._runner is None else self._runner
        return await runner(argv, env=self.env)  # type: ignore[operator]

    async def invoke(self, *, action: str, request: Path, on_line: LineSink) -> Process:
        """Start one working invocation of the program (§5.1)."""
        argv = invocation_command(self.argv, action, request)
        logger.debug("program: %s", shlex.join(argv))
        spawner = spawn_program if self._spawner is None else self._spawner
        return await spawner(argv, on_line=on_line, env=self.env)  # type: ignore[operator]
