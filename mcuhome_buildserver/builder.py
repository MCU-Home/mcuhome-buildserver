# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""How this server invokes the ``mcuhome`` builder.

**The builder runs as a subprocess here, and that is the opposite of the
dashboard's rule on purpose.** The dashboard imports the builder
in-process (ADR 0011 decision 1) because it wants a ``ConfigError``
object with a line number in it. This server wants none of that: it
wants a compile it can kill.

Three properties come only from a separate process, and ESPHome's
rebuilt job model is where the lesson is written down:

*Cancellation.* A Zephyr+Matter build is ninety seconds of ``ninja``
fanning out over a dozen compilers. There is no cooperative cancellation
point anywhere in it. Killing a process group is the only mechanism that
actually stops one, and a build running inside this process cannot be
killed without killing the server.

*Isolation.* A ``west build`` that runs out of memory, segfaults a
compiler or leaves a CMake cache in a bad state takes down what it runs
in. What it runs in must not be the thing holding the queue, the job
history and every connected client.

*Honesty about the interface.* This server is deployed as the builder
image with a thin server in it (ADR 0003 decision 3). Spawning the CLI
means the thing it ships is the thing it runs, and the version it
reports in ``/capabilities`` is the version that will do the work.

``mcuhome.api`` is still imported — for :data:`VERSION` and
:data:`MODEL_VERSION`, which are facts about the installed builder and
not an invocation of it.

Block 0 gap, and why this module has a probe
--------------------------------------------

ADR 0007 decision 1 fixes the resolved ``device-model.json`` as the wire
format: stages 1-3 run in the dashboard, and only the canonical model
crosses. **The builder's CLI has no way to consume one.** ``mcuhome
build`` takes a ``<device>`` argument that is a folder name or a path to
a *YAML configuration*, and re-runs stages 1-3 itself; there is no
``mcuhome.api`` entry point for "build this model" either.

The three ways out, and why this is the one:

* Reconstruct a YAML configuration from the model here. That is a second
  implementation of the builder's own serialization, on the side of the
  boundary that AGENTS.md says must never hold one.
* Ship the configuration tree instead of the model. That is ADR 0007
  decision 1 reversed, and it hands the build server the secrets store.
* Ask the builder for one flag. :data:`MODEL_OPTION` is that flag.

So the invocation this module builds is the one it *should* be, and
:func:`probe_features` asks the installed builder whether it understands
it. Until it does, ``submit_job`` refuses with a message naming exactly
what is missing (``unsupported``, ADR 0006 decision 4's "a clear refusal
naming both sides' versions — never a silent fallback, never a failure
ten minutes into a compile"), and ``/capabilities`` advertises
``model_input: false`` so a dashboard sees it before it submits.

When the flag lands in the firmware repository, nothing here changes.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from mcuhome.api import MODEL_VERSION, VERSION

__all__ = [
    "BUILDER_COMMAND",
    "MODEL_OPTION",
    "MODEL_VERSION",
    "MODEL_VERSION_MAX",
    "MODEL_VERSION_MIN",
    "VERSION",
    "BuilderFeatures",
    "build_argv",
    "build_environment",
    "probe_features",
]

logger = logging.getLogger(__name__)

#: The ``model_version`` range this server accepts, advertised in
#: ``/capabilities`` (ADR 0006 decision 4, ADR 0007 decision 4). Both
#: ends are the installed builder's own number today; they exist as two
#: constants so that accepting an older model later is a change here and
#: not a change to the protocol.
MODEL_VERSION_MIN = MODEL_VERSION
MODEL_VERSION_MAX = MODEL_VERSION

#: The command that is the builder. A list so that a deployment can put
#: a wrapper in front of it (``--builder-command``) without this module
#: learning about shells.
BUILDER_COMMAND = ("mcuhome",)

#: The option that hands ``mcuhome build`` a resolved device model
#: instead of a configuration to resolve. See the module docstring.
MODEL_OPTION = "--model"

#: The builder's environment variable for the parallel job count. Set
#: per deployment rather than guessed per job: a dedicated build machine
#: knows better than the builder's RAM heuristic (REMOTE-BUILD.md).
JOBS_VAR = "MCUHOME_JOBS"

#: The builder's environment variable for the container image tag.
IMAGE_VAR = "MCUHOME_BUILDER_IMAGE"

#: How long `mcuhome build --help` may take before the probe gives up.
#: It is argparse printing a string; a second is already generous, and
#: hanging here would hang startup.
PROBE_TIMEOUT = 10.0


@dataclass(frozen=True)
class BuilderFeatures:
    """What the installed builder can actually do, asked rather than assumed."""

    #: The builder was found and answered.
    present: bool
    #: ``mcuhome build`` accepts :data:`MODEL_OPTION`.
    model_input: bool
    #: ``mcuhome build`` accepts ``--no-sign``/``--public-key``, i.e.
    #: detached signing (ADR 0007 decision 3) is available.
    detached_signing: bool
    #: ``mcuhome build`` accepts ``--json``.
    json_output: bool
    #: Why the builder is unusable, in one sentence, or ``None``.
    problem: str | None = None

    @property
    def usable(self) -> bool:
        """Whether a job submitted now could actually be built."""
        return self.present and self.model_input and self.detached_signing and self.json_output

    def refusal(self) -> str:
        """Plain language for the client that just tried to submit."""
        if not self.present:
            return (
                f"This build server cannot run the MCUHome builder: {self.problem}. "
                "It is deployed as the builder image with a server in it, so this is "
                "a broken installation rather than a configuration mistake."
            )
        missing = [
            name
            for name, ok in (
                (f"mcuhome build {MODEL_OPTION} <device-model.json>", self.model_input),
                ("mcuhome build --no-sign --public-key", self.detached_signing),
                ("mcuhome build --json", self.json_output),
            )
            if not ok
        ]
        return (
            f"The builder installed here (mcuhome {VERSION}) is missing "
            f"{', '.join(missing)}, which this build server needs for every job. "
            "The dashboard sends a resolved device model and keeps the signing key "
            "(ADR 0007), so a builder that cannot take a model or cannot build "
            "unsigned has nothing it can do with the request. Install a builder "
            "release that has it."
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "present": self.present,
            "model_input": self.model_input,
            "detached_signing": self.detached_signing,
            "json_output": self.json_output,
            "usable": self.usable,
            "problem": self.problem,
        }


def _flags(text: str) -> set[str]:
    """Every long option argparse printed in a help text."""
    return set(re.findall(r"--[A-Za-z0-9][A-Za-z0-9-]*", text))


async def probe_features(command: tuple[str, ...] = BUILDER_COMMAND) -> BuilderFeatures:
    """Ask ``mcuhome build --help`` what it understands.

    Reading a help text is a blunt instrument, and it is the right one
    here: it is the CLI's own description of its surface, it costs one
    process at startup, and the alternative — submitting a job and
    watching argparse reject it — turns a configuration problem into a
    failed build with ``unrecognized arguments`` in the log.
    """
    if shutil.which(command[0]) is None:
        return BuilderFeatures(
            present=False,
            model_input=False,
            detached_signing=False,
            json_output=False,
            problem=f"{command[0]} is not on PATH",
        )
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            "build",
            "--help",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=PROBE_TIMEOUT)
    except (OSError, TimeoutError) as error:
        return BuilderFeatures(
            present=False,
            model_input=False,
            detached_signing=False,
            json_output=False,
            problem=f"{' '.join(command)} build --help failed ({error})",
        )

    text = stdout.decode("utf-8", errors="replace")
    if process.returncode != 0:
        return BuilderFeatures(
            present=False,
            model_input=False,
            detached_signing=False,
            json_output=False,
            problem=f"{' '.join(command)} build --help exited {process.returncode}",
        )
    flags = _flags(text)
    features = BuilderFeatures(
        present=True,
        model_input=MODEL_OPTION in flags,
        detached_signing={"--no-sign", "--public-key"} <= flags,
        json_output="--json" in flags,
    )
    if not features.usable:
        logger.warning("%s", features.refusal())
    return features


def build_argv(
    *,
    model_file: Path,
    build_dir: Path,
    public_key: Path,
    native: bool,
    image: str | None = None,
    snippets: tuple[str, ...] = (),
    command: tuple[str, ...] = BUILDER_COMMAND,
) -> list[str]:
    """The exact command one job runs.

    ``--no-sign --public-key`` is not an option this server offers: it is
    what it *is*. The private key never leaves the dashboard (ADR 0007
    decision 3), so there is no configuration in which this process could
    sign, and a build that tried would fail on a missing key ten minutes
    in rather than refuse in a millisecond.

    ``--json`` puts the build manifest on stdout and the compiler's
    output on stderr, which is exactly the split this server needs: one
    document to parse, one stream to tee into the job's log sidecar.
    """
    argv = [
        *command,
        "build",
        MODEL_OPTION,
        str(model_file),
        "--build-dir",
        str(build_dir),
        "--no-sign",
        "--public-key",
        str(public_key),
        "--json",
    ]
    for snippet in snippets:
        argv += ["--snippet", snippet]
    # ADR 0003 decision 3 and the task's requirement: the container path
    # is the default and the builder owns the docker invocation, because
    # it is the half that knows which mounts a build needs. --native is
    # the developer escape hatch, passed straight through.
    argv.append("--native" if native else "--no-native")
    if image and not native:
        argv += ["--image", image]
    return argv


def build_environment(
    *,
    jobs: int | None,
    image: str | None,
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """The environment one job runs in.

    Deliberately the parent's environment plus two variables rather than
    a scrubbed one: the builder needs ``PATH``, ``HOME`` and whatever the
    container runtime reads out of the environment, and a build server
    that guessed at that list would break on the first machine whose
    docker needs a socket path.

    What is *not* in here is anything about the device. Credentials
    travel in the model file, which is mode 0600 in the job directory —
    never on a command line, where every process on the machine can read
    them out of ``/proc``.
    """
    env = dict(os.environ if base is None else base)
    if jobs is not None:
        env[JOBS_VAR] = str(jobs)
    if image:
        env[IMAGE_VAR] = image
    return env
