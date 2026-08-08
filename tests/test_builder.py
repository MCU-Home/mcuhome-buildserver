# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The builder invocation, and the Block 0 gap it is waiting on.

The last test in this file is a *status report against the real
builder*, not a pass/fail on this repository's code: it asks the
installed ``mcuhome build --help`` whether it can take a resolved device
model, and skips with an explanation when it cannot. The day the
firmware repository lands the flag, this test starts asserting and the
build server starts building — with no change here.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from mcuhome_buildserver import builder


def test_the_invocation_is_always_detached_and_machine_readable() -> None:
    argv = builder.build_argv(
        model_file=Path("/jobs/j1/device-model.json"),
        build_dir=Path("/jobs/j1/build"),
        public_key=Path("/jobs/j1/signing.pub"),
        native=False,
        command=("mcuhome",),
    )

    assert argv[:2] == ["mcuhome", "build"]
    assert builder.MODEL_OPTION in argv
    # ADR 0007 decision 3: this server has no private key, so there is no
    # configuration in which it signs.
    assert "--no-sign" in argv
    assert "--public-key" in argv
    # --json is what splits the manifest (stdout) from the log (stderr).
    assert "--json" in argv
    # ADR 0003 decision 3: the container is the build environment.
    assert "--no-native" in argv
    assert "--native" not in argv


def test_native_is_passed_straight_through() -> None:
    argv = builder.build_argv(
        model_file=Path("m.json"),
        build_dir=Path("b"),
        public_key=Path("k.pem"),
        native=True,
        image="ghcr.io/mcu-home/builder:x",
    )
    assert "--native" in argv
    # An image is meaningless without a container, and passing it anyway
    # would be a command line that contradicts itself.
    assert "--image" not in argv


def test_snippets_are_repeated_options() -> None:
    argv = builder.build_argv(
        model_file=Path("m.json"),
        build_dir=Path("b"),
        public_key=Path("k.pem"),
        native=True,
        snippets=("debug-rtt", "wifi"),
    )
    assert argv.count("--snippet") == 2
    assert "debug-rtt" in argv and "wifi" in argv


def test_nothing_about_the_device_is_on_the_command_line() -> None:
    argv = builder.build_argv(
        model_file=Path("/jobs/j1/device-model.json"),
        build_dir=Path("/jobs/j1/build"),
        public_key=Path("/jobs/j1/signing.pub"),
        native=True,
    )
    # Every process on the machine can read /proc/<pid>/cmdline. The
    # model — which carries the Matter passcode — travels as a 0600 file.
    joined = " ".join(argv)
    assert "passcode" not in joined
    assert "20202021" not in joined


def test_the_environment_carries_the_deployment_s_choices() -> None:
    env = builder.build_environment(jobs=24, image="ghcr.io/x:y", base={"PATH": "/usr/bin"})
    assert env["MCUHOME_JOBS"] == "24"
    assert env["MCUHOME_BUILDER_IMAGE"] == "ghcr.io/x:y"
    # The parent's environment is kept: the builder needs PATH, and a
    # container runtime reads more out of it than we could enumerate.
    assert env["PATH"] == "/usr/bin"


def test_no_choices_means_no_overrides() -> None:
    env = builder.build_environment(jobs=None, image=None, base={"PATH": "/usr/bin"})
    assert "MCUHOME_JOBS" not in env
    assert "MCUHOME_BUILDER_IMAGE" not in env


class TestFeatures:
    def features(self, **kwargs: bool) -> builder.BuilderFeatures:
        base = {
            "present": True,
            "model_input": True,
            "detached_signing": True,
            "json_output": True,
        }
        return builder.BuilderFeatures(**{**base, **kwargs})

    def test_a_complete_builder_is_usable(self) -> None:
        assert self.features().usable is True

    @pytest.mark.parametrize("missing", ["model_input", "detached_signing", "json_output"])
    def test_anything_missing_makes_it_unusable(self, missing: str) -> None:
        features = self.features(**{missing: False})
        assert features.usable is False
        assert features.refusal()

    def test_the_refusal_names_what_is_missing(self) -> None:
        message = self.features(model_input=False).refusal()
        assert builder.MODEL_OPTION in message
        assert builder.VERSION in message

    def test_an_absent_builder_says_the_installation_is_broken(self) -> None:
        features = builder.BuilderFeatures(
            present=False,
            model_input=False,
            detached_signing=False,
            json_output=False,
            problem="mcuhome is not on PATH",
        )
        assert "broken installation" in features.refusal()


async def test_probing_something_that_is_not_there(tmp_path: Path) -> None:
    features = await builder.probe_features((str(tmp_path / "no-such-builder"),))
    assert features.present is False
    assert features.usable is False


async def test_probing_the_fake_builder_finds_everything(fake_builder: Path) -> None:
    import sys

    # The fake builder is a script, so the probe has to be told to run it
    # with an interpreter — which is also how a deployment puts a wrapper
    # in front of the real one.
    features = await builder.probe_features((sys.executable, str(fake_builder)))
    assert features.present is True
    assert features.model_input is True
    assert features.detached_signing is True
    assert features.json_output is True


async def test_the_installed_builder_against_the_contract() -> None:
    """Block 0 gap: can the real ``mcuhome build`` take a device model?

    ADR 0007 decision 1 makes the resolved ``device-model.json`` the wire
    format, and the builder's CLI has no way to consume one — it takes a
    YAML configuration and re-runs stages 1-3 itself. Everything else the
    build server needs (``--json``, ``--no-sign``, ``--public-key``) is
    there since Block 0.

    This test is the tripwire: it skips while the flag is missing and
    passes the moment it lands.
    """
    if shutil.which("mcuhome") is None:
        pytest.skip("the mcuhome builder is not installed in this environment")
    features = await builder.probe_features()

    assert features.present, features.problem
    assert features.json_output, "mcuhome build --json is a Block 0 deliverable"
    assert features.detached_signing, "mcuhome build --no-sign is a Block 0 deliverable"
    if not features.model_input:
        pytest.skip(
            f"mcuhome {builder.VERSION} has no `mcuhome build {builder.MODEL_OPTION} "
            "<device-model.json>`. Until it does, this build server starts, answers "
            "/capabilities with model_input: false, and refuses every job with that "
            "reason. See mcuhome_buildserver/builder.py."
        )
    assert features.usable
