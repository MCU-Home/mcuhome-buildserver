# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""One real remote build, against this server, with everything real.

The unit suite fakes docker at the seam the contract draws, because a
build server is an orchestrator and there is no build to stand in for.
That is the right shape for testing a protocol and the wrong shape for
finding what actually broke here: three of the four defects that reached
a real remote build were about *time* — a lease that ran out under its
own build — and one was about an address being parsed as a URL. A fake
has no clock worth outrunning and never dials anything.

So this harness fakes nothing. It starts the server as a process, hands
it a real SDK package, and drives ``mcuhome device build --build-mode
remote`` at it over a real socket until a signed image exists. What it
then checks is listed in :func:`main` and each check prints the line it
proves, because a green job that verified nothing is the failure mode
this file exists to prevent.

Run it by hand exactly as CI does::

    python e2e/run.py --sdk-dir <dir with the SDK package and index.json>

The device it builds is ``e2e/project/devices/e2e-node`` — deliberately
the cheapest configuration that still walks the whole chain; its own file
says why.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "project"
DEVICE = "e2e-node"

#: How long a session may sit with nothing happening. Fifteen seconds
#: against a build of minutes, which is the whole point: with the
#: ten-minute default, "the lease survived its own build" is a claim this
#: job would make without ever testing it. The build below must outlast
#: this number, and :func:`check_the_lease_was_actually_tested` refuses a
#: run where it did not.
IDLE_TIMEOUT_SECONDS = 15

#: What the server may never say. `reaped` is the sweep taking a session
#: away; `session.expired` is what a client is told when it addresses one
#: that was taken. Either in this log means the lease fired during an
#: ordinary build.
FORBIDDEN_LOG_MARKERS = ("reaped", "session.expired")

#: The artifacts a standalone device produces. No `.ota`: a Matter OTA
#: image is Matter's, and this device has none.
EXPECTED_ARTIFACTS = (
    "firmware.bin",
    "firmware.hex",
    "bootloader.hex",
    "firmware.signed.bin",
    "firmware.signed.hex",
    "build-report.json",
)


class Failed(Exception):
    """A check that did not hold. Its message is the report."""


def say(message: str) -> None:
    print(f"  {message}", flush=True)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def wait_for_health(port: int, *, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/health"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as answer:  # noqa: S310 - literal http
                if answer.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            time.sleep(0.2)
    raise Failed(f"the server did not answer {url} within {timeout:g}s")


@contextlib.contextmanager
def server(*, sdk_dir: Path, state: Path, log: Path, token: str):
    """The real server, as a process, with a short idle timeout."""
    port = free_port()
    argv = [
        sys.executable,
        "-m",
        "mcuhome.buildserver",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--token",
        token,
        "--no-pair-file",
        "--sdk-source",
        str(sdk_dir),
        "--context-root",
        str(state),
        "--session-idle-timeout-seconds",
        str(IDLE_TIMEOUT_SECONDS),
        "--log-level",
        "INFO",
    ]
    with log.open("wb") as sink:
        process = subprocess.Popen(argv, stdout=sink, stderr=subprocess.STDOUT)  # noqa: S603
        try:
            wait_for_health(port)
            yield port
        finally:
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=20)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)


def build(project: Path, *, port: int, token: str, sdk_dir: Path) -> tuple[dict, float]:
    """``mcuhome device build`` through the remote method. Returns the document."""
    argv = [
        "mcuhome",
        "device",
        "build",
        DEVICE,
        "--build-mode",
        "remote",
        "--build-server",
        f"127.0.0.1:{port}",
        "--build-token",
        token,
        "--sdk-sources",
        str(sdk_dir),
        "-o",
        "json",
    ]
    started = time.monotonic()
    done = subprocess.run(  # noqa: S603
        argv, cwd=project, capture_output=True, text=True, check=False
    )
    seconds = time.monotonic() - started
    if done.stderr.strip():
        print(done.stderr, file=sys.stderr, flush=True)
    if not done.stdout.strip():
        raise Failed(f"the build printed no document at all (exit {done.returncode})")
    document = json.loads(done.stdout)
    if done.returncode != 0 or not document.get("ok"):
        raise Failed(f"the build failed (exit {done.returncode}): {json.dumps(document, indent=2)}")
    return document, seconds


# --------------------------------------------------------------------------
# The checks. One function each, each printing what it proved.
# --------------------------------------------------------------------------


def check_the_artifacts_are_all_there(build_dir: Path) -> None:
    missing = [name for name in EXPECTED_ARTIFACTS if not (build_dir / name).is_file()]
    if missing:
        raise Failed(f"artifacts missing from {build_dir}: {', '.join(missing)}")
    empty = [name for name in EXPECTED_ARTIFACTS if (build_dir / name).stat().st_size == 0]
    if empty:
        raise Failed(f"artifacts present but empty: {', '.join(empty)}")
    say(f"the artifact set is complete and non-empty ({len(EXPECTED_ARTIFACTS)} files)")


def check_the_lease_was_actually_tested(seconds: float) -> None:
    """A build shorter than the idle timeout proves nothing about it.

    This is the check that keeps the interesting one honest: shrink the
    fixture far enough and "no session was reaped" becomes true because
    nothing ever had the chance to be.
    """
    if seconds <= IDLE_TIMEOUT_SECONDS:
        raise Failed(
            f"the build took {seconds:.0f}s and the idle timeout is {IDLE_TIMEOUT_SECONDS}s — "
            "the lease was never under load, so a green run says nothing about it"
        )
    say(f"the build ran {seconds:.0f}s against a {IDLE_TIMEOUT_SECONDS}s idle timeout")


def check_no_session_was_taken_away(log: Path) -> None:
    text = log.read_text(encoding="utf-8", errors="replace")
    for marker in FORBIDDEN_LOG_MARKERS:
        if marker in text:
            lines = [line for line in text.splitlines() if marker in line]
            raise Failed(f"the server log says {marker!r}: {lines[0]}")
    if "container" not in text:
        raise Failed("the server log never mentions a container — did this build run remotely?")
    say("no session was reaped, and the server did start a container")


def check_the_private_key_never_travelled(project: Path, build_dir: Path, state: Path) -> None:
    """The invariant, checked against the bytes rather than the design.

    ``.mcuhome-remote/context`` is what the client packs and uploads, so
    it is the honest place to look: if the private half is not in there,
    it did not go over the wire.
    """
    key = project / "secrets" / "firmware" / "mcuboot.pem"
    if not key.is_file():
        raise Failed(f"no signing key at {key} — this build signed with something else")
    secret = key.read_bytes()
    body = b"".join(line for line in secret.splitlines() if line and not line.startswith(b"-----"))
    if len(body) < 32:
        raise Failed(f"the signing key at {key} is too short to search for")
    needle = body[:32]

    searched = 0
    for root in (build_dir / ".mcuhome-remote" / "context", state):
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            searched += 1
            if needle in path.read_bytes():
                raise Failed(f"the private signing key reached {path}")
    say(f"the private key is in none of the {searched} files the server or the wire ever saw")


def check_the_context_holds_the_public_half(build_dir: Path) -> None:
    """The counterpart, so the check above cannot pass by emptiness."""
    public = build_dir / ".mcuhome-remote" / "context" / "keys" / "signing.pub"
    if not public.is_file():
        raise Failed(f"the uploaded context carries no public key at {public}")
    text = public.read_text(encoding="utf-8")
    if "PUBLIC KEY" not in text:
        raise Failed(f"{public} is not a public key: {text.splitlines()[:1]}")
    say("the uploaded context carries the public half, and only that")


def check_the_signature_verifies(project: Path, build_dir: Path) -> None:
    public = build_dir / "signing.pub"
    written = subprocess.run(  # noqa: S603
        ["mcuhome", "public-key"], cwd=project, capture_output=True, text=True, check=True
    )
    public.write_text(written.stdout, encoding="utf-8")
    report = json.loads((build_dir / "build-report.json").read_text(encoding="utf-8"))
    slot = report["signing"]["arguments"]["slot-size"]
    # The workbench's own lookup, not a second rule: the same imgtool
    # that signed the image is the one asked whether the signature holds.
    from mcuhome.workbench.imgtool import require_imgtool

    done = subprocess.run(  # noqa: S603
        [
            *require_imgtool(env=dict(os.environ)),
            "verify",
            "--key",
            str(public),
            str(build_dir / "firmware.signed.bin"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0 or "Image was correctly validated" not in done.stdout:
        raise Failed(f"imgtool could not verify the signed image:\n{done.stdout}{done.stderr}")
    say(f"the signed image verifies against the public key (slot {slot} bytes)")


def check_the_server_kept_nothing(state: Path) -> None:
    """ADR 0019: a context lives for the session and is deleted with it."""
    leftovers = [path for path in state.rglob("*") if path.is_file()]
    if leftovers:
        raise Failed(f"the server kept {len(leftovers)} file(s) after the session: {leftovers[:3]}")
    say("the server kept nothing after the session closed")


def check_the_document_says_what_it_did(document: dict) -> None:
    if not document.get("signed"):
        raise Failed("the document does not claim a signed build")
    roles = {entry.get("role") for entry in document.get("artifacts", ())}
    for role in ("firmware", "bootloader", "report"):
        if role not in roles:
            raise Failed(f"the document names no {role} artifact: {sorted(roles)}")
    if not document.get("signed_artifacts"):
        raise Failed("the document names no signed artifact")
    say(f"the machine-readable document names every role ({', '.join(sorted(roles))})")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--sdk-dir",
        required=True,
        type=Path,
        help="directory holding the MCUHome SDK package and its index.json",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="do not delete the working tree afterwards (for debugging a failure)",
    )
    args = parser.parse_args(argv)

    sdk_dir = args.sdk_dir.resolve()
    if not (sdk_dir / "index.json").is_file():
        parser.error(f"{sdk_dir} holds no index.json — build the SDK package first")

    workspace = Path(tempfile.mkdtemp(prefix="mcuhome-e2e-"))
    token = "e2e-" + os.urandom(16).hex()
    project = workspace / "project"
    state = workspace / "server-state"
    log = workspace / "server.log"
    shutil.copytree(FIXTURE, project)
    state.mkdir()

    print(f"workspace {workspace}", flush=True)
    try:
        with server(sdk_dir=sdk_dir, state=state, log=log, token=token) as port:
            print(f"server on 127.0.0.1:{port}, idle timeout {IDLE_TIMEOUT_SECONDS}s", flush=True)
            document, seconds = build(project, port=port, token=token, sdk_dir=sdk_dir)
        build_dir = Path(document["build_dir"])

        print("checks:", flush=True)
        check_the_artifacts_are_all_there(build_dir)
        check_the_document_says_what_it_did(document)
        check_the_lease_was_actually_tested(seconds)
        check_no_session_was_taken_away(log)
        check_the_private_key_never_travelled(project, build_dir, state)
        check_the_context_holds_the_public_half(build_dir)
        check_the_signature_verifies(project, build_dir)
        check_the_server_kept_nothing(state)
    except Failed as failure:
        print(f"\nFAILED: {failure}\n", file=sys.stderr, flush=True)
        if log.is_file():
            print("--- server log (last 60 lines) ---", file=sys.stderr)
            tail = log.read_text(encoding="utf-8", errors="replace").splitlines()[-60:]
            print("\n".join(tail), file=sys.stderr, flush=True)
        return 1
    finally:
        if not args.keep:
            shutil.rmtree(workspace, ignore_errors=True)

    print("\nOK — one real remote build, every check held.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
