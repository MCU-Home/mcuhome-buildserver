# The end-to-end job

One real remote build, with nothing faked: this server as a process, a
real build container, `mcuhome device build --build-mode remote` driven
at it over a real socket, and a signed image at the end.

## Why it exists

`tests/` fakes docker, and that is the right shape: a build server is an
orchestrator, and there is no build to stand in for. But a fake has no
clock worth outrunning and never dials anything, and that is precisely
where this server broke. Four defects reached a real remote build before
anything caught them:

| What broke | Why the unit suite could not see it |
|---|---|
| a session reaped mid-compile | needs a build that outlasts the idle timeout |
| a session already idle when its build ended | same, plus a real `get-artifact` afterwards |
| a lease shorter than the build deadline | two numbers that only meet in a long build |
| a server address parsed as a URL | the fake was never dialled |

`run.py` is the harness. Every check prints the sentence it proves,
because a green job that verified nothing is the failure mode this
directory exists to prevent.

## What it checks

1. The artifact set is complete and non-empty — firmware, bootloader,
   both signed forms, the report.
2. The machine-readable document names every role.
3. **The build outlasted the idle timeout.** The server runs with a
   15-second one, and a build shorter than that would make check 4 true
   by never putting the lease under load; this refuses such a run.
4. The server log says neither `reaped` nor `session.expired`, and does
   mention a container.
5. The private signing key is in none of the files the wire or the
   server ever saw.
6. …and the uploaded context does carry the public half, so check 5
   cannot pass by emptiness.
7. The signed image verifies against the public key, through the same
   imgtool lookup the workbench signs with.
8. The server kept nothing after the session closed (ADR 0019).

## The device

`project/` is an ordinary MCUHome project, committed as one — marker
file included, which is what that file is for. Its device has no
transport and no Matter, so no OpenThread and no CHIP get compiled:
about four minutes instead of about fifteen, and a remote build is
always a cold one because this server never mounts a writable compiler
cache. The device's own file says all this and asks not to be grown.

What this job does **not** test is firmware. That is the `matter` job in
[mcu-home/mcuhome-sdk](https://github.com/mcu-home/mcuhome-sdk), which
builds the real reference device on the real patch set.

## Running it by hand

Needs docker, and the four distributions installed (this server, the
workbench with its `remote` extra, the model and the compiler, and the
`mcuhome` command):

```sh
python .deps/mcuhome-sdk/scripts/build_sdk_archive.py --output-dir dist/sdk
python tests/e2e/run.py --sdk-dir dist/sdk
```

`--keep` leaves the working tree — server log, project, build directory —
where a failure can be read.
