# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The SDK package: found by its pin, verified by its hash, unpacked per session.

Build-container contract §9.1 makes a verified SDK a **backend duty**:
"the content of ``trees.sdk`` matches the manifest's
``mcuhome.package.sha256``. The backend acquires the package by (name,
version, sha256) from operator-configured sources only; the manifest's
``package.url`` is a hint, never an instruction."

Three consequences, and this module is all three.

**The URL in the context is never fetched.** ADR 0019 §8 is explicit:
the backend resolves ``(name, version, sha256)`` against its *configured
source list*. A context is client-supplied, so a backend that followed
its URL would let a client point this server's fetcher wherever it
liked — the classic server-side request forgery, with a build server's
network position behind it. The URL travels into ``manifest.yaml``
because it is part of the pin the client resolved, and it is read by
nobody here.

**The source list has a fixed search order** (ADR 0019's amendment of
2026-08-09): a local directory first, then ``packages.mcuhome.org``,
then any other external source. Contract v1 of this server implements
the first tier only (E48) — one or more local directories, searched in
the order the operator listed them — so "not here" is a final answer
and ``sdk.unavailable`` is not retryable. The remaining tiers are a
fetcher this server does not have, and a code that promised a retry
against a source list with no network in it would be a lie a client
would act on.

**The hash decides, not the name.** The file is named
``mcuhome-sdk-<version>.tar.zst`` because a directory needs a lookup key,
but the version in the name is only how the candidate is found: what
makes it the package the context pinned is that its bytes hash to
``mcuhome.package.sha256``. A file with the right name and the wrong
bytes is refused exactly as loudly as one that is not there, and the
refusal says which of the two it was.

The unpack is the safe extraction of §9.1, reusing the ingress
extractor (:func:`mcuhome_buildserver.ingress.unpack_tree`) rather than
restating it — one implementation of "regular files and directories
only" in this repository, whatever delivered the bytes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import zstandard
from mcuhome.model.hashes import sha256_file

from mcuhome_buildserver.errors import SessionError
from mcuhome_buildserver.ingress import IngressCaps, unpack_tree

#: The caps an SDK package is unpacked under. Deliberately NOT the
#: client-facing session caps from the config: those size a *context*
#: (model, keys, patches — kilobytes to a few megabytes), while an SDK
#: package is the operator's own source tree, and holding the operator's
#: material to the client's budget shape would make the two knobs fight
#: (E44's numbers were argued for contexts, not for source trees). The
#: numbers are generous bounds against a corrupt or malicious archive,
#: not a policy anyone tunes — an operator who does not trust an SDK
#: source should not list it.
SDK_CAPS = IngressCaps(
    compressed_bytes=256 * 1024 * 1024,
    decompressed_bytes=1024 * 1024 * 1024,
    entries=65536,
    file_bytes=256 * 1024 * 1024,
    path_depth=24,
)

#: The decompressed budget handed to the quota check, same argument.
SDK_MAX_BYTES = 1024 * 1024 * 1024

__all__ = ["SdkPackage", "acquire_sdk", "package_filename"]

logger = logging.getLogger(__name__)

#: How large a chunk the decompressor is asked to hand over at a time.
#: Bounded for the same reason the ingress spool bounds it: a zstd frame
#: can expand without limit, and a cap that only fires after the
#: expansion is not a cap.
_BLOCK = 1 << 20


def package_filename(version: str) -> str:
    """What an SDK package is called in a local source directory.

    ``tar.zst``, like the context archive on the wire, for the same
    reason: one archive format in the family rather than one per
    transport (E41).
    """
    return f"mcuhome-sdk-{version}.tar.zst"


@dataclass(frozen=True)
class SdkPackage:
    """One SDK package, found and verified. The tree is already unpacked."""

    version: str
    sha256: str
    #: Where the archive was found, for the log and for a bug report.
    source: Path
    #: The unpacked tree, which is what ``trees.sdk`` names.
    tree: Path


def acquire_sdk(
    *,
    version: str,
    sha256: str,
    sources: tuple[Path, ...],
    into: Path,
    caps: IngressCaps,
    max_bytes: int,
) -> SdkPackage:
    """Find the pinned package, check its bytes, unpack it into *into*.

    *sha256* is the pin out of the **locked** context — the value the
    freeze wrote into ``manifest.yaml`` and the value the context ID was
    computed over — so verifying against it is one half of §9.1's
    cross-check: the SDK this server hands the program is the SDK the
    context is identified by, or the invocation does not happen.

    The tree is unpacked **per session** and lives inside the session's
    own directory, which is what makes it safe to hand out writable when
    the ``sdk`` layer carries patches (§6.2): a per-session copy that
    dies with the session is a writable view by construction, needing
    neither an overlay nor a shared tree anybody could poison.
    """
    wanted = package_filename(version)
    searched = [str(directory) for directory in sources]
    candidate: Path | None = None
    for directory in sources:
        found = directory / wanted
        if found.is_file():
            candidate = found
            break
    if candidate is None:
        # The searched directories are operator host paths, and they stay
        # off the wire: they leak this host's filesystem layout to a
        # client that cannot act on them anyway (the failure is a
        # deployment gap only the operator can close). The operator, who
        # can, reads them in the log.
        logger.warning(
            "SDK %s unavailable: no configured source holds %s (searched: %s)",
            version,
            wanted,
            ", ".join(searched) or "no sources configured",
        )
        raise _unavailable(version, sha256, f"no configured source holds {wanted}")

    measured = sha256_file(candidate)
    if measured != sha256:
        # Named right, wrong bytes. Refused rather than repaired, and
        # said plainly: this is either a corrupted mirror or a package
        # somebody replaced, and both are answers an operator has to
        # see rather than a fallback this server can make. The located
        # file's path is a host path and stays off the wire for the same
        # reason; the operator reads it in the log, and the client keeps
        # the pinned hash and the measured one, which are what it can act
        # on.
        logger.warning(
            "SDK %s at %s hashes to %s, not the pinned %s", version, candidate, measured, sha256
        )
        raise _unavailable(
            version,
            sha256,
            "a file named for this version hashes to a different value",
            measured=measured,
        )

    into.mkdir(parents=True, exist_ok=True)
    spool = into.parent / f"{into.name}.tar"
    try:
        _decompress(candidate, spool, limit=max_bytes)
        unpack_tree(spool, into=into, caps=caps, quota_bytes=max_bytes)
    finally:
        spool.unlink(missing_ok=True)
    logger.info("unpacked SDK %s from %s", version, candidate)
    return SdkPackage(version=version, sha256=sha256, source=candidate, tree=into)


def _decompress(archive: Path, spool: Path, *, limit: int) -> None:
    """zstd to a plain tar on disk, refusing an expansion mid-stream.

    Streaming rather than one-shot for the reason
    :mod:`mcuhome_buildserver.ingress` gives about the wire: a few
    kilobytes of zstd can expand to gigabytes, and a decompressor that
    returned its output as one ``bytes`` would have allocated the bomb
    before any check could run. The package is the operator's own file
    rather than a client's, which makes a bomb unlikely and a corrupt
    archive perfectly likely — and both come out here as a bounded read
    instead of an out-of-memory kill.
    """
    written = 0
    with archive.open("rb") as raw, spool.open("wb") as handle:
        reader = zstandard.ZstdDecompressor().stream_reader(raw)
        while block := reader.read(_BLOCK):
            written += len(block)
            if written > limit:
                raise _too_large(archive, limit)
            handle.write(block)


def _too_large(archive: Path, limit: int) -> SessionError:
    return SessionError(
        "policy.ingress-limit-exceeded",
        f"The SDK package at {archive} unpacks to more than this server's limit of "
        f"{limit} bytes. The limit bounds what one session may materialize, whoever "
        "supplied the bytes.",
        cap="sdk package size",
        limit=limit,
    )


def _unavailable(
    version: str,
    sha256: str,
    problem: str,
    **details: str,
) -> SessionError:
    """``sdk.unavailable`` — the pin names a package this server has not.

    **Not retryable**, and the source list is why: contract v1 of this
    server searches configured local directories and fetches nothing, so
    the same command a second later searches the same directories and
    finds the same nothing. What changes the answer is an operator
    putting the package where this server looks, which is not something
    a client retry can bring about.

    The envelope carries the two things the client can act on — the
    version and the hash the context pinned — and no host path. The
    directories that were searched, and any located file, are operator
    filesystem layout: the failure is almost always a deployment gap the
    client cannot close, so those go to the log for the operator who can,
    not onto the wire to the client who cannot.
    """
    return SessionError(
        "sdk.unavailable",
        f"This server cannot supply the SDK package this context pins ({problem}). The "
        "package is fetched from operator-configured sources only and never from the "
        "url in the context, which is a hint; ask the operator to add "
        f"{package_filename(version)} to one of this server's configured SDK sources.",
        version=version,
        sha256=sha256,
        **details,
    )
