# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Egress: what this server does with ``out``, and what it hands back.

Build-container contract §9.3 opens with the reason the whole module
exists: "``out`` is written by the least trusted component in the system
and its contents travel over the network onto other people's machines."
Five duties follow it, and :func:`harden` is all five:

* enumerate ``out`` **without following symlinks** and reject symlinks,
  hardlinks (``nlink > 1``), devices, FIFOs and sockets;
* normalize every declared artifact path and enforce strict containment
  under the named ``root``, skipping any artifact whose ``root`` this
  version does not know;
* **re-hash every artifact from the bytes on disk** — declared values
  are advisory, and the comparison is against the one legal spelling of
  §3.3.1, never case-insensitive;
* serve exactly the intersection of declared and verified; files that
  were not declared are not served, but they are not deleted either —
  they are diagnostic material;
* apply size caps during enumeration, from the bytes on disk — an
  artifact entry declares no size.

The program is forbidden to create links, devices, sockets or FIFOs in
``out`` at all, and ``out`` path segments are ``[A-Za-z0-9._-]+`` (§9.2).
That is what makes this an audit rather than a repair: everything below
refuses, and nothing below rewrites a path into one that would have been
allowed.

**Download is an archive, in the format the wire already speaks.** The
mirror of E41's upload, settled by the product owner as E45: one
``tar.zst`` in both directions. With a path it holds exactly that
declared artifact, without one it holds all of them under their declared
paths; the announced ``sha256`` is the **archive's**, computed at egress
while the bytes are read off disk, and per-file integrity stays the
client's own check against the result document it already holds.

**The five duties are enforced twice, and the second time is the one
that matters.** :func:`harden` runs when an invocation ends;
:func:`build_archive` runs whenever a client asks, which is arbitrarily
later and — because the session's container is alive until
``close-session`` and a later invocation writes into the same tree — on
a directory that may have changed in between. A check that only ran at
the earlier moment would be a check on bytes nobody serves: an artifact
replaced by a symlink after ``harden`` passed would be *followed* at
download time and its target streamed to the client under a declared
name. So every member is re-opened with ``O_NOFOLLOW``, re-checked for
being a regular file with one link, and **re-hashed while it is packed**;
a member that is no longer what was verified is
``artifact.integrity-mismatch`` and the whole delivery is refused rather
than built around it.
"""

from __future__ import annotations

import hashlib
import io
import os
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path

import zstandard
from mcuhome.model.hashes import sha256_file

from mcuhome_buildserver.abi import Artifact
from mcuhome_buildserver.errors import SessionError

__all__ = [
    "Delivery",
    "build_archive",
    "harden",
    "undeclared",
]

#: How much of a file is read at a time when it goes into a download
#: archive. The archive is built on disk rather than in memory for the
#: same reason the ingress spool is: a build's ``out`` is not bounded by
#: anything this process can hold.
_BLOCK = 1 << 20


@dataclass(frozen=True)
class Delivery:
    """One built download archive, announced before its bytes.

    ``sha256`` is the archive's own, "computed at egress while reading
    from disk" (E45) — never a value copied out of the result document.
    The per-file hashes the client checks are the ones it already holds
    from the result payload, which is what makes this hash a transport
    check rather than a second integrity claim.
    """

    path: Path
    size: int
    sha256: str
    members: tuple[Artifact, ...]


def harden(
    out: Path,
    declared: tuple[Artifact, ...],
    *,
    max_bytes: int,
) -> tuple[tuple[Artifact, ...], tuple[str, ...]]:
    """Verify the declared artifacts against the bytes in ``out``.

    Returns ``(verified, problems)``. *verified* is the intersection of
    declared and verified, in declaration order, with each artifact's
    ``sha256`` **replaced by the value re-read from disk** — which is
    the same value it declared, or it would not be in the list. The
    replacement is deliberate: everything downstream serves and
    attributes from this tuple, and carrying a declared hash forward
    would leave one path through this server on which a client's value
    was believed.

    *problems* is why an entry did not survive, one sentence each. It
    is not empty exactly when the intersection is smaller than the
    declaration, and §5.3's sixth condition is "problems is empty" —
    "every declared artifact exists as a regular file under its declared
    ``root`` and re-hashes to its declared value". A build that declared
    four artifacts and produced three is not a build that delivers
    three.
    """
    verified: list[Artifact] = []
    problems: list[str] = []
    for artifact in declared:
        resolved = _contained(out, artifact.path)
        if resolved is None:
            problems.append(f'"{artifact.path}" is not contained in the out directory')
            continue
        info = _lstat(resolved)
        if info is None:
            problems.append(f'"{artifact.path}" was declared and is not there')
            continue
        if not stat.S_ISREG(info.st_mode):
            problems.append(f'"{artifact.path}" is not a regular file')
            continue
        if info.st_nlink > 1:
            # A hardlink is a second name for bytes that may live
            # outside `out` entirely, and `lstat` cannot tell which name
            # came first. §9.2 forbids the program to make one at all.
            problems.append(f'"{artifact.path}" is a hardlink (nlink {info.st_nlink})')
            continue
        if info.st_size > max_bytes:
            problems.append(
                f'"{artifact.path}" is {info.st_size} bytes and this server serves at '
                f"most {max_bytes}"
            )
            continue
        measured = sha256_file(resolved)
        if measured != artifact.sha256:
            # The comparison is against the one legal spelling and never
            # case-insensitive: a declared hash in any other rendering is
            # a mismatch, not a value to fold. `abi.declared_artifacts`
            # turns a misrendered one into a problem of its own before it
            # reaches here, so what is left at this line is a genuine
            # disagreement about bytes.
            problems.append(
                f'"{artifact.path}" hashes to {measured} and was declared as {artifact.sha256}'
            )
            continue
        verified.append(
            Artifact(
                root=artifact.root,
                path=artifact.path,
                role=artifact.role,
                sha256=measured,
            )
        )
    return tuple(verified), tuple(problems)


def undeclared(out: Path, verified: tuple[Artifact, ...]) -> tuple[str, ...]:
    """Everything in ``out`` that is not served, for the record.

    "Files that were not declared are not served, but they are not
    deleted either — they are diagnostic material." Naming them costs a
    walk and is the difference between a build that produced nothing and
    a build that produced something it forgot to declare, which are the
    two readings of an empty delivery and are not the same news.

    The walk does not follow symlinks and does not descend into one, so
    a symlinked directory in ``out`` is reported as one entry rather
    than as everything it points at.
    """
    served = {artifact.path for artifact in verified}
    found: list[str] = []
    for root, directories, files in os.walk(out, followlinks=False):
        base = Path(root)
        for name in list(directories):
            if (base / name).is_symlink():
                directories.remove(name)
                found.append(str((base / name).relative_to(out)))
        for name in files:
            relative = str((base / name).relative_to(out))
            if relative not in served:
                found.append(relative)
    return tuple(sorted(found))


def _contained(out: Path, relative: str) -> Path | None:
    """The absolute path of a declared artifact, or ``None``.

    Strict containment, checked segment by segment with ``lstat`` rather
    than with :meth:`Path.resolve`. ``resolve`` answers where a path
    *leads*, which is the wrong question: a ``firmware.hex`` that is a
    symlink to ``/etc/shadow`` resolves to a perfectly contained-looking
    absolute path only after the link has already been followed. What
    matters is that no segment of the path is a link at all, and that is
    what this walk asks.
    """
    segments = relative.split("/")
    if not segments or any(part in ("", ".", "..") for part in segments):
        return None
    current = out
    for part in segments:
        current = current / part
        info = _lstat(current)
        if info is None:
            return current if part == segments[-1] else None
        if stat.S_ISLNK(info.st_mode):
            return None
        if part != segments[-1] and not stat.S_ISDIR(info.st_mode):
            return None
    return current


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except OSError:
        return None


def build_archive(
    *,
    out: Path,
    artifacts: tuple[Artifact, ...],
    spool: Path,
) -> Delivery:
    """Pack *artifacts* into a ``tar.zst`` at *spool* and measure it.

    The members are named by their **declared** paths, so an archive of
    one artifact and an archive of all of them place the same file at
    the same name, and a client that asked twice gets the same layout.

    Ownership and mode are normalized rather than copied. The files were
    written by the least trusted component in the system, and their uid,
    gid and permission bits are properties of the container's user
    namespace that mean nothing on the machine the archive is unpacked
    on — carrying them across would be carrying a setuid bit across.

    The archive is built even when *artifacts* is empty, and it is then
    a valid empty ``tar.zst``. That is E45 read together with §5.4: "an
    absent list is an empty delivery, not a permissive one", so the
    honest answer to "give me everything this invocation declared" when
    it declared nothing is an archive with nothing in it, not a refusal
    that would read as "the invocation is unknown".

    **Delivery re-verifies rather than trusting the earlier pass.**
    ``harden`` ran when the invocation ended and this runs when a client
    asks, and between the two the session's container is alive and its
    tree is writable. So the containment walk is redone, the member is
    opened with ``O_NOFOLLOW`` and re-checked on the *descriptor*
    (regular file, one link) rather than on the name, and its bytes are
    hashed as they are packed. A member whose digest is no longer the
    verified one is :data:`artifact.integrity-mismatch` — raised, not
    logged, because a client that receives an archive has no way to tell
    that one of its members is a file it never asked for.
    """
    digest = hashlib.sha256()
    size = 0
    compressor = zstandard.ZstdCompressor()
    with (
        spool.open("wb") as handle,
        compressor.stream_writer(handle, closefd=False) as writer,
        tarfile.open(fileobj=_Counter(writer), mode="w|") as tar,
    ):
        for artifact in artifacts:
            _pack(tar, out, artifact)
    with spool.open("rb") as handle:
        while block := handle.read(_BLOCK):
            digest.update(block)
            size += len(block)
    return Delivery(path=spool, size=size, sha256=digest.hexdigest(), members=artifacts)


def _pack(tar: tarfile.TarFile, out: Path, artifact: Artifact) -> None:
    """Put one verified artifact into the archive, or refuse the delivery.

    Ownership and mode are normalized rather than copied, and the
    descriptor rather than the path is what everything after the open is
    asked about: a check on a name and a read of that name are two
    operations, and the window between them is exactly what a swapped
    symlink lives in.
    """
    resolved = _contained(out, artifact.path)
    if resolved is None:
        raise _changed(artifact, "its path no longer resolves inside the out directory")
    descriptor = _open_nofollow(artifact, resolved)
    try:
        measured = os.fstat(descriptor)
        if not stat.S_ISREG(measured.st_mode):
            raise _changed(artifact, "it is not a regular file any more")
        if measured.st_nlink > 1:
            raise _changed(artifact, f"it carries {measured.st_nlink} links now")
        info = tarfile.TarInfo(artifact.path)
        info.size = measured.st_size
        info.mode = 0o644
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        reader = _Rehashed(descriptor)
        try:
            tar.addfile(info, reader)
        except tarfile.TarError:
            raise _changed(artifact, "it grew shorter while it was being packed") from None
        if reader.hexdigest != artifact.sha256:
            raise _changed(
                artifact,
                f"it hashes to {reader.hexdigest} and was verified as {artifact.sha256}",
            )
    finally:
        os.close(descriptor)


def _open_nofollow(artifact: Artifact, resolved: Path) -> int:
    try:
        return os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise _changed(
            artifact, f"it could not be opened without following a link ({exc.strerror})"
        ) from None


def _changed(artifact: Artifact, problem: str) -> SessionError:
    """``artifact.integrity-mismatch`` — what was verified is not there.

    Named as a statement about the artifact rather than about the
    invocation or the context: the invocation ran, this file was a
    regular file under ``out`` that hashed to the declared value when it
    ended, and it is not that file now. Non-retryable, because a second
    download reads the same changed bytes.
    """
    return SessionError(
        "artifact.integrity-mismatch",
        f'"{artifact.path}" is not the file this server verified when the invocation '
        f"ended: {problem}. Egress is checked again at download time rather than only at "
        "the end of an invocation, because the session's tree stays writable in between "
        "and an archive gives a client no way to notice the substitution.",
        path=artifact.path,
        role=artifact.role,
        sha256=artifact.sha256,
        problem=problem,
    )


class _Rehashed:
    """A read-only view of one descriptor that hashes what goes past it.

    ``tarfile`` copies exactly ``TarInfo.size`` bytes out of this object,
    so hashing here measures precisely the bytes that reach the archive
    — which is what makes the comparison against the verified digest a
    statement about the delivery rather than about a second read of the
    same file.
    """

    def __init__(self, descriptor: int) -> None:
        self._descriptor = descriptor
        self._digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        wanted = _BLOCK if size is None or size < 0 else size
        chunks: list[bytes] = []
        remaining = wanted
        while remaining > 0:
            block = os.read(self._descriptor, remaining)
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        self._digest.update(data)
        return data

    @property
    def hexdigest(self) -> str:
        return self._digest.hexdigest()


class _Counter(io.RawIOBase):
    """A write-only sink that forwards to the compressor.

    ``tarfile`` in stream mode wants a file object with ``write``;
    ``zstandard``'s ``stream_writer`` is one, but it also closes the
    handle underneath it when the ``tarfile`` closes. This adapter keeps
    the two lifetimes apart, which is what lets the spool be re-read for
    hashing once both are done.
    """

    def __init__(self, target) -> None:
        super().__init__()
        self._target = target

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:  # type: ignore[override]
        self._target.write(data)
        return len(data)
