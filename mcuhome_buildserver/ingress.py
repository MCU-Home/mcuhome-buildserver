# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Context bytes arriving: the streaming caps, and safe extraction.

Two duties of ADR 0019 decision 8 live here, and they are separate on
purpose.

**Receiving** is :class:`Upload`. ``send-context`` and ``extend-context``
announce an archive in their JSON payload — its compressed size and its
SHA-256 — and the bytes follow as WebSocket BINARY frames (E41). The
announcement is not trusted and neither is the size: the receiver counts
what actually arrives, hashes it, and decompresses it as it goes, so a
cap can refuse **mid-stream**. That is the whole point of the ADR's word
*streaming*, and the reason the 8 MiB ``max_msg_size`` in
:mod:`mcuhome_buildserver.ws` is explicitly *not* the ingress cap: a
limit that only fires once the bytes are on the host is not a limit.

The decompression bomb is the case that decides the shape. A few
kilobytes of zstd can expand to gigabytes, so nothing here ever calls a
one-shot decompressor: the compressed bytes are pushed through
``ZstdDecompressor.stream_writer``, which hands the unpacked bytes to
:class:`_Spool` in chunks of at most 128 KiB, and :class:`_Spool`
refuses the moment the cumulative budget is spent. A bomb therefore
costs at most one chunk beyond the cap instead of the whole expansion.

**Unpacking** is :func:`unpack`. It is the ADR's safe-extraction rule
and the build-container contract §9.1 duty of the same name, stated
once: regular files and directories only; absolute paths, ``..``,
symlinks, hardlinks and device nodes rejected; writes confined to
``context.yaml`` at the root plus ``model/``, ``keys/`` and
``patches/<layer>/``; ``manifest.yaml`` never an extraction target,
because it is written by this side at ``lock-context``.

The archive format is **tar.zst** and there is no negotiation of it: one
format, chosen for family consistency with the SDK package the same
contract pins (E41). A client that sends anything else is refused by the
decompressor or by ``tarfile``, and that refusal is answered with the
pre-registry ``bad_request`` code — see :func:`_unreadable`.

Nothing here reads or writes session state; the caller owns the session
and passes in the ledger that makes the caps cumulative.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

import zstandard
from mcuhome.model.context import CONTEXT_FILE, KEYS_DIR, MANIFEST_FILE, MODEL_FILE, PATCHES_DIR

from mcuhome_buildserver.errors import SessionError
from mcuhome_buildserver.protocol import ProtocolError

__all__ = [
    "MAX_NAME_BYTES",
    "MAX_PATH_BYTES",
    "IngressCaps",
    "IngressLedger",
    "Upload",
    "ancestors",
    "check_file_target",
    "check_patch_layer",
    "check_path_shape",
    "patch_layer_of",
    "type_conflict",
    "unpack",
]

#: The whitelisted top-level directories, from the model's own constants
#: so that "where model files live" has one spelling in the product.
#: ``mcuhome.model.context`` names the model *file* rather than its
#: directory, and deriving the directory from it beats writing "model"
#: down a second time.
MODEL_DIR = MODEL_FILE.split("/", 1)[0]

#: Exactly 64 lowercase hex digits — build-container contract §3.3.1's
#: spelling for a bare hash. The archive hash is not part of any context
#: identity, but a server that accepted ``SHA256:AB…`` here and refused
#: it three fields later would be teaching clients two spellings.
_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")

#: How large a chunk is copied out of the archive at a time. Bounded so
#: that the per-session disk quota is enforced while the file is being
#: written and not once it is on disk.
_COPY_BLOCK = 1 << 20

#: How long one path component and one whole context path may be, in
#: bytes. Not caps in ADR 0019 decision 8's sense and not configuration:
#: they are the filesystem's own limits (``NAME_MAX`` is 255 on every
#: filesystem this server runs on, ``PATH_MAX`` 4096), and an operator
#: raising them would only move the refusal from this module into
#: ``open()``. They are checked here because they are the one shape of
#: entry that is otherwise refused by the kernel rather than by the
#: protocol: ``model/<300 characters>`` reached ``ENAMETOOLONG`` and left
#: as an untyped ``internal_error``, which is a stack trace where a
#: registry code belongs. The path bound is deliberately well under
#: ``PATH_MAX`` because the per-session directory is a prefix of every
#: one of these paths.
MAX_NAME_BYTES = 255
MAX_PATH_BYTES = 1024


@dataclass(frozen=True)
class IngressCaps:
    """The five caps of ADR 0019 decision 8, as values.

    A frozen record rather than module constants, because the numbers
    are configuration ("the config is the policy") and because a test
    that has to allocate 64 MiB to prove a cap fires is a test nobody
    runs.
    """

    compressed_bytes: int
    decompressed_bytes: int
    entries: int
    file_bytes: int
    path_depth: int

    @staticmethod
    def from_config(config: Any) -> IngressCaps:
        return IngressCaps(
            compressed_bytes=config.max_compressed_bytes,
            decompressed_bytes=config.max_decompressed_bytes,
            entries=config.max_entries,
            file_bytes=config.max_file_bytes,
            path_depth=config.max_path_depth,
        )


@dataclass
class IngressLedger:
    """What one session has already spent of its budgets.

    The caps count **cumulatively across the base context and every
    extension** (E44): ``extend-context`` is repeatable, so a per-archive
    cap would bound nothing at all — a client would simply send the
    same bytes twice.

    The byte and entry counters move when the **transfer** completes,
    not when the verb succeeds. An archive that arrived whole and then
    turned out to carry a symlink is still an archive this host received
    and decompressed, and refunding it would make a bad archive free to
    send again and again. A transfer cut off mid-stream is charged
    nothing, because there was nothing to charge for: the point of the
    streaming refusal is that the rest never arrived.

    :attr:`disk_bytes` is the per-session disk quota's meter. It counts
    what the context directory holds, and falls again when
    ``extend-context`` removes a file. The upload spool is deliberately
    not counted: it is transient, it is bounded by
    :attr:`IngressCaps.decompressed_bytes` in its own right, and it is
    deleted before the verb answers.
    """

    compressed_bytes: int = 0
    decompressed_bytes: int = 0
    entries: int = 0
    disk_bytes: int = 0


def _too_large(what: str, limit: int, measured: int, **details: Any) -> SessionError:
    """The one refusal every cap raises. Never retryable, by registry."""
    return SessionError(
        "policy.ingress-limit-exceeded",
        f"This upload exceeds the server's {what} cap of {limit}: {measured}. The caps "
        "are enforced while the bytes arrive and count across the base context and "
        "every extension of this session.",
        cap=what,
        limit=limit,
        measured=measured,
        **details,
    )


def _unreadable(reason: str) -> ProtocolError:
    """A body that is not a tar.zst archive at all.

    Pre-registry on purpose. The typed registry of
    :mod:`mcuhome_buildserver.errors` describes a *session's* refusals —
    a cap, a forbidden path, a hash that disagrees — and none of its
    entries means "these bytes are not an archive". No ADR names a code
    for it either, and adding one is a protocol decision rather than an
    implementation choice, so this answers in the envelope's own
    vocabulary (``bad_request``, "the frame was not understood, always
    the client's fault") instead of inventing a code that would then be
    append-only forever.
    """
    return ProtocolError(f"This send did not carry a readable tar.zst archive: {reason}.")


class _Spool:
    """The sink the decompressor writes into — and the streaming cap.

    ``zstandard``'s ``stream_writer`` calls :meth:`write` with at most
    one output buffer (128 KiB) per call, so raising from here stops a
    decompression bomb after one chunk over the budget rather than after
    the whole expansion. That is the mechanism behind the ADR's
    "enforced *streaming* during upload"; a decompressor that returned
    its output as one ``bytes`` would have allocated the bomb before any
    check could run.
    """

    def __init__(self, handle: BinaryIO, *, limit: int, spent: int) -> None:
        self._handle = handle
        self._limit = limit
        self._spent = spent
        self.written = 0

    def write(self, data: bytes) -> int:
        self.written += len(data)
        total = self._spent + self.written
        if total > self._limit:
            raise _too_large("cumulative decompressed size", self._limit, total)
        self._handle.write(data)
        return len(data)

    def flush(self) -> None:
        self._handle.flush()


class Upload:
    """One announced archive, received frame by frame off the socket.

    The lifetime is deliberately split across two callers, because the
    two halves happen in different places: the ``/ws`` read loop calls
    :meth:`feed` for every BINARY frame — synchronously, so no queue can
    grow behind it — and the verb handler waits on :meth:`result`, which
    is what turns "the bytes arrived and hashed correctly" into the
    command's own answer. That is E41's acknowledgement: the result
    frame of ``send-context`` *is* the acknowledgement, correlated by
    the frame id like every other answer, so no new frame kind is
    needed.

    The declared hash is checked against the bytes actually received and
    a disagreement is ``context.integrity-mismatch`` — ADR 0019 decision
    8's "never trust client-declared hashes … declared values are
    advisory", applied to the one hash the client declares about the
    transport itself.
    """

    def __init__(
        self,
        *,
        declared_size: int,
        declared_sha256: str,
        spool: Path,
        caps: IngressCaps,
        ledger: IngressLedger,
    ) -> None:
        if declared_size <= 0:
            raise ProtocolError("An announced archive must declare a positive size in bytes.")
        if _SHA256_HEX.fullmatch(declared_sha256) is None:
            raise ProtocolError(
                'An announced archive declares its "sha256" as exactly 64 lowercase hex '
                "digits, the one spelling the build-container contract fixes for a bare "
                f"hash (§3.3.1); this one reads {declared_sha256!r}."
            )
        # The compressed cap is checked twice, and both are needed. Here,
        # against the *declared* size, so an archive that cannot fit is
        # refused before a single byte is accepted; and on the wire in
        # :meth:`feed`, against the count that actually arrives, so a
        # client that under-declares is cut off at its own declaration.
        if ledger.compressed_bytes + declared_size > caps.compressed_bytes:
            raise _too_large(
                "compressed size",
                caps.compressed_bytes,
                ledger.compressed_bytes + declared_size,
                declared=declared_size,
            )
        self._declared_size = declared_size
        self._declared_sha256 = declared_sha256
        self._path = spool
        self._ledger = ledger
        self._hash = hashlib.sha256()
        self._received = 0
        self._handle = spool.open("wb")
        self._sink = _Spool(
            self._handle, limit=caps.decompressed_bytes, spent=ledger.decompressed_bytes
        )
        self._writer = zstandard.ZstdDecompressor().stream_writer(self._sink, closefd=False)
        self._done: asyncio.Future[Path] = asyncio.get_running_loop().create_future()

    def feed(self, data: bytes) -> None:
        """Take one BINARY frame. Called from the read loop; never raises.

        A failure is stored on the future instead of thrown, because the
        thrower here would be the connection's reader: an exception in
        it would take down the whole socket over one bad upload, and the
        client would lose the typed refusal that says what went wrong.
        """
        if self._done.done():
            return
        try:
            self._receive(data)
        except (SessionError, ProtocolError) as exc:
            self._fail(exc)
        except zstandard.ZstdError as exc:
            self._fail(_unreadable(f"the zstd stream is not valid ({exc})"))
        except Exception as exc:  # the future is the only way an error can leave
            self._fail(exc)

    def _receive(self, data: bytes) -> None:
        self._received += len(data)
        if self._received > self._declared_size:
            raise ProtocolError(
                f"This upload announced {self._declared_size} bytes and has already sent "
                f"{self._received}. The announced size bounds the transfer; a context "
                "that grew is a new send-context, not a longer one."
            )
        self._hash.update(data)
        self._writer.write(data)
        if self._received == self._declared_size:
            self._complete()

    def _complete(self) -> None:
        self._writer.close()
        self._handle.close()
        computed = self._hash.hexdigest()
        if computed != self._declared_sha256:
            raise SessionError(
                "context.integrity-mismatch",
                "The archive this server received does not hash to the value the upload "
                "declared. Declared hashes are advisory and the bytes decide (ADR 0019 "
                "decision 8), so the upload is refused rather than repaired.",
                declared=self._declared_sha256,
                computed=computed,
                paths=[],
            )
        self._ledger.compressed_bytes += self._received
        self._ledger.decompressed_bytes += self._sink.written
        self._done.set_result(self._path)

    def _fail(self, exc: BaseException) -> None:
        self.close()
        if not self._done.done():
            self._done.set_exception(exc)

    async def result(self, *, timeout: float) -> Path:
        """Wait for the archive, and answer where it was spooled.

        *timeout* is the session's own idle timeout rather than a number
        of this module's making. A client that announces an archive and
        then sends nothing is precisely an idle session — the ADR's
        idle timeout "counts absent commands" and this is a command that
        never finished — so the deadline that already exists is the one
        that applies, and there is no second number to invent.
        """
        try:
            return await asyncio.wait_for(self._done, timeout)
        except TimeoutError:
            self.close()
            raise ProtocolError(
                f"This upload announced {self._declared_size} bytes, delivered "
                f"{self._received}, and then went quiet for {timeout:.0f} seconds. The "
                "session is untouched; send the context again."
            ) from None
        finally:
            self.close()

    def close(self) -> None:
        """Release the spool handle. Idempotent; the spooled file survives.

        The decompressor is closed first and its complaint swallowed: on
        an abandoned upload the zstd frame is simply unfinished, which
        is not news — the refusal that got us here already said what was
        wrong, and a second exception from the cleanup path would hide
        it.
        """
        if not self._handle.closed:
            with contextlib.suppress(zstandard.ZstdError, ValueError, OSError):
                self._writer.close()
            self._handle.close()


# --------------------------------------------------------------------------
# Safe extraction
# --------------------------------------------------------------------------


def check_path_shape(name: str) -> str:
    """The context-relative path of one archive entry, or a refusal.

    Refused rather than normalized, for the reason the whole format
    refuses rather than normalizes: these strings become the ``path``
    values of the ``files`` integrity list, and ``mcuhome.model.context``
    rejects ``.`` and ``..`` segments there. Silently rewriting ``./x``
    to ``x`` here would accept a context whose own identity rule then
    refuses it — two spellings for one file, which is exactly what
    build-container contract §3.3.1 exists to prevent.
    """
    cleaned = name.rstrip("/")
    usable = (
        cleaned
        and "\\" not in cleaned
        and "\x00" not in cleaned
        and not cleaned.startswith("/")
        and all(part not in ("", ".", "..") for part in cleaned.split("/"))
    )
    if not usable:
        raise SessionError(
            "context.unsafe-entry",
            f"The archive entry {name!r} is not a usable context path. Context paths are "
            "relative, use forward slashes and carry no empty, . or .. segment — they are "
            "extraction targets and hashed identity at once.",
            entry=name,
        )
    # The kernel's own bounds, refused here so that they are refused
    # typed. Without this an over-long component reaches `open()` and
    # comes back as `ENAMETOOLONG`, which leaves the verb as an untyped
    # `internal_error` on input a client fully controls.
    encoded = cleaned.encode("utf-8", errors="surrogateescape")
    longest = max(
        len(part.encode("utf-8", errors="surrogateescape")) for part in cleaned.split("/")
    )
    if longest > MAX_NAME_BYTES or len(encoded) > MAX_PATH_BYTES:
        raise SessionError(
            "context.unsafe-entry",
            f"The archive entry {name[:80]!r} is too long to be a context path: this server "
            f"takes at most {MAX_NAME_BYTES} bytes per path component and {MAX_PATH_BYTES} "
            "bytes in total, which is what the filesystem underneath it takes.",
            entry=name[:80],
            component_bytes=longest,
            path_bytes=len(encoded),
        )
    return cleaned


def ancestors(path: str) -> tuple[str, ...]:
    """Every directory *path* would live in, outermost first."""
    parts = path.split("/")
    return tuple("/".join(parts[:index]) for index in range(1, len(parts)))


def type_conflict(path: str, *, conflict: str, where: str) -> SessionError:
    """One path claimed as a file and as a directory at once.

    Registered as ``context.unsafe-entry`` rather than as a code of its
    own. That entry is about an extraction target this server refuses,
    and a path that has to be a file and a directory simultaneously is
    one: no filesystem holds both, so the context the client is
    describing does not exist. Widening the registry entry's summary was
    the alternative to a new code, and the pre-release window is what
    makes amending a summary legitimate where adding a code would be a
    protocol decision (:mod:`mcuhome_buildserver.errors`).

    Both paths are named, because the offending entry is rarely the
    interesting one: a client that sent ``model/a`` sees nothing wrong
    with it until it is told that ``model/a/b.json`` is already there.
    """
    if conflict == path:
        problem = f'"{path}" appears in this {where} as a file and as a directory'
    else:
        problem = (
            f'"{path}" and "{conflict}" cannot both be in this {where}: one of them is a '
            "file and the other needs it to be a directory"
        )
    return SessionError(
        "context.unsafe-entry",
        f"{problem}. A context path is one or the other, so this describes a directory "
        "tree that cannot exist; send one of the two.",
        entry=path,
        conflict=conflict,
    )


def patch_layer_of(path: str) -> str | None:
    """The patch layer *path* belongs to, or ``None`` if it is not a patch.

    The whole of patch semantics, as ADR 0018 decision 2 defines it: a
    patch's layer **is** its subfolder. There is no declared patch list
    anywhere in the format, which is what lets a server re-derive its
    policy from the files actually present and be sure nothing disagrees.
    """
    parts = path.split("/")
    if len(parts) == 3 and parts[0] == PATCHES_DIR:
        return parts[1]
    return None


def check_file_target(path: str, *, allow_context_file: bool) -> None:
    """Refuse a file the context layout has no place for.

    The whitelist is ADR 0019 decision 8's, verbatim: ``context.yaml`` at
    the root plus ``model/``, ``keys/`` and ``patches/<layer>/``.
    ``patches`` is the one subtree with a fixed depth, because a layer
    folder holds patch files and nothing else — a nested path has no
    meaning for the application order, which is the filename alone.

    Exported because ``extend-context``'s ``remove`` list names files in
    exactly this layout, and a second copy of the whitelist is how the
    two halves of one verb start disagreeing about where a context ends.
    """
    parts = path.split("/")
    if path == CONTEXT_FILE:
        if not allow_context_file:
            raise SessionError(
                "context.pins-immutable",
                "An extension may not carry context.yaml. It holds the pins this session "
                "was admitted on, and changing them is a new session rather than an "
                "extension (ADR 0018's amendment, build-container contract §3.2).",
                entry=path,
            )
        return
    if path == MANIFEST_FILE:
        raise SessionError(
            "context.unsafe-entry",
            "manifest.yaml is never an extraction target: it is written by this server at "
            "lock-context and is the result of freezing the context, never an input to it.",
            entry=path,
        )
    if parts[0] in (MODEL_DIR, KEYS_DIR) and len(parts) >= 2:
        return
    if patch_layer_of(path) is not None:
        return
    raise SessionError(
        "context.unsafe-entry",
        f'"{path}" is outside the subtrees a context may carry. A context holds '
        f"{CONTEXT_FILE} at its root and files under {MODEL_DIR}/, {KEYS_DIR}/ and "
        f"{PATCHES_DIR}/<layer>/, and nothing else.",
        entry=path,
    )


def _patch_layer_directory(path: str) -> str | None:
    """The layer a ``patches/<layer>`` **directory** entry would create.

    Checked so that a denied layer is refused by its folder as well as
    by the patches in it. An empty folder carries no patch and could not
    change a build, but accepting one would leave a context whose shape
    says a denied layer is welcome here.
    """
    parts = path.split("/")
    if len(parts) == 2 and parts[0] == PATCHES_DIR:
        return parts[1]
    return None


def _check_directory_target(path: str) -> None:
    """The same whitelist, for the directories a file could live in."""
    parts = path.split("/")
    if parts[0] in (MODEL_DIR, KEYS_DIR):
        return
    if parts[0] == PATCHES_DIR and len(parts) <= 2:
        return
    raise SessionError(
        "context.unsafe-entry",
        f'"{path}/" is not a directory a context has. Only {MODEL_DIR}/, {KEYS_DIR}/ and '
        f"{PATCHES_DIR}/<layer>/ exist in the layout the context format defines.",
        entry=path,
    )


def check_patch_layer(layer: str, allowed_layers: frozenset[str], *, where: str) -> None:
    """The config is the policy: an unlisted layer is denied (decision 7).

    Deny-by-default, and the same answer for a layer this server knows
    but does not allow, for one it has never heard of, and for a
    third-party ``x-`` name that nobody listed. Three different reasons
    to say no, one thing the client has to do about it.

    Exported because ADR 0019 §2 requires the layer set to be re-derived
    "from the files *actually present*" after every extension, and that
    re-derivation must reach the same verdict as this one — which it can
    only be sure of by being this one.
    """
    if layer in allowed_layers:
        return
    raise SessionError(
        "policy.patch-layer-denied",
        f'This server does not allow contexts to patch the "{layer}" layer. Patch policy '
        "is the server's configuration and unlisted layers are denied; there is no "
        "permissive mode.",
        entry=where,
        layer=layer,
        allowed=sorted(allowed_layers),
    )


def unpack(
    archive: Path,
    *,
    into: Path,
    caps: IngressCaps,
    ledger: IngressLedger,
    allowed_layers: frozenset[str],
    quota_bytes: int,
    allow_context_file: bool,
) -> tuple[str, ...]:
    """Unpack the spooled tar into *into*, refusing at the first offence.

    Returns the context-relative paths written, in archive order. Every
    check is made **before** the entry it judges is materialized, so a
    refusal never leaves the offending entry behind; the caller discards
    the whole target directory anyway, which is what makes a refused
    upload leave a session exactly as it found it.

    The archive's own mode bits are discarded rather than applied. A
    mode is not context content — nothing in the format or the contract
    reads one — and honouring it would let an archive ask for setuid
    bits on a file this server owns.
    """
    into.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    files: set[str] = set()
    directories: set[str] = set()
    try:
        with archive.open("rb") as raw, tarfile.open(fileobj=raw, mode="r|") as tar:
            for member in tar:
                # Charged as the member is read rather than when the
                # unpack succeeds, which is the rule :class:`IngressLedger`
                # states for all three counters: an archive that arrived
                # whole and then turned out to carry a symlink is still an
                # archive this host received, and refunding its entries
                # would make a bad archive free to send again and again.
                # The offending member counts too — it arrived.
                ledger.entries += 1
                if ledger.entries > caps.entries:
                    raise _too_large("entry count", caps.entries, ledger.entries)
                path = check_path_shape(member.name)
                depth = len(path.split("/"))
                if depth > caps.path_depth:
                    raise _too_large("path depth", caps.path_depth, depth, entry=path)
                if member.isdir():
                    _check_directory_target(path)
                    layer = _patch_layer_directory(path)
                    if layer is not None:
                        check_patch_layer(layer, allowed_layers, where=path)
                    _check_kinds(path, files=files, directories=directories, directory=True)
                    (into / path).mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise SessionError(
                        "context.unsafe-entry",
                        f'"{path}" is not a regular file. A context carries regular files '
                        "and directories only: a symlink, a hardlink or a device node in "
                        "an archive is a way out of the directory it is unpacked into.",
                        entry=path,
                    )
                # Shape before policy: `patches/0001.patch` names no layer
                # at all, and answering "layer 0001.patch is denied" would
                # tell the client to ask an operator for something that
                # could never be allowed.
                check_file_target(path, allow_context_file=allow_context_file)
                layer = patch_layer_of(path)
                if layer is not None:
                    check_patch_layer(layer, allowed_layers, where=path)
                if path in files:
                    raise _unreadable(f"it names {path!r} twice, so its content is ambiguous")
                _check_kinds(path, files=files, directories=directories, directory=False)
                if member.size > caps.file_bytes:
                    raise _too_large("per-file size", caps.file_bytes, member.size, entry=path)
                _write_member(tar, member, into / path, ledger=ledger, quota=quota_bytes)
                written.append(path)
    except tarfile.TarError as exc:
        raise _unreadable(f"the tar stream is not valid ({exc})") from exc
    except EOFError as exc:
        raise _unreadable("the tar stream ends in the middle of an entry") from exc
    return tuple(written)


def _check_kinds(path: str, *, files: set[str], directories: set[str], directory: bool) -> None:
    """Refuse an entry whose kind contradicts one already materialized.

    The bookkeeping is the archive's own, not the filesystem's, because
    the filesystem answers this question by raising: ``mkdir`` over a
    regular file is ``FileExistsError`` and ``open(…, "wb")`` on a
    directory is ``IsADirectoryError``, and both used to leave the verb
    as an untyped ``internal_error`` on input the client fully controls.
    Every other malformed archive in this module gets a registry code;
    this one now does too.

    Both directions are checked, because an archive names its entries in
    whatever order it likes: ``model/a`` then ``model/a/b`` is a file
    that a later entry needs to be a directory, and ``model/a/b`` then
    ``model/a`` is the same collision announced the other way round.
    """
    for parent in ancestors(path):
        if parent in files:
            raise type_conflict(path, conflict=parent, where="archive")
        directories.add(parent)
    if directory:
        if path in files:
            raise type_conflict(path, conflict=path, where="archive")
        directories.add(path)
        return
    if path in directories:
        blocking = next((known for known in sorted(files) if known.startswith(path + "/")), path)
        raise type_conflict(path, conflict=blocking, where="archive")
    files.add(path)


def _write_member(
    tar: tarfile.TarFile,
    member: tarfile.TarInfo,
    target: Path,
    *,
    ledger: IngressLedger,
    quota: int,
) -> None:
    """Copy one member out, counting as it goes rather than afterwards.

    **The per-file cap is not re-checked here, and the reason is that it
    cannot fire.** ``tarfile.extractfile`` hands back a reader bounded by
    the header's ``size``, so the bytes that appear can never exceed the
    number the caller already refused against — an under-declaring header
    yields *fewer* bytes, not more. The claim that used to stand here,
    that the header "is checked again against the bytes that actually
    appear", was therefore untestable and untrue, and a check no input
    can reach is a check nobody maintains.

    The **quota** check below is a different matter and stays streaming:
    it counts across every file of the session, so it can be spent by an
    entry that is individually well under the per-file cap.
    """
    source = tar.extractfile(member)
    if source is None:  # pragma: no cover - isfile() was true a line ago
        raise _unreadable(f"{member.name!r} carries no data")
    target.parent.mkdir(parents=True, exist_ok=True)
    copied = 0
    with target.open("wb") as handle:
        while block := source.read(_COPY_BLOCK):
            copied += len(block)
            if ledger.disk_bytes + copied > quota:
                raise SessionError(
                    "policy.quota-exceeded",
                    f"This session's disk budget of {quota} bytes is spent. The quota is "
                    "per session and answered here rather than by the host running out of "
                    "room; close the session or send a smaller context.",
                    quota=quota,
                    measured=ledger.disk_bytes + copied,
                )
            handle.write(block)
    target.chmod(0o600)
    ledger.disk_bytes += copied
