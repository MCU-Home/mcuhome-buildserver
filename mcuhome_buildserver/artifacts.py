# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Chunked, hashed artifact transfer (ADR 0006 decision 7).

An artifact set is a bootloader, an unsigned application, a merged hex
and a manifest — a megabyte or two, over a WebSocket that is also
carrying a live build log. It goes in chunks, and every chunk carries a
hash.

**The manifest is the index, and the whitelist.** ``build-manifest.json``
already states every file the build produced with its size and its
SHA-256 (`mcuhome/manifest.py`), so this module does not walk a
directory and does not join a client's string onto a path. A download
names a path that is *in the index* or it is a ``not_found`` — which
means path traversal is not defended against here, it is unreachable.

**Two hashes, two jobs.** The per-file SHA-256 comes from the manifest
and is what ADR 0010's flash tunnel anchors on: it was computed by the
build, it travels in a document the dashboard can keep, and it says the
bytes are the bytes the build produced. The per-chunk SHA-256 is
computed here and says the chunk survived the wire. A client that checks
only the second one has verified a transfer; a client that checks both
has verified the artifact.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "DEFAULT_CHUNK_BYTES",
    "MANIFEST_FILE",
    "Artifact",
    "ArtifactSet",
    "read_artifact_set",
    "read_chunk",
]

#: Written by the builder at the top of the build directory.
MANIFEST_FILE = "build-manifest.json"

#: Bytes per chunk before base64. 256 KiB is ~350 KiB on the wire, which
#: is a comfortable WebSocket frame and still only a handful of round
#: trips for a Matter image.
DEFAULT_CHUNK_BYTES = 256 * 1024


@dataclass(frozen=True)
class Artifact:
    """One downloadable file, as the manifest describes it."""

    #: Relative to the build directory, forward slashes, exactly as the
    #: manifest spells it.
    path: str
    size: int
    #: SHA-256 as the *build* computed it, or ``None`` for the manifest
    #: itself — a document cannot state its own hash.
    sha256: str | None
    #: ``bootloader`` · ``application`` · ``merged`` · ``manifest``
    role: str

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256, "role": self.role}


@dataclass(frozen=True)
class ArtifactSet:
    """Everything one finished build offers, and where it lives."""

    root: Path
    manifest: dict[str, Any]
    artifacts: tuple[Artifact, ...]

    def get(self, path: str) -> Artifact | None:
        return next((item for item in self.artifacts if item.path == path), None)

    def resolve(self, path: str) -> Path | None:
        """The file behind an indexed path, or ``None``.

        The index membership check is the whole security argument, and
        the ``is_relative_to`` below is the belt to its braces: a
        manifest is generator output, but this process serves what it
        says, so "the manifest could not name ``../..``" is an assumption
        worth not making.
        """
        if self.get(path) is None:
            return None
        candidate = (self.root / path).resolve()
        if not candidate.is_relative_to(self.root.resolve()) or not candidate.is_file():
            return None
        return candidate

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest,
            "artifacts": [item.to_dict() for item in self.artifacts],
            "chunk_bytes": DEFAULT_CHUNK_BYTES,
        }


def _entries(manifest: dict[str, Any]) -> list[Artifact]:
    found: dict[str, Artifact] = {}

    def add(entry: Any, role: str) -> None:
        if not isinstance(entry, dict):
            return
        path = entry.get("path")
        if not isinstance(path, str) or not path:
            return
        found.setdefault(
            path,
            Artifact(
                path=path,
                size=int(entry.get("size") or 0),
                sha256=entry.get("sha256"),
                role=role,
            ),
        )

    for image in manifest.get("images") or []:
        if not isinstance(image, dict):
            continue
        role = str(image.get("role") or image.get("name") or "image")
        for entry in image.get("files") or []:
            add(entry, role)
    add(manifest.get("merged"), "merged")
    return sorted(found.values(), key=lambda item: item.path)


def read_artifact_set(build_dir: Path) -> ArtifactSet | None:
    """Index one finished build directory, or ``None`` when it has none.

    Reads the manifest from disk rather than trusting the copy in the job
    record: the record is what the build *said*, this is what the
    directory *has*, and a download has to serve the second one.
    """
    manifest_path = build_dir / MANIFEST_FILE
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(manifest, dict):
        return None

    artifacts = _entries(manifest)
    with contextlib.suppress(OSError):  # pragma: no branch - it was just read
        artifacts.append(
            Artifact(
                path=MANIFEST_FILE,
                size=manifest_path.stat().st_size,
                sha256=None,
                role="manifest",
            )
        )
    return ArtifactSet(root=build_dir, manifest=manifest, artifacts=tuple(artifacts))


def read_chunk(path: Path, offset: int, limit: int = DEFAULT_CHUNK_BYTES) -> dict[str, Any]:
    """One chunk of *path*, base64 with its own hash.

    Blocking; the caller runs it in a thread. ``eof`` is what ends the
    loop on the other side — a client stops when the server says the
    file is done, not when it counted bytes to a size it was told
    earlier and which a truncated file would never reach.
    """
    with path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(limit)
        eof = handle.read(1) == b""
    return {
        "offset": offset,
        "length": len(data),
        "next_offset": offset + len(data),
        "eof": eof,
        "sha256": hashlib.sha256(data).hexdigest(),
        "data": base64.b64encode(data).decode("ascii"),
    }
