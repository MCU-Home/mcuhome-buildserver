# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Egress: what is not served, and the download archive.

Contract §9.3 opens with the reason all of this exists: "``out`` is
written by the least trusted component in the system and its contents
travel over the network onto other people's machines." The cases below
are the ones a build container would have to be hostile or broken to
produce, which is exactly why they are stated directly rather than
through a session.
"""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
from pathlib import Path

import pytest
import zstandard

from mcuhome_buildserver import artifacts
from mcuhome_buildserver.abi import Artifact
from mcuhome_buildserver.errors import SessionError


def _declare(path: str, payload: bytes, role: str = "firmware") -> Artifact:
    return Artifact(root="out", path=path, role=role, sha256=hashlib.sha256(payload).hexdigest())


def _out(tmp_path: Path, **files: bytes) -> Path:
    out = tmp_path / "out"
    out.mkdir()
    for name, payload in files.items():
        target = out / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    return out


# --------------------------------------------------------------------------
# What is not served, and is not deleted either (§9.3)
# --------------------------------------------------------------------------


def test_undeclared_files_are_not_served_and_not_deleted(tmp_path: Path) -> None:
    """ "Files that were not declared are not served, but they are not
    deleted either — they are diagnostic material."

    Naming them is the difference between a build that produced nothing
    and a build that produced something it forgot to declare, which are
    the two readings of an empty delivery and are not the same news.
    """
    out = _out(tmp_path, **{"firmware.hex": b"a", "zephyr.map": b"b", "logs/west.log": b"c"})
    leftovers = artifacts.undeclared(out, (_declare("firmware.hex", b"a"),))
    assert leftovers == ("logs/west.log", "zephyr.map")
    assert (out / "zephyr.map").exists()


# --------------------------------------------------------------------------
# The download archive (E45)
# --------------------------------------------------------------------------


def _members(archive: Path) -> dict[str, bytes]:
    raw = zstandard.ZstdDecompressor().decompress(archive.read_bytes(), max_output_size=1 << 22)
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        return {
            member.name: tar.extractfile(member).read()
            for member in tar.getmembers()
            if member.isfile()
        }


def test_the_archive_holds_the_artifacts_under_their_declared_paths(tmp_path: Path) -> None:
    """E45, and the reason the paths are the declared ones: an archive of
    one artifact and an archive of all of them place the same file at the
    same name, so a client that asked twice gets the same layout."""
    out = _out(tmp_path, **{"firmware.hex": b"hex", "sub/firmware.bin": b"bin"})
    delivery = artifacts.build_archive(
        out=out,
        artifacts=(_declare("firmware.hex", b"hex"), _declare("sub/firmware.bin", b"bin")),
        spool=tmp_path / "download.tar.zst",
    )
    assert _members(delivery.path) == {"firmware.hex": b"hex", "sub/firmware.bin": b"bin"}
    assert delivery.sha256 == hashlib.sha256(delivery.path.read_bytes()).hexdigest()
    assert delivery.size == delivery.path.stat().st_size


def test_the_archive_normalizes_ownership_and_mode(tmp_path: Path) -> None:
    """The files were written by the least trusted component in the
    system, and their uid, gid and permission bits are properties of a
    user namespace that mean nothing where the archive is unpacked —
    carrying them across would be carrying a setuid bit across."""
    out = _out(tmp_path, **{"firmware.hex": b"hex"})
    (out / "firmware.hex").chmod(0o4777)
    delivery = artifacts.build_archive(
        out=out, artifacts=(_declare("firmware.hex", b"hex"),), spool=tmp_path / "d.tar.zst"
    )
    raw = zstandard.ZstdDecompressor().decompress(delivery.path.read_bytes(), 1 << 20)
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        member = tar.getmember("firmware.hex")
    assert member.mode == 0o644
    assert member.uid == 0 and member.uname == ""


def test_an_artifact_swapped_for_a_symlink_after_hardening_is_not_followed(
    tmp_path: Path,
) -> None:
    """The blocker: §9.3 enforced at delivery and not only at finish.

    The orchestrator verifies when the invocation ends and this runs
    when the client asks, and in between the session's tree is writable
    inside a container that outlives the invocation. A ``firmware.hex`` replaced
    by a link to a host file was followed at download time and its
    target's bytes streamed to the client under the declared name —
    with the archive's own hash matching, because the hash is computed
    over the archive that was built from it.
    """
    out = _out(tmp_path, **{"firmware.hex": b"payload"})
    verified = (_declare("firmware.hex", b"payload"),)

    outside = tmp_path / "outside"
    outside.write_bytes(b"root:x:0:0 -- a host file outside out/\n")
    (out / "firmware.hex").unlink()
    (out / "firmware.hex").symlink_to(outside)

    spool = tmp_path / "download.tar.zst"
    with pytest.raises(SessionError) as excinfo:
        artifacts.build_archive(out=out, artifacts=verified, spool=spool)
    assert excinfo.value.code == "artifact.integrity-mismatch"
    assert excinfo.value.details["path"] == "firmware.hex"
    assert outside.read_bytes() not in spool.read_bytes()


def test_a_member_swapped_between_the_check_and_the_open_is_not_followed(
    tmp_path: Path, monkeypatch
) -> None:
    """``O_NOFOLLOW`` is what the containment walk cannot do on its own.

    Checking a name and opening that name are two operations, and the
    window between them is where a substitution lives. The re-hash does
    not close it: a link whose target's bytes hash to the declared value
    passes every check that reads content, and the server has still read
    a file outside ``out`` — which may be somebody else's, and which
    ``out`` being the boundary is supposed to make impossible.

    The race is simulated rather than run, because a race that
    reproduces sometimes is a test that passes sometimes: the swap is
    made from inside the containment walk, at exactly the moment the
    real one would leave it.
    """
    out = _out(tmp_path, **{"firmware.hex": b"payload"})
    verified = (_declare("firmware.hex", b"payload"),)
    outside = tmp_path / "outside"
    outside.write_bytes(b"payload")
    real = artifacts._contained

    def racing(out_directory: Path, relative: str):
        resolved = real(out_directory, relative)
        (out / "firmware.hex").unlink()
        (out / "firmware.hex").symlink_to(outside)
        return resolved

    monkeypatch.setattr(artifacts, "_contained", racing)
    with pytest.raises(SessionError) as excinfo:
        artifacts.build_archive(out=out, artifacts=verified, spool=tmp_path / "d.tar.zst")
    assert excinfo.value.code == "artifact.integrity-mismatch"
    assert "without following a link" in excinfo.value.details["problem"]


def test_a_directory_on_the_way_that_became_a_link_is_refused_at_delivery(tmp_path: Path) -> None:
    """Every segment, not only the last — at delivery as at hardening.

    ``O_NOFOLLOW`` protects the final component and nothing before it,
    so an ``images/`` that became a symlink between the two moments
    would be walked through by the open. The declared path is therefore
    re-resolved segment by segment here too, and the bytes behind the
    link hashing to the declared value does not make it the artifact.
    """
    out = _out(tmp_path, **{"images/firmware.hex": b"payload"})
    verified = (_declare("images/firmware.hex", b"payload"),)

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "firmware.hex").write_bytes(b"payload")
    (out / "images" / "firmware.hex").unlink()
    (out / "images").rmdir()
    (out / "images").symlink_to(elsewhere)

    with pytest.raises(SessionError) as excinfo:
        artifacts.build_archive(out=out, artifacts=verified, spool=tmp_path / "d.tar.zst")
    assert excinfo.value.code == "artifact.integrity-mismatch"
    assert "no longer resolves inside" in excinfo.value.details["problem"]


def test_an_artifact_rewritten_after_hardening_fails_the_re_hash(tmp_path: Path) -> None:
    """The same window without a link in it: same path, same file, other
    bytes.

    The descriptor is re-checked and the member is re-hashed **while it
    is packed**, so what the archive is measured against is what went
    into it rather than a second read of the file afterwards.
    """
    out = _out(tmp_path, **{"firmware.hex": b"payload"})
    verified = (_declare("firmware.hex", b"payload"),)
    (out / "firmware.hex").write_bytes(b"other payload")

    with pytest.raises(SessionError) as excinfo:
        artifacts.build_archive(out=out, artifacts=verified, spool=tmp_path / "d.tar.zst")
    assert excinfo.value.code == "artifact.integrity-mismatch"
    assert excinfo.value.to_envelope()["retryable"] is False
    assert "hashes to" in excinfo.value.details["problem"]


def test_an_artifact_hardlinked_after_hardening_is_refused_at_delivery(tmp_path: Path) -> None:
    """``nlink > 1`` is asked of the **descriptor**, not of the name.

    A check on a path and a read of that path are two operations, and
    the window between them is where the substitution lives — so the
    open comes first and everything after it is asked about the file
    that was actually opened.
    """
    out = _out(tmp_path, **{"firmware.hex": b"payload"})
    verified = (_declare("firmware.hex", b"payload"),)
    os.link(out / "firmware.hex", tmp_path / "second-name")

    with pytest.raises(SessionError) as excinfo:
        artifacts.build_archive(out=out, artifacts=verified, spool=tmp_path / "d.tar.zst")
    assert excinfo.value.code == "artifact.integrity-mismatch"
    assert "links" in excinfo.value.details["problem"]


def test_an_artifact_deleted_after_hardening_is_refused_at_delivery(tmp_path: Path) -> None:
    """A verified artifact that is simply gone is the same statement."""
    out = _out(tmp_path, **{"firmware.hex": b"payload"})
    verified = (_declare("firmware.hex", b"payload"),)
    (out / "firmware.hex").unlink()

    with pytest.raises(SessionError) as excinfo:
        artifacts.build_archive(out=out, artifacts=verified, spool=tmp_path / "d.tar.zst")
    assert excinfo.value.code == "artifact.integrity-mismatch"


def test_an_empty_delivery_is_an_archive_with_nothing_in_it(tmp_path: Path) -> None:
    """ "An absent list is an empty delivery, not a permissive one."

    So the honest answer to "give me everything this invocation
    declared" when it declared nothing is an archive with nothing in it,
    not a refusal that would read as "the invocation is unknown".
    """
    delivery = artifacts.build_archive(
        out=_out(tmp_path), artifacts=(), spool=tmp_path / "empty.tar.zst"
    )
    assert _members(delivery.path) == {}
    assert delivery.size > 0
