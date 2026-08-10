# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Egress hardening, the download archive, and the SDK this server fetches.

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

from mcuhome_buildserver import artifacts, sdkstore
from mcuhome_buildserver.abi import Artifact
from mcuhome_buildserver.errors import SessionError
from mcuhome_buildserver.ingress import IngressCaps

CAPS = IngressCaps(
    compressed_bytes=1 << 20,
    decompressed_bytes=1 << 20,
    entries=64,
    file_bytes=1 << 20,
    path_depth=8,
)


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
# §9.3, duty by duty
# --------------------------------------------------------------------------


def test_a_matching_artifact_survives_hardening(tmp_path: Path) -> None:
    """The happy path of §9.3, and it is named for what it checks.

    It used to be called "…served with the hash read off disk", which it
    cannot tell apart from "served with the hash it declared": ``harden``
    has already refused every entry where the two differ by the time it
    builds the verified tuple, so both readings produce the same value
    and no assertion here can distinguish them. What the test does show
    is the condition §5.3 counts — a declared artifact that exists,
    re-hashes and comes back with no problem beside it.
    """
    out = _out(tmp_path, **{"firmware.hex": b"payload"})
    verified, problems = artifacts.harden(
        out, (_declare("firmware.hex", b"payload"),), max_bytes=1 << 20
    )
    assert problems == ()
    assert verified[0].sha256 == hashlib.sha256(b"payload").hexdigest()


def test_a_symlinked_artifact_is_refused_rather_than_followed(tmp_path: Path) -> None:
    """ "Enumerate ``out`` **without following symlinks** and reject
    symlinks."

    The containment walk asks whether any segment *is* a link rather
    than where the path leads, which is the only question with a safe
    answer: a ``firmware.hex`` pointing at ``/etc/shadow`` resolves to a
    contained-looking absolute path only after the link was followed.
    """
    out = _out(tmp_path)
    secret = tmp_path / "secret"
    secret.write_bytes(b"payload")
    (out / "firmware.hex").symlink_to(secret)
    verified, problems = artifacts.harden(
        out, (_declare("firmware.hex", b"payload"),), max_bytes=1 << 20
    )
    assert verified == ()
    assert problems and "firmware.hex" in problems[0]


def test_a_symlinked_directory_on_the_way_is_refused_too(tmp_path: Path) -> None:
    """Every segment, not only the last: a link one level up is the same
    escape with one more step in it."""
    out = _out(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "firmware.hex").write_bytes(b"payload")
    (out / "images").symlink_to(elsewhere)
    verified, problems = artifacts.harden(
        out, (_declare("images/firmware.hex", b"payload"),), max_bytes=1 << 20
    )
    assert verified == ()
    assert problems


def test_a_hardlinked_artifact_is_refused(tmp_path: Path) -> None:
    """ "Reject … hardlinks (``nlink > 1``)".

    A second name for bytes that may live outside ``out`` entirely, and
    ``lstat`` cannot tell which name came first. §9.2 forbids the
    program to make one at all.
    """
    out = _out(tmp_path, **{"firmware.hex": b"payload"})
    os.link(out / "firmware.hex", tmp_path / "second-name")
    verified, problems = artifacts.harden(
        out, (_declare("firmware.hex", b"payload"),), max_bytes=1 << 20
    )
    assert verified == ()
    assert "hardlink" in problems[0]


def test_a_fifo_is_not_a_regular_file(tmp_path: Path) -> None:
    """ "Regular files only" — a FIFO declared as an artifact would make
    the egress read block forever on a build container's whim."""
    out = _out(tmp_path)
    os.mkfifo(out / "firmware.hex")
    verified, problems = artifacts.harden(out, (_declare("firmware.hex", b""),), max_bytes=1 << 20)
    assert verified == ()
    assert "regular file" in problems[0]


def test_the_size_cap_is_applied_from_the_bytes_on_disk(tmp_path: Path) -> None:
    """ "Apply size caps during enumeration, from the bytes on disk — an
    artifact entry declares no size."

    ``artifacts[].size`` was struck from the frozen surface, so there is
    nothing to trust and nothing to compare: the file's own length is
    the only number there is.
    """
    payload = b"x" * 4096
    out = _out(tmp_path, **{"firmware.bin": payload})
    verified, problems = artifacts.harden(out, (_declare("firmware.bin", payload),), max_bytes=100)
    assert verified == ()
    assert "serves at most 100" in problems[0]


def test_undeclared_files_are_not_served_and_not_deleted(tmp_path: Path) -> None:
    """ "Files that were not declared are not served, but they are not
    deleted either — they are diagnostic material."

    Naming them is the difference between a build that produced nothing
    and a build that produced something it forgot to declare, which are
    the two readings of an empty delivery and are not the same news.
    """
    out = _out(tmp_path, **{"firmware.hex": b"a", "zephyr.map": b"b", "logs/west.log": b"c"})
    verified, _ = artifacts.harden(out, (_declare("firmware.hex", b"a"),), max_bytes=1 << 20)
    leftovers = artifacts.undeclared(out, verified)
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

    ``harden`` runs when the invocation ends and this runs when the
    client asks, and in between the session's tree is writable inside a
    container that outlives the invocation. A ``firmware.hex`` replaced
    by a link to a host file was followed at download time and its
    target's bytes streamed to the client under the declared name —
    with the archive's own hash matching, because the hash is computed
    over the archive that was built from it.
    """
    out = _out(tmp_path, **{"firmware.hex": b"payload"})
    declared = _declare("firmware.hex", b"payload")
    verified, problems = artifacts.harden(out, (declared,), max_bytes=1 << 20)
    assert problems == () and verified

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
    verified, _ = artifacts.harden(out, (_declare("firmware.hex", b"payload"),), max_bytes=1 << 20)
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
    verified, problems = artifacts.harden(
        out, (_declare("images/firmware.hex", b"payload"),), max_bytes=1 << 20
    )
    assert problems == () and verified

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
    verified, _ = artifacts.harden(out, (_declare("firmware.hex", b"payload"),), max_bytes=1 << 20)
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
    verified, _ = artifacts.harden(out, (_declare("firmware.hex", b"payload"),), max_bytes=1 << 20)
    os.link(out / "firmware.hex", tmp_path / "second-name")

    with pytest.raises(SessionError) as excinfo:
        artifacts.build_archive(out=out, artifacts=verified, spool=tmp_path / "d.tar.zst")
    assert excinfo.value.code == "artifact.integrity-mismatch"
    assert "links" in excinfo.value.details["problem"]


def test_an_artifact_deleted_after_hardening_is_refused_at_delivery(tmp_path: Path) -> None:
    """A verified artifact that is simply gone is the same statement."""
    out = _out(tmp_path, **{"firmware.hex": b"payload"})
    verified, _ = artifacts.harden(out, (_declare("firmware.hex", b"payload"),), max_bytes=1 << 20)
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


# --------------------------------------------------------------------------
# The SDK package (E48)
# --------------------------------------------------------------------------


def _package(directory: Path, version: str, entries: dict[str, bytes]) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, payload in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
    archive = zstandard.ZstdCompressor().compress(raw.getvalue())
    (directory / sdkstore.package_filename(version)).write_bytes(archive)
    return hashlib.sha256(archive).hexdigest()


def test_the_first_source_that_holds_the_package_wins(tmp_path: Path) -> None:
    """ADR 0019's amendment fixes the order the source list is searched
    in, and this server implements its first tier: the configured local
    directories, in the order the operator gave them."""
    first = tmp_path / "first"
    second = tmp_path / "second"
    _package(second, "2.4.0", {"mcuhome/__init__.py": b"second\n"})
    sha256 = _package(first, "2.4.0", {"mcuhome/__init__.py": b"first\n"})
    package = sdkstore.acquire_sdk(
        version="2.4.0",
        sha256=sha256,
        sources=(first, second),
        into=tmp_path / "tree",
        caps=CAPS,
        max_bytes=1 << 20,
    )
    assert package.source == first / "mcuhome-sdk-2.4.0.tar.zst"
    assert (package.tree / "mcuhome/__init__.py").read_bytes() == b"first\n"


def test_a_pin_no_source_holds_names_every_directory_searched(tmp_path: Path) -> None:
    """``sdk.unavailable``, and the details are for the operator.

    The failure is almost always a deployment gap rather than a bad
    context, and the client that sees the refusal is not the party that
    can fix it — so the version, the pinned hash and every directory
    searched all travel with it.
    """
    with pytest.raises(SessionError) as excinfo:
        sdkstore.acquire_sdk(
            version="2.4.0",
            sha256="a" * 64,
            sources=(tmp_path / "nowhere",),
            into=tmp_path / "tree",
            caps=CAPS,
            max_bytes=1 << 20,
        )
    assert excinfo.value.code == "sdk.unavailable"
    assert excinfo.value.details["sources"] == [str(tmp_path / "nowhere")]
    assert excinfo.value.details["version"] == "2.4.0"


def test_the_hash_decides_and_not_the_name(tmp_path: Path) -> None:
    """§9.1: "the content of ``trees.sdk`` matches the manifest's
    ``mcuhome.package.sha256``".

    A file named for the right version whose bytes hash to something
    else is either a corrupted mirror or a package somebody replaced,
    and both are answers an operator has to see rather than a fallback
    this server can make.
    """
    source = tmp_path / "packages"
    _package(source, "2.4.0", {"mcuhome/__init__.py": b"real\n"})
    with pytest.raises(SessionError) as excinfo:
        sdkstore.acquire_sdk(
            version="2.4.0",
            sha256="b" * 64,
            sources=(source,),
            into=tmp_path / "tree",
            caps=CAPS,
            max_bytes=1 << 20,
        )
    assert excinfo.value.code == "sdk.unavailable"
    assert excinfo.value.details["measured"] != "b" * 64


def test_the_package_is_unpacked_with_the_same_safe_extraction(tmp_path: Path) -> None:
    """§9.1 states the rule once for "whatever transport delivered" an
    input, and this reuses the ingress extractor rather than restating
    it: one implementation of "regular files and directories only" in
    this repository.
    """
    source = tmp_path / "packages"
    source.mkdir()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        info = tarfile.TarInfo("escape")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    archive = zstandard.ZstdCompressor().compress(raw.getvalue())
    (source / "mcuhome-sdk-2.4.0.tar.zst").write_bytes(archive)

    with pytest.raises(SessionError) as excinfo:
        sdkstore.acquire_sdk(
            version="2.4.0",
            sha256=hashlib.sha256(archive).hexdigest(),
            sources=(source,),
            into=tmp_path / "tree",
            caps=CAPS,
            max_bytes=1 << 20,
        )
    assert excinfo.value.code == "context.unsafe-entry"


def test_a_package_that_expands_past_the_cap_is_refused_mid_stream(tmp_path: Path) -> None:
    """The reason ``_decompress`` streams at all: "a few kilobytes of
    zstd can expand to gigabytes, and a decompressor that returned its
    output as one ``bytes`` would have allocated the bomb before any
    check could run."

    The cap therefore has to fire *during* the decompression, and the
    spool it was writing into has to be gone afterwards — a refusal that
    left a half-written expansion on disk would have spent the bytes it
    refused to spend.
    """
    source = tmp_path / "packages"
    sha256 = _package(source, "2.4.0", {"big.bin": b"z" * (256 * 1024)})
    into = tmp_path / "tree"
    with pytest.raises(SessionError) as excinfo:
        sdkstore.acquire_sdk(
            version="2.4.0",
            sha256=sha256,
            sources=(source,),
            into=into,
            caps=CAPS,
            max_bytes=4096,
        )
    assert excinfo.value.code == "policy.ingress-limit-exceeded"
    assert excinfo.value.details["limit"] == 4096
    assert not (into.parent / f"{into.name}.tar").exists()


def test_an_sdk_package_may_hold_paths_no_context_could(tmp_path: Path) -> None:
    """The layout whitelist is the *context's* and travels with it.

    An SDK package is a source tree whose shape this server has no
    business knowing, so the part that varies between the two callers of
    the extractor is the layout check and nothing else.
    """
    source = tmp_path / "packages"
    sha256 = _package(source, "2.4.0", {"pyproject.toml": b"[project]\n", "docs/index.md": b"#\n"})
    package = sdkstore.acquire_sdk(
        version="2.4.0",
        sha256=sha256,
        sources=(source,),
        into=tmp_path / "tree",
        caps=CAPS,
        max_bytes=1 << 20,
    )
    assert (package.tree / "pyproject.toml").exists()
    assert (package.tree / "docs/index.md").exists()
