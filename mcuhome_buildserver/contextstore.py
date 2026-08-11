# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The context on disk: where it lives, what it declares, and the freeze.

Three things, in the order a session meets them.

**Where it lives** is :class:`SessionPaths`. ADR 0019 decision 8 requires
extraction "into a per-session directory the server owns", and ADR 0019's
amendment requires that directory — the context and every artifact in
it — to be destroyed at ``close-session``. So the directory belongs to
the session record rather than to a verb, and every exit from a session
goes through :meth:`SessionPaths.discard`.

**What it declares** is :func:`parse_context_yaml`. ``context.yaml`` is
the request document of ADR 0018's amendment: the format version, the
resolved pins — SDK package hash, target board — the Zephyr line the
build container has to carry, and the constraint the SDK pin was
resolved from. It is what carries the pins into a session, and it is the
one file an extension may not touch. It does **not** name a container:
choosing one of the required line, out of the images this server serves,
is this server's job (E61).

**The freeze** is :func:`freeze_context`, the body of ``lock-context``.
It hashes every content file, builds the ``files`` integrity list,
computes the context ID and writes ``manifest.yaml`` beside
``context.yaml``.

**Every value the freeze computes comes from ``mcuhome-model`` and none
of the rule is restated here** (ADR 0020 decision 4). The ID is
``mcuhome.model.context.context_id``, each file hash is
``mcuhome.model.hashes.sha256_file``, each integrity entry is a
``ContextFile`` and the manifest document is
``ContextManifest.to_dict()``. That is not tidiness: the ID's entire
purpose is that two independently written parties compute the same
value, so a second implementation of the rule in this repository would
be two chances to disagree about a number whose only job is to be
identical — and the disagreement would surface as a rejected upload or a
misattributed artifact rather than as a failing test.

What this module *does* own is the two things ``mcuhome-model``
deliberately does not carry, both consequences of that package being
dependency-free by construction: a YAML parser and a YAML emitter. They
are this repository's own ``ruamel.yaml``, declared in its
``pyproject.toml``; ``mcuhome.workbench.contextdir`` has the reference
emitter and importing it is forbidden by the same ADR that forbids
re-implementing the hash.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcuhome.model.context import (
    CONTEXT_FILE,
    MANIFEST_FILE,
    MODEL_FILE,
    ContainerResolution,
    ContextFile,
    ContextManifest,
    SdkPin,
    context_id,
    validate_zephyr_line,
)
from mcuhome.model.errors import BuildError
from mcuhome.model.hashes import sha256_file
from mcuhome.model.modelfile import read_model
from ruamel.yaml import YAML, YAMLError
from ruamel.yaml.events import AliasEvent

from mcuhome_buildserver.errors import SessionError
from mcuhome_buildserver.ingress import check_patch_layer, patch_layer_of
from mcuhome_buildserver.protocol import ProtocolError

__all__ = [
    "ContextPins",
    "SessionPaths",
    "collect_context_files",
    "content_files",
    "count_context_files",
    "derive_patch_layers",
    "freeze_context",
    "parse_context_yaml",
    "prepare_context_root",
    "recheck_locked_context",
    "recheck_patch_policy",
]

_SESSION_ID = re.compile(r"s-[A-Za-z0-9_-]{1,64}\Z")

#: The shape :mod:`mcuhome_buildserver.sessions` issues invocation ids
#: in — ``inv-`` and a per-session counter. Pinned here as well as
#: there because this is where one becomes a path segment.
_INVOCATION_ID = re.compile(r"inv-[1-9][0-9]{0,9}\Z")


class UnsafeContextRoot(Exception):
    """The configured context root is not a directory this server may own.

    Raised at startup rather than at ``send-context``: it is an operator's
    mistake about a path, and the process that would go on to write
    commissioning credentials into it should not start.
    """


def prepare_context_root(root: Path) -> Path:
    """Create the per-session root, or refuse to serve out of it.

    The reason is what the directory holds. Every per-session directory
    under it carries ``keys/`` — a device's Matter commissioning
    credentials for as long as the session lives — and the session ids
    that name them are unguessable
    (:func:`secrets.token_urlsafe`), so an attacker's way in is the
    *parent*, not the name: whoever owns the directory a session tree is
    created in can rename it away and substitute their own.

    That is not hypothetical, because of where the default lands. With
    neither ``XDG_STATE_HOME`` nor ``HOME`` set — the systemd case
    :func:`~mcuhome_buildserver.config.default_context_root` is written
    for — the fallback is ``/tmp/mcuhome-build-server/sessions``, a fixed
    name in a directory every local user can write to. A user who creates
    it before the server starts owns it, and ``mkdir(parents=True,
    exist_ok=True)`` would have reused it without a word.

    So: every level this function creates is created ``0o700``, and
    **every** level that already exists — up to ``/``, not just the
    innermost one — is checked the way ``sudo`` and OpenSSH check the
    directories they trust. Owned by this process or by root, and not
    world-writable unless it carries the sticky bit, which is exactly
    what makes ``/tmp`` itself (root-owned, ``0o1777``, sticky)
    legitimate while ``/tmp/mcuhome-build-server`` created by a stranger
    is not. Checking one level would miss the interesting case: a root
    this server owns is still a root a stranger can rename away if they
    own its parent.

    Group-writable is deliberately **not** refused. An ancestor becomes
    group-writable because somebody said so, while world-writable is
    where the default fallback lands by accident; refusing the former
    would refuse every deployment under a ``umask 002`` account and buy
    protection against a group the operator chose to trust.

    The checks follow symlinks, which is the right question to ask: what
    matters is who owns the directory the name resolves to.

    **A relative root is refused before any of that**, and it is refused
    here rather than resolved, because resolving it would answer a
    different question than the operator asked. Every path in an
    invocation's request document descends from this one, and contract
    §5.2 rule 4 is unambiguous: "a path value that is not absolute ⇒
    ``unsupported.request``" — so a relative root produces a document
    every conforming program must refuse. The same string is also a
    ``docker run --volume`` source, where docker reads a name without a
    slash as a *named volume* rather than a bind mount and would hand
    the program an empty directory instead of the context. Silently
    calling ``resolve()`` would pick whatever the server's working
    directory happened to be, which is not a location an operator chose.

    Returns *root* so a caller can use it in one expression.
    """
    if not root.is_absolute():
        raise UnsafeContextRoot(
            f"{root} is a relative path and --context-root has to be absolute. Every path "
            "in a build container's request document descends from it, and the contract "
            "requires all of them to be absolute; the same value is also a bind-mount "
            "source, where a name without a leading slash is a named volume rather than a "
            "directory. Name the directory in full."
        )
    missing: list[Path] = []
    probe = root
    while not probe.exists():
        missing.append(probe)
        if probe.parent == probe:  # pragma: no cover - "/" always exists
            break
        probe = probe.parent
    for level in [*reversed(probe.parents), probe]:
        _check_trusted(level)
    for path in reversed(missing):
        # `mode=` rather than a `chmod` afterwards, so the directory is
        # never briefly readable by anyone else; the umask can only take
        # bits away from it, never add them. And not `exist_ok`: anything
        # that appeared between the walk above and this line was put
        # there by somebody who is not us.
        path.mkdir(mode=0o700)
    return root


def _check_trusted(path: Path) -> None:
    """Refuse one pre-existing ancestor that a stranger could move."""
    stat_result = path.stat()
    ours = os.geteuid()
    if stat_result.st_uid not in (ours, 0):
        raise UnsafeContextRoot(
            f"{path} is owned by uid {stat_result.st_uid} and this server runs as "
            f"{ours}. Per-session directories under it hold a device's commissioning "
            "credentials, and whoever owns their parent can replace them; point "
            "--context-root somewhere this server owns."
        )
    if stat_result.st_mode & 0o002 and not stat_result.st_mode & 0o1000:
        raise UnsafeContextRoot(
            f"{path} is world-writable (mode {stat_result.st_mode & 0o7777:04o}) and carries "
            "no sticky bit, so anyone on this host can replace the per-session directories "
            "underneath it — and those hold a device's commissioning credentials. Tighten "
            "it, or point --context-root elsewhere."
        )


@dataclass(frozen=True)
class SessionPaths:
    """The directory tree one session owns, and how it goes away.

    The context half, and the split matters. ``context/`` is the context
    itself — the only part that outlives a verb. ``spool`` holds the
    unpacked tar of an upload in flight and is deleted as soon as it has
    been read. ``staging/`` is where an ``extend-context`` archive is
    unpacked *before* it is applied, which is what makes a refused
    extension leave the accepted context exactly as it was: no document
    settles whether an extension is atomic, and a half-applied one on a
    context whose ID is about to be computed is not something to leave
    to chance.

    The backend half arrived with the container backend, and every one
    of its four children is named by build-container contract §4 or §5:

    * ``work/`` is the session's persistent working area, "exclusive to
      this session". It is per session by construction here — one
      directory named by session id — which is how §9.1's "one session
      per ``work``" is kept without a check.
    * ``sdk/`` is the SDK package unpacked for this session (§9.1's
      verified SDK, E48). Per session rather than shared, which is what
      lets it be handed over *writable* when the ``sdk`` layer carries
      patches without an overlay and without anybody else's tree being
      at risk.
    * ``invocations/<id>/`` is the **backend-owned per-invocation
      directory** of §5.1 step 1, holding ``out/``, ``tmp/``, the
      request document, the result document, the events file and the
      cancel sentinel. It is outside the context, which is exactly what
      lets ``context`` be a kernel-enforced read-only mount, and it is
      per invocation, which removes the data race two concurrent
      ``docker exec`` invocations had over one fixed path.
    * ``downloads/`` is where ``get-artifact`` builds the archive it is
      about to stream, and nothing else lives there.

    ADR 0019 §2 spells the per-invocation area ``/out/<invocation-id>/``.
    That is superseded prose rather than a layout to mimic: ``out`` is
    one of *five* things an invocation needs a directory for, and the
    contract that came after names all five.
    """

    root: Path

    @property
    def context(self) -> Path:
        return self.root / "context"

    @property
    def spool(self) -> Path:
        return self.root / "upload.tar"

    @property
    def staging(self) -> Path:
        return self.root / "staging"

    @property
    def work(self) -> Path:
        return self.root / "work"

    @property
    def sdk(self) -> Path:
        return self.root / "sdk"

    @property
    def invocations(self) -> Path:
        return self.root / "invocations"

    @property
    def downloads(self) -> Path:
        return self.root / "downloads"

    def invocation(self, invocation_id: str) -> Path:
        """The per-invocation directory for *invocation_id*.

        The id is checked against the shape this server issues, for the
        reason :meth:`create` gives about the session id: a path element
        assembled from an identifier is exactly where "it can only ever
        be safe" stops being true after a refactor. Here it is more than
        theory — the id reaches this function straight from a client
        payload at ``get-artifact`` and ``cancel``.
        """
        if _INVOCATION_ID.fullmatch(invocation_id) is None:
            raise ValueError(f"{invocation_id!r} is not an invocation id this server issues")
        return self.invocations / invocation_id

    def prepare_backend(self) -> None:
        """Create the directories the container mounts, before it starts.

        All of them, and before the container rather than with the first
        invocation, because a bind-mount source that does not exist is
        created **by docker, owned by root** — and the whole point of
        running the program as this server's own user is that everything
        it writes comes back readable.
        """
        for directory in (self.work, self.sdk, self.invocations, self.downloads):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)

    @staticmethod
    def create(context_root: Path, session_id: str) -> SessionPaths:
        """Make the session's directory, named by session id.

        The id is checked against the shape :class:`~mcuhome_buildserver.
        sessions.SessionManager` generates even though this server is the
        only thing that ever produces one: a path element assembled from
        an identifier is exactly the place where "it can only ever be
        safe" stops being true after a refactor.
        """
        if _SESSION_ID.fullmatch(session_id) is None:  # pragma: no cover - defensive
            raise ValueError(f"{session_id!r} is not a session id this server issues")
        root = context_root / session_id
        root.mkdir(parents=True, exist_ok=True)
        root.chmod(0o700)
        return SessionPaths(root=root)

    def discard(self) -> None:
        """Delete everything the session held. Never raises.

        Called from ``close-session``, from lease expiry, and from every
        failed upload. It cannot raise, because each of those callers is
        already answering something else and a cleanup that turns a
        refusal into an internal error tells the client the wrong story.
        """
        shutil.rmtree(self.root, ignore_errors=True)

    def clear_staging(self) -> None:
        shutil.rmtree(self.staging, ignore_errors=True)


@dataclass(frozen=True)
class ContextPins:
    """``context.yaml``, parsed — the pins a session was sent.

    Held on the session because the freeze needs them: ``manifest.yaml``
    "repeats the pin blocks — ``mcuhome``, ``target`` — exactly as
    ``context.yaml`` states them" (ADR 0018's amendment), and so it does
    with ``zephyr``, so every field of them travels, hashed or not. The
    one field that does not travel is ``created``: it dates the request,
    and the manifest's own moment is the lock.

    There is no container here, and that is E61: a context states the
    Zephyr line it needs and this server answers it with an image of its
    own choosing. What it chose is a
    :class:`~mcuhome.model.context.ContainerResolution` written into the
    manifest at the freeze, not a pin read out of a client's document.
    """

    context_version: int
    sdk: SdkPin
    #: The Zephyr release line a build container must carry to serve this
    #: context. A **requirement**, not a choice — see the class docstring.
    zephyr: str
    board: str
    #: What ``context.yaml`` said, kept only to be able to say what was
    #: accepted. It never reaches ``manifest.yaml`` and never the hash.
    created: str | None

    def to_wire(self) -> dict[str, Any]:
        """The pins as ``send-context`` echoes them back.

        Shaped like ``context.yaml``'s own blocks so that a client can
        compare what it sent against what was accepted without a mapping
        table in between. The shape is normative since E60; E61 changed
        its content and not its rule — the ``container`` block moved out
        of here, because a client's pins no longer carry one, and the
        answer's own ``container`` key now carries this server's
        resolution instead.
        """
        return {
            "mcuhome": {
                "constraint": self.sdk.constraint,
                "version": self.sdk.version,
                "package": {"url": self.sdk.url, "sha256": self.sdk.sha256},
            },
            "zephyr": self.zephyr,
            "target": {"board": self.board},
        }


def _malformed(problem: str) -> ProtocolError:
    """``context.yaml`` is not the document the format describes.

    Pre-registry, like every other "this frame was not understood": the
    typed registry has ``version.context-format-unsupported`` for a
    format version outside the server's range, and that check belongs at
    ``open-session`` — "version negotiation happens at the door and never
    downstream". A document that contradicts its own session, or that is
    missing a pin, is not a version this server cannot read; it is a
    client contradicting itself, and no registered code says that.
    """
    return ProtocolError(f"The context.yaml in this context is not usable: {problem}.")


def _string(data: dict[str, Any], *keys: str) -> str:
    """One required string, addressed by its dotted path, or a refusal."""
    node: Any = data
    for index, key in enumerate(keys):
        if not isinstance(node, dict) or key not in node:
            raise _malformed(f"it has no {'.'.join(keys[: index + 1])}")
        node = node[key]
    if not isinstance(node, str) or not node.strip():
        raise _malformed(f"{'.'.join(keys)} is not a non-empty string")
    return node


def parse_context_yaml(path: Path, *, expected_version: int, max_bytes: int) -> ContextPins:
    """Read the pins out of a received ``context.yaml``.

    Hardened three ways beyond "load some YAML", all decided together
    with the ingress caps. The document is bounded (*max_bytes*, the
    operator's ``--max-context-yaml-bytes``) before it is parsed at all.
    It is **safe-loaded**, so no tag can construct a Python object. And
    it may carry neither duplicate keys nor anchors: a duplicate key
    makes the document mean two things at once, and an anchor lets a
    small file expand into a large graph — the billion-laughs shape —
    which a parser will happily build before any cap of this server sees
    it.

    The bound is a **parameter and not a constant of this module**, which
    is the same rule the other six limits follow: "the config is the
    policy", and a limit an operator cannot move is a limit they will
    work around by other means (:mod:`mcuhome_buildserver.config`). It
    used to be a constant here while the README advertised its value to
    operators who had no way to change it.

    *expected_version* is the context format the **session was admitted
    on**, carried on the session record since admission rather than
    re-read from a module constant: the refusal below tells the client
    which number the document was measured against, and that sentence is
    only true if the two are the same number by construction.

    Only ``context.yaml``'s **shape** is judged here. Whether the pins
    are true is the cross-check of build-container contract §9.1, and
    two thirds of that check cannot be made on this server yet; see
    :func:`~mcuhome_buildserver.sessions.send_context`.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise _malformed(f"it cannot be read ({exc.strerror})") from exc
    if size > max_bytes:
        raise SessionError(
            "policy.ingress-limit-exceeded",
            f"context.yaml is {size} bytes and this server reads at most "
            f"{max_bytes}. It carries a format version, three pin blocks and "
            "a timestamp; anything larger is not that document.",
            cap="context.yaml size",
            limit=max_bytes,
            measured=size,
        )
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _malformed("it is not UTF-8 text") from exc

    yaml = YAML(typ="safe", pure=True)
    try:
        for event in yaml.parse(text):
            if isinstance(event, AliasEvent) or getattr(event, "anchor", None) is not None:
                raise _malformed(
                    "it uses a YAML anchor or alias, which this server does not accept — "
                    "a pin document has nothing to share with itself and an alias graph "
                    "is how a small file becomes a large one"
                )
        data = yaml.load(text)
    except YAMLError as exc:
        problem = str(exc).splitlines()[0] if str(exc) else "unreadable syntax"
        raise _malformed(f"it is not valid YAML ({problem})") from exc
    if not isinstance(data, dict):
        raise _malformed("it does not describe a context")

    found = data.get("context")
    if found != expected_version:
        raise _malformed(
            f"it states context format {found!r} and this session was admitted on "
            f"{expected_version}. The format is negotiated at open-session and not "
            "re-negotiated here, so a context that disagrees with its own session is "
            "refused rather than accepted under one of the two numbers"
        )

    created = data.get("created")
    pins = ContextPins(
        context_version=expected_version,
        sdk=SdkPin(
            constraint=_string(data, "mcuhome", "constraint"),
            version=_string(data, "mcuhome", "version"),
            url=_string(data, "mcuhome", "package", "url"),
            sha256=_string(data, "mcuhome", "package", "sha256"),
        ),
        zephyr=_string(data, "zephyr"),
        board=_string(data, "target", "board"),
        created=created if isinstance(created, str) else None,
    )
    _check_pin_spelling(pins)
    return pins


def _check_pin_spelling(pins: ContextPins) -> None:
    """Refuse a hash rendered any way but the one legal one (§3.3.1).

    "Uppercase or mixed-case hex, a missing prefix where one is
    required, an added prefix where none is, whitespace, a ``0x`` form,
    a truncated or over-long digest: each of these is invalid input, not
    something to normalize. An implementation that encounters one MUST
    refuse the manifest, naming the offending value, and MUST NOT
    compute an ID from it."

    The check is :func:`~mcuhome.model.context.context_id` itself, run
    over an empty file list and its result thrown away. That looks
    indirect and is deliberate: ``context_id`` validates exactly these
    two values strictly before it hashes anything, and it is the only
    **public** entry point in ``mcuhome-model`` that does — the strict
    checkers behind it are private, and ``validate_manifest`` needs a
    whole manifest, which a server holding freshly parsed pins does not
    have. Re-spelling the rules here instead would be a second
    implementation of §3.3.1 in the repository that must not have one.
    The ID it returns is discarded because the ID has exactly one moment,
    and this is not it.

    The Zephyr line is checked alongside them by the same borrowing
    argument, through the one public checker ``mcuhome-model`` exposes
    for it. It is not a §3.3.1 value — it never enters the hash — but it
    is what this server matches an image against a few lines later, and a
    line no matcher could ever satisfy is better refused where it
    arrived than as "no container serves this".
    """
    try:
        context_id(
            sdk_sha256=pins.sdk.sha256,
            board=pins.board,
            files=(),
        )
        validate_zephyr_line(pins.zephyr)
    except BuildError as exc:
        raise _malformed(str(exc).rstrip(".")) from exc


# --------------------------------------------------------------------------
# The file set
# --------------------------------------------------------------------------


def collect_context_files(root: Path) -> tuple[ContextFile, ...]:
    """Every content file of the context, hashed, sorted by path.

    The integrity list of build-container contract §3.2. It excludes the
    two context documents: ``manifest.yaml`` structurally, because it is
    the document that carries the list, and ``context.yaml`` because
    ADR 0018 §6 keeps ``created`` and ``mcuhome.constraint`` out of the
    hash by name — hashing the file they live in would readmit both
    through the back door, and two byte-identical configurations created
    a second apart would get two identities.

    ``mcuhome-model`` refuses both paths in an integrity list, so a bug
    here is caught rather than hashed. Collecting them is still this
    side's duty: the model validates a list, it does not walk a
    directory.
    """
    entries = [
        ContextFile(path=path.relative_to(root).as_posix(), sha256=sha256_file(path))
        for path in content_files(root)
    ]
    entries.sort(key=lambda entry: entry.path)
    return tuple(entries)


def content_files(root: Path) -> tuple[Path, ...]:
    """The context's content files, sorted — the walk without the hashing.

    One exclusion rule, used twice, because two spellings of "which files
    are the context" is how the file count in one answer starts
    disagreeing with the integrity list in another.
    """
    return tuple(
        path
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.relative_to(root).as_posix() not in (MANIFEST_FILE, CONTEXT_FILE)
    )


def count_context_files(root: Path) -> int:
    """How many content files the context holds.

    Separate from :func:`collect_context_files` because the hashes are
    the expensive part and a count does not need them.
    ``extend-context`` answers a file count on every call and is
    repeatable by design, so hashing the whole context to produce one
    number meant a repeatable verb could be made to do a full SHA-256
    pass over a context up to the per-session disk quota — 2 GiB by
    default — as often as a client liked. The hashes have exactly one
    consumer, and it is the freeze.
    """
    return len(content_files(root))


def derive_patch_layers(root: Path) -> tuple[str, ...]:
    """The layers this context patches, read off the paths present.

    ADR 0019 §2: "After every extension the server re-derives the
    patch-layer set from the files *actually present* and re-runs policy
    — patch semantics live entirely in the paths (ADR 0018 decision 2);
    there is no declared patch list that could disagree." There is
    nothing to compare against and that is the design: the paths are the
    declaration.
    """
    layers = {
        layer
        for path in root.rglob("*")
        if path.is_file()
        for layer in (patch_layer_of(path.relative_to(root).as_posix()),)
        if layer is not None
    }
    return tuple(sorted(layers))


def recheck_patch_policy(root: Path, allowed_layers: frozenset[str]) -> tuple[str, ...]:
    """Re-run policy over the context as it now stands, and say what it patches.

    The ADR's rule stated where the ADR states it — *after* the change,
    over the files actually present. It cannot fail today, because every
    path that reached the context passed the same check on its way in
    (:func:`~mcuhome_buildserver.ingress.check_patch_layer`), and that
    ingress-time check is what makes a denial leave the context
    untouched instead of half-written. Keeping this one as well is
    cheap, and it is the check that stays correct if a future way into
    the directory forgets the other.
    """
    layers = derive_patch_layers(root)
    for layer in layers:
        check_patch_layer(layer, allowed_layers, where=f"patches/{layer}/")
    return layers


# --------------------------------------------------------------------------
# The freeze
# --------------------------------------------------------------------------


def freeze_context(
    paths: SessionPaths,
    pins: ContextPins,
    *,
    container: ContainerResolution,
    context_yaml_sha256: str,
) -> str:
    """Freeze the context: hash it, identify it, write ``manifest.yaml``.

    The data flow, and the ``mcuhome-model`` symbol behind each step:

    1. the bytes received are re-hashed per file —
       :func:`mcuhome.model.hashes.sha256_file`;
    2. each becomes an integrity entry —
       :class:`mcuhome.model.context.ContextFile`;
    3. the three hashed inputs become the ID —
       :func:`mcuhome.model.context.context_id`;
    4. the pins, *container*, the list and the ID become the document —
       :meth:`mcuhome.model.context.ContextManifest.to_dict`;
    5. this module's ``ruamel.yaml`` renders it, and the file is
       replaced atomically and fsynced.

    *container* is this server's own answer to the context's ``zephyr``
    requirement — the image ``send-context`` selected out of the ones it
    serves (E61). It is written into the manifest and stays **outside**
    the ID, which is what lets two servers with two different images of
    one Zephyr line freeze the same bytes to the same identity while each
    manifest still records, exactly, what actually built it.

    Before any of it, ``context.yaml`` is re-hashed and compared against
    the hash ``send-context`` recorded when it accepted the pins. That
    is defence in depth on top of the extension refusal rather than a
    duplicate of it: the pins are two of the three hashed inputs and
    the document that declares them is outside the integrity list by
    construction, so nothing else in the freeze would notice if it had
    changed. A disagreement is ``context.integrity-mismatch`` — a
    recomputed value disagreeing with the bytes received, which is
    exactly what that code means. It also covers ``zephyr``, which is
    hashed nowhere and would otherwise be the one accepted value a
    rewrite could move silently between the acceptance and the freeze.

    That closes the *temporal* gap around ``zephyr``; the *semantic* one
    is closed by :func:`_require_model_agrees` on the next line. See its
    docstring: the reason the ID may leave ``zephyr`` out is that the
    line is provably inside the hashed model, and nothing made that
    provable until this check existed.

    The ID is **not** compared against a client's value, and never can
    be: ``lock-context``'s request carries ``session_id`` and nothing
    else (E37). The comparison ADR 0019 requires happens on the client,
    which computes the ID from the bytes it sent and closes the session
    on a disagreement. This server never sees that value.
    """
    context = paths.context
    actual = sha256_file(context / CONTEXT_FILE)
    if actual != context_yaml_sha256:
        raise SessionError(
            "context.integrity-mismatch",
            "context.yaml no longer hashes to what this server accepted at send-context. "
            "It carries the pins the session was admitted on, and two of the three inputs "
            "of the context id come from it, so the freeze refuses rather than identifying "
            "a context by pins nobody sent.",
            paths=[CONTEXT_FILE],
            accepted=context_yaml_sha256,
            computed=actual,
        )
    _require_model_agrees(context, pins)

    files = collect_context_files(context)
    identity = context_id(
        sdk_sha256=pins.sdk.sha256,
        board=pins.board,
        files=files,
    )
    manifest = ContextManifest(
        sdk=pins.sdk,
        zephyr=pins.zephyr,
        container=container,
        board=pins.board,
        files=files,
        id=identity,
        context_version=pins.context_version,
    )
    _write_manifest(manifest, context / MANIFEST_FILE)
    return identity


def recheck_locked_context(paths: SessionPaths, pins: ContextPins, *, expected_id: str) -> str:
    """Re-measure a locked context before every working invocation.

    Three duties in one pass, and none of them is the freeze repeated.

    **The integrity list, re-measured.** Every file of the context is
    re-hashed and compared against ``manifest.yaml``'s ``files``. A file
    that is missing, one whose bytes hash to something else, and one
    present but absent from the list are one outcome and one refusal
    naming every offending path — which is the same trio contract §7.3
    defines for ``verify``, checked here on the *backend's* side of the
    boundary, where it does not depend on the container being honest.

    **The pins, cross-checked.** §9.1 makes the backend compare the
    manifest's declared values "against the header the session was
    admitted on", and ADR 0018's amendment states the duty normatively
    because ``verify_context`` cannot establish it: a self-consistently
    forged manifest verifies clean. This server wrote the manifest
    itself, so what this catches is a manifest that changed *after* it
    was written — which is exactly the gap the duty names.

    Under context format 2 the compared values are ``context``,
    ``zephyr``, ``mcuhome.package.sha256`` and ``target.board``.
    ``container.digest`` dropped out of the list and was not replaced: it
    is no longer a pin a client sent and this server verified, it is this
    server's own record of what it chose, so comparing it against the
    pins would be comparing this server to itself. ``zephyr`` took its
    place in the list and earns it — it is what the choice was *made
    against*, and unlike the other two it is hashed nowhere, so a rewrite
    of it is invisible to every other check here. ``context`` is in the
    list for that same reason; :func:`_pin_disagreements` argues it.

    **The model, cross-checked** — the same equality the freeze makes
    (:func:`_require_model_agrees`), repeated here for the same reason
    every other value in this pass is repeated: the freeze establishes
    it once and this is the pass that says it still holds. Its own
    refusal rather than an entry in ``offending``, because it names two
    documents that disagree rather than a path whose bytes moved.

    **The identity, recomputed.** Attribution always uses the id this
    server computed itself; the one recomputed here is compared against
    the one the lock answered, so an invocation is never attributed to
    an id the client was never told.

    Contexts are small — a model, a key, a few patches — so this runs
    before **every** working invocation rather than once at the lock.
    That is the product owner's decision and it is the cheap half of a
    guarantee whose expensive half (the container's own ``verify``) is
    optional for callers.

    Returns the recomputed id, so a caller never has two values to keep
    in step.
    """
    context = paths.context
    manifest_path = context / MANIFEST_FILE
    recorded = _read_manifest(manifest_path)
    _require_model_agrees(context, pins)
    offending = _pin_disagreements(recorded, pins)

    listed = {entry.path: entry.sha256 for entry in recorded.files}
    measured = {entry.path: entry.sha256 for entry in collect_context_files(context)}
    offending += sorted(
        path for path in set(listed) | set(measured) if listed.get(path) != measured.get(path)
    )
    if offending:
        raise SessionError(
            "context.integrity-mismatch",
            "The locked context no longer matches the manifest this server wrote for it. "
            "A file is missing, a file's bytes changed, a file appeared that the integrity "
            "list does not carry, or a pin was rewritten — the context id is computed over "
            "all of them, so the invocation is refused rather than attributed to an "
            "identity nobody agreed on.",
            paths=offending,
            context_id=expected_id,
        )

    identity = recorded.compute_id()
    if identity != expected_id:
        raise SessionError(
            "context.integrity-mismatch",
            "The context id recomputed from the manifest is not the id this session "
            "answered at lock-context. Attribution always uses the id this server computed "
            "itself, so an invocation whose identity moved underneath it is refused.",
            paths=[MANIFEST_FILE],
            context_id=expected_id,
            computed=identity,
        )
    return identity


def _read_manifest(path: Path) -> ContextManifest:
    """``manifest.yaml`` back as an object, or the integrity refusal.

    This server wrote the file, so a document that will not parse is not
    a client's mistake — it is a manifest that changed on disk, which is
    the same news the hash comparison carries and gets the same code.
    """
    yaml = YAML(typ="safe", pure=True)
    try:
        data = yaml.load(path.read_text(encoding="utf-8"))
        return ContextManifest.from_dict(data)
    except (OSError, YAMLError, UnicodeDecodeError, KeyError, TypeError, ValueError) as exc:
        raise SessionError(
            "context.integrity-mismatch",
            f"The manifest this server wrote at lock-context cannot be read back ({exc}). "
            "It carries the integrity list every working action is measured against, so "
            "there is nothing left to measure.",
            paths=[MANIFEST_FILE],
        ) from exc


def _pin_disagreements(recorded: ContextManifest, pins: ContextPins) -> list[str]:
    """Which of the recorded values moved since ``send-context``.

    Named as pseudo-paths (``target.board`` and friends) so that one
    ``paths`` list in the refusal can carry both kinds of disagreement.
    A client fixing either does the same thing — send the context again
    — and splitting the answer in two would only make it guess which
    half it got.

    ``context`` is here for the same reason ``zephyr`` is: it is a value
    the manifest declares and nothing else measures. It is not in the
    hash — :meth:`~mcuhome.model.context.ContextManifest.compute_id`
    takes three inputs and this is not one — and it is not in the
    integrity list, because ``manifest.yaml`` carries that list and
    cannot be in it. ``context.yaml`` gets a hard version gate on every
    read (:func:`parse_context_yaml`) and the freeze can only ever have
    written the version the session was admitted on, so a manifest
    stating another one is by construction a manifest that changed after
    it was written — which is exactly what this pass exists to catch.
    Without this entry the rewrite travelled all the way into the
    container and came back as ``unsupported.context``, telling the
    operator the *image* was wrong.
    """
    return [
        name
        for name, expected, found in (
            ("context", pins.context_version, recorded.context_version),
            ("zephyr", pins.zephyr, recorded.zephyr),
            ("mcuhome.package.sha256", pins.sdk.sha256, recorded.sdk.sha256),
            ("target.board", pins.board, recorded.board),
        )
        if expected != found
    ]


#: How the model cross-check names itself in a refusal's ``paths``. Not a
#: file that changed but two documents that disagree, so it names both.
MODEL_LINE_PATH = f"zephyr vs {MODEL_FILE}"


def _model_zephyr_line(context: Path) -> str | None:
    """The Zephyr line the context's device model states, or ``None``.

    ``None`` where there is nothing to compare against: no model file, a
    model this server's ``mcuhome-model`` cannot read (a model version it
    does not implement, a truncated file), or one stating no line. None
    of those is this check's business — a context whose model cannot be
    read does not build, and the program inside the container refuses it
    with a far better message than a build server guessing at a document
    it deliberately does not interpret.

    Interpreting is exactly what is *not* happening here: one field of
    one file is read, compared for equality and used for nothing else.
    ``mcuhome.model``'s reader is used rather than a JSON dig of this
    module's own because the field's spelling then has one owner —
    :mod:`mcuhome.model.model` — instead of a second, silent copy on this
    side that a model change could leave behind.
    """
    path = context / MODEL_FILE
    if not path.is_file():
        return None
    try:
        stated = read_model(path).toolchain.zephyr_line
    except BuildError:
        return None
    return stated if isinstance(stated, str) and stated else None


def _require_model_agrees(context: Path, pins: ContextPins) -> None:
    """``context.yaml``'s ``zephyr`` against the model's own line.

    **The one thing that makes leaving ``zephyr`` out of the ID
    legitimate.** §3.3 excludes the field as "redundancy, not identity",
    on the grounds that the line is provably inside two things the ID
    already hashes — the SDK package and the canonical device model. The
    model half is the one that can be checked here, and until it is
    checked the argument is circular: ``context.yaml`` is outside the
    integrity list by construction, so two contexts with byte-identical
    files and two different required lines freeze to **one** ID, get
    built in containers of two different Zephyr lines, and both pass
    ``verify``. The document ADR 0018 calls the identity of a build would
    then name two builds.

    Server-side because it is the only side that helps: a client-side
    check is worthless against a hand-edited ``context.yaml``, which is
    the whole scenario. Run at the freeze — the moment the identity is
    issued — and again before every working invocation, alongside the
    other values a locked manifest is re-measured against.

    A **scoped deviation** from "the build server never parses the device
    model" (E61), and deliberately the smallest one available: the file
    is one this server already hashes into the integrity list, the read
    is one field, and the field is used for one equality. §9.1's
    cross-checked-pins duty gains it as an erratum, since §3.3's
    exclusion rationale depends on the invariant holding.

    Not fixed by hashing ``zephyr`` instead: the rule is frozen with
    ``context`` format version 2, so that would be a format bump for what
    is really a missing consistency check.
    """
    stated = _model_zephyr_line(context)
    if stated is None or stated == pins.zephyr:
        return
    raise SessionError(
        "context.integrity-mismatch",
        f"This context requires Zephyr {pins.zephyr} and its device model was resolved "
        f"against {stated}. The context id does not hash the required line — it is left "
        "out because the model already carries it — so a context whose two documents "
        "disagree about it would be identified as, and built differently from, the "
        "context that agrees.",
        paths=[MODEL_LINE_PATH],
        required=pins.zephyr,
        stated=stated,
    )


def _write_manifest(manifest: ContextManifest, path: Path) -> None:
    """Render and place ``manifest.yaml`` durably.

    Durably because the session flips to ``locked`` on the strength of
    this file existing, and the lock is one-way: a manifest that was
    answered to a client but lost to a crash would leave a session whose
    context can never be re-created and never be extended. Written to a
    neighbour, fsynced, renamed, and the directory fsynced after the
    rename so the name itself survives.

    The YAML bytes are presentation and never identity — the ID was
    computed over the canonical JSON form before this function ran, and
    a reader re-parses values rather than hashing this file.
    """
    yaml = YAML()
    yaml.default_flow_style = False
    # No line wrapping. A ``sha256:`` digest is 71 characters and lands
    # past ruamel's default width, so the emitter folds it onto a second
    # line — legal YAML that every conforming parser folds back, and
    # still the wrong thing to write here. ``manifest.yaml`` is read by
    # build containers this project does not write, in languages this
    # project does not choose (contract §1.1's third-party program), and
    # build-container contract §3.3.1 has them refuse a digest rendered
    # any other way rather than repair it. A one-line value cannot be
    # read as two.
    yaml.width = 4096
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        yaml.dump(manifest.to_dict(), handle)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
