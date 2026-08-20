# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Which build environments this server is willing to run.

A build context names its build environment itself, pinned to a digest,
and that pin arrives **from the client**. Everything else about the pin
is verified — the digest binds one set of bytes, the image's labels are
checked against what it claims, ``describe`` has to answer conformingly
— but none of that answers the one question an operator actually has:
*may this server run that image at all?*

It is a separate question from every other gate here, and it is the
first one, because the gates below it all cost a container:

* ``docker run --rm <image> cat /mcuhome/describe.json`` reads the
  static self-description (§2.2.1) — and a ``cat`` argument does not
  displace an image's own ``ENTRYPOINT``;
* ``describe`` starts the program deliberately.

So by the time an image's labels are read, it has already run. A
conformance check cannot be the thing that decides whether a stranger's
image is allowed to execute, because it happens too late — and it is a
weak filter besides: a label is a string anybody can put in a
Dockerfile, which is exactly why the contract calls labels "a pre-start
hint".

**The allowlist is the boundary, and it is always on.** It holds
repositories, not tags and not digests: a repository is the thing an
operator can reason about ("images published by MCUHome"), while a tag
moves and a digest would have to be re-listed on every release. A pin
whose repository is not listed is refused before any ``docker`` command
mentions it.

**It is checked twice, against two different claims.** The reference in
the context is what the client *says*; the image found on this host is
what the digest *is*. They can disagree — an image is matched by digest
alone, so a context may name an allowed repository while its digest
belongs to some other image entirely — and a check that only read the
client's spelling would be a check on a string the client chose.

This is also what makes fetching safe to offer at all. Without the
allowlist, a server that pulls what a context pins would fetch and run
arbitrary images from arbitrary registries on an operator's machine;
with it, the reachable set is the operator's own list either way, and
pulling becomes a convenience question rather than a trust one.
"""

from __future__ import annotations

from collections.abc import Iterable

from mcuhome.model.imageref import DOCKER_HUB, parse_reference

from mcuhome.buildserver.errors import SessionError

__all__ = [
    "check_allowed",
    "digest_reference",
    "repository_of",
]


def repository_of(reference: str) -> str:
    """*reference*'s ``registry/path``, with any tag and digest removed.

    Parsed rather than split, so that the two spellings of Docker Hub
    ("``busybox``", "``docker.io/library/busybox``") compare equal and an
    operator's list means what it looks like it means. A reference this
    package cannot parse answers as itself: the caller is about to refuse
    it either way, and a refusal that quotes the operator's own string
    back is more use than one that quotes a normalization of it.
    """
    try:
        parsed = parse_reference(reference, default_registry=DOCKER_HUB)
    except Exception:  # noqa: BLE001 - a name this server will refuse regardless
        return reference
    if parsed.registry == DOCKER_HUB and "/" not in parsed.path:
        # Docker's own rule for its own registry: a one-word name lives
        # under `library/`. Applied here so that a spelling this
        # server's *resolver* treats as one repository does not become
        # two for its allowlist — an operator would otherwise have to
        # guess which of two names for one image to list.
        return f"{parsed.registry}/library/{parsed.path}"
    return parsed.repository


def check_allowed(reference: str, *, allowed: Iterable[str], what: str) -> None:
    """Refuse *reference* unless its repository is one of *allowed*.

    *what* names which of the two claims is being checked, because the
    two refusals mean different things to whoever reads them: the
    context named a repository this server does not serve, or the digest
    it pinned turned out to belong to an image from one.

    Comparison is on the whole ``registry/path`` and is exact. No
    prefixes and no wildcards: ``ghcr.io/*`` would read as "images from
    ghcr.io", which is every image anybody has ever pushed there, and an
    operator writing it would almost certainly mean their own account.
    Somebody who wants a whole account listed can list its repositories.
    """
    repository = repository_of(reference)
    listed = tuple(dict.fromkeys(allowed))
    if repository in listed:
        return
    raise SessionError(
        "policy.environment-denied",
        f"This server does not run build environments from {repository}. It builds in "
        f"the images its operator listed and in no others, and {what} names one that is "
        "not on that list.",
        environment=reference,
        repository=repository,
        allowed=sorted(listed),
    )


def digest_reference(reference: str) -> str:
    """*reference* as ``repository@digest`` — the name docker reports back.

    A pinned reference carries a tag *and* a digest, which docker
    resolves without complaint but never *reports*: what an image
    inspect lists are the names it has, and those are repo tags and repo
    digests, never a mixture. So a lookup that has to recognize its own
    answer asks by the half that appears in ``RepoDigests``.

    A reference with no digest answers as itself: the caller is asking
    about something that was never pinned, and inventing a spelling for
    it would be worse than passing the one it was given.
    """
    try:
        parsed = parse_reference(reference, default_registry=DOCKER_HUB)
    except Exception:  # noqa: BLE001 - a name the caller will fail on anyway
        return reference
    if parsed.digest is None:
        return reference
    return f"{parsed.repository}@{parsed.digest}"
