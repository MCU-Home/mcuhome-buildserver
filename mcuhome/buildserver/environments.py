# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Which build environments this server is willing to run.

A build context names its build environment by the package set it
pins, and that pin arrives **from the client**. Everything else about
the pin is verified — the digest binds one set of bytes, and the
image's labels are checked against what the context asked for — but
none of that answers the one question an operator actually has: *may
this server even talk to that image at all?*

It is a separate question from every other check here, and it is the
first one: the image's labels are read by inspecting it, with no
container started to get them, but even that inspection — and pulling
the image, where the operator allows it — reaches whatever registry the
reference names. A pin that fails the allowlist must not cost that
registry request.

**The allowlist is the boundary, and it is always on.** It holds
repositories, not tags and not digests: a repository is the thing an
operator can reason about ("images published by MCUHome"), while a tag
moves and a digest would have to be re-listed on every release. A pin
whose repository is not listed is refused before any ``docker`` command
mentions it.

**One check, because one value arrives from outside.** The image pin a
client sends with ``send-context`` is the only reference this server
does not produce itself, and that is where the check sits. What comes
after it is a construction rather than a claim: the image is searched
for *in the allowed repositories*, matched by the labels found there,
and then fetched by the digest whose labels were just read — so a
candidate is from a listed repository by the way it was found, and
there is no second spelling left for an allowlist to disagree with.

This is also what makes fetching safe to offer at all. Without the
allowlist, a server that pulls what a build pins would fetch and run
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

    *what* names the value the refusal is about, so a reader learns
    where the refused reference came from rather than only that it was
    refused. The one caller passes the image pin the build carried;
    the parameter stays a parameter because a second source of a
    reference would need its own wording and not this one reused.

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
