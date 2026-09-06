# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The build environment a context pins, read and frozen by this server.

Every other test of this property drives it over the socket, and none of
those can run while remote builds are unavailable — the server refuses
before a context is ever accepted. That would leave the whole of the
format-4 half unheld: the parse, the strictness borrowed from the shared
vocabulary, the identity the freeze computes and the values the wire
echoes back.

None of it needs a build. ``parse_context_yaml`` and ``freeze_context``
are ordinary functions over a directory, so this module calls them
directly. It is deliberately the *server's* functions and not the model's
— the model has its own tests, and what is worth pinning here is that
this server reaches for them rather than re-deriving what a pin may look
like.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from mcuhome.model.context import EnvironmentPin, PackagePin, SdkPin
from mcuhome.model.hashes import sha256_file
from ruamel.yaml import YAML

from mcuhome.buildserver import contextstore, protocol
from tests.python.conftest import (
    CONTEXT_YAML,
    ENVIRONMENT,
    TOOLS_SHA256,
    WORKSPACE_SHA256,
    context_yaml,
)

BOARD = "nrf7002dk/nrf5340/cpuapp"
SDK_SHA256 = "a" * 64


def parsed(tmp_path: Path, text: bytes) -> contextstore.ContextPins:
    document = tmp_path / "context.yaml"
    document.write_bytes(text)
    return contextstore.parse_context_yaml(document, expected_version=4, max_bytes=65536)


def pins(**overrides) -> contextstore.ContextPins:
    """The pins a client sent, as an object, for the freeze's own tests."""
    base = contextstore.ContextPins(
        context_version=4,
        sdk=SdkPin(constraint="", version="2.4.0", url="", sha256=SDK_SHA256),
        build_environment=ENVIRONMENT,
        board=BOARD,
        created=None,
    )
    return replace(base, **overrides)


# --------------------------------------------------------------------------
# The parse
# --------------------------------------------------------------------------


def test_the_two_package_pins_are_read_out_of_the_document(tmp_path) -> None:
    """Both entries, all three members each, in the shape the format fixes."""
    found = parsed(tmp_path, CONTEXT_YAML.encode())
    assert found.build_environment == ENVIRONMENT
    assert found.build_environment.workspace.sha256 == WORKSPACE_SHA256
    assert found.build_environment.tools.sha256 == TOOLS_SHA256


#: A well-formed tools entry, so that a case varying the *workspace*
#: varies nothing else. Every parametrized case below is a complete
#: block — an incomplete one is refused for being incomplete and would
#: prove nothing about the member it meant to test.
GOOD_TOOLS = "{name: mcuhome-build-tools, version: '2.4.0', sha256: '" + "b" * 64 + "'}"


def environment_block(workspace: str) -> str:
    return "{workspace: " + workspace + ", tools: " + GOOD_TOOLS + "}"


@pytest.mark.parametrize(
    ("what", "block"),
    [
        (
            "an uppercase hash",
            environment_block("{name: w, version: '1', sha256: '" + "AB" * 32 + "'}"),
        ),
        ("a hash of the wrong length", environment_block("{name: w, version: '1', sha256: abcd}")),
        (
            "a prefixed hash",
            environment_block("{name: w, version: '1', sha256: 'sha256:" + "a" * 64 + "'}"),
        ),
        (
            "an empty package name",
            environment_block("{name: '', version: '1', sha256: '" + "a" * 64 + "'}"),
        ),
        (
            "an uppercase package name",
            environment_block("{name: W, version: '1', sha256: '" + "a" * 64 + "'}"),
        ),
        (
            "a path-shaped package name",
            environment_block("{name: a/b, version: '1', sha256: '" + "a" * 64 + "'}"),
        ),
        (
            "a name with two architecture suffixes",
            environment_block("{name: a_b_c, version: '1', sha256: '" + "a" * 64 + "'}"),
        ),
        (
            "an empty version",
            environment_block("{name: w, version: '', sha256: '" + "a" * 64 + "'}"),
        ),
        (
            "a version with a space in it",
            environment_block("{name: w, version: '1 0', sha256: '" + "a" * 64 + "'}"),
        ),
        ("no tools entry", "{workspace: {name: w, version: '1', sha256: '" + "a" * 64 + "'}}"),
        ("no workspace entry", "{tools: " + GOOD_TOOLS + "}"),
        ("a scalar where the set belongs", "ghcr.io/mcu-home/build-container@sha256:" + "b" * 64),
        ("a list where the set belongs", "[]"),
    ],
)
def test_an_environment_the_format_does_not_describe_is_refused(tmp_path, what, block) -> None:
    """Every member of both entries is hashed into the context ID.

    So a value spelled any other way is not a pin at all and no ID may be
    computed from it — the same rule the SDK package hash has always been
    held to, applied to the six members that joined it. The strictness is
    the shared vocabulary's own, borrowed through ``context_id`` rather
    than restated: a second implementation of "what a package pin may
    look like" is exactly what this repository must not grow.

    Each case is a **complete** block varying one member, so that what is
    measured is the member and not the missing half of the set — the two
    incomplete cases at the end say so by being named for it.
    """
    del what
    with pytest.raises(protocol.ProtocolError):
        parsed(tmp_path, context_yaml(build_environment=block))


def test_a_document_with_no_build_environment_at_all_is_refused(tmp_path) -> None:
    """Absence is malformed, and the refusal says which key is missing."""
    text = CONTEXT_YAML
    head, _, tail = text.partition("build_environment:")
    _, _, rest = tail.partition("target:")
    with pytest.raises(protocol.ProtocolError) as refusal:
        parsed(tmp_path, f"{head}target:{rest}".encode())
    assert "build_environment" in str(refusal.value)


# --------------------------------------------------------------------------
# The identity
# --------------------------------------------------------------------------


def frozen(tmp_path: Path, sent: contextstore.ContextPins) -> str:
    """Freeze a one-file context and answer the ID the server computed."""
    paths = contextstore.SessionPaths(root=tmp_path)
    paths.context.mkdir(parents=True, exist_ok=True)
    (paths.context / "context.yaml").write_bytes(CONTEXT_YAML.encode())
    (paths.context / "model").mkdir(exist_ok=True)
    (paths.context / "model" / "device-model.json").write_text('{"model_version": 2}\n')
    return contextstore.freeze_context(
        paths, sent, context_yaml_sha256=sha256_file(paths.context / "context.yaml")
    )


def test_the_frozen_identity_covers_the_build_environment(tmp_path) -> None:
    """The property every docstring in the store argues for, measured.

    Two contexts with byte-identical files and one changed member of one
    package pin are two contexts. If the environment ever stopped
    reaching the ID, the same firmware could be attributed to a context
    that was compiled somewhere else — which is the one thing the pin
    exists to prevent.
    """
    identities = set()
    for environment in (
        ENVIRONMENT,
        replace(ENVIRONMENT, tools=replace(ENVIRONMENT.tools, sha256="d" * 64)),
        replace(
            ENVIRONMENT, tools=replace(ENVIRONMENT.tools, name="mcuhome-build-tools_linux-amd64")
        ),
        replace(ENVIRONMENT, tools=replace(ENVIRONMENT.tools, version="9.9.9")),
        replace(ENVIRONMENT, workspace=replace(ENVIRONMENT.workspace, sha256="e" * 64)),
    ):
        identities.add(frozen(tmp_path / str(len(identities)), pins(build_environment=environment)))
    assert len(identities) == 5


def test_the_manifest_states_the_two_pins_and_no_location_hint(tmp_path) -> None:
    """What the freeze writes is what the format says a lock carries."""
    root = tmp_path / "session"
    frozen(root, pins())
    document = YAML(typ="safe").load(
        (root / "context" / "manifest.yaml").read_text(encoding="utf-8")
    )
    assert document["build_environment"] == ENVIRONMENT.to_dict(url=False)
    assert "url" not in document["build_environment"]["workspace"]


# --------------------------------------------------------------------------
# What the client is told back
# --------------------------------------------------------------------------


def test_the_wire_echoes_the_pins_in_the_documents_own_shape() -> None:
    """A client compares what it sent against what was accepted.

    So the echo is shaped like ``context.yaml``'s own block — no mapping
    table in between, and no rendering of its own that could disagree
    with the document.
    """
    assert pins().to_wire()["build_environment"] == ENVIRONMENT.to_dict(url=False)


def test_a_rewritten_environment_hash_is_named_by_the_immutability_check() -> None:
    """Which value moved, not merely that the identity did.

    The recomputed identity catches a manifest rewritten after the lock
    either way; this is the half that turns "the id came out different"
    into the name of the field, which is what an operator acts on. A
    comparison over names and versions alone would miss a changed hash —
    the very member the identity is built on.
    """
    sent = pins()
    rewritten = replace(
        sent,
        build_environment=replace(
            ENVIRONMENT, workspace=replace(ENVIRONMENT.workspace, sha256="f" * 64)
        ),
    )
    assert "build_environment" in contextstore._pin_disagreements(sent, rewritten)
    assert contextstore._pin_disagreements(sent, sent) == []


def test_a_pin_the_format_allows_but_this_server_rejects_is_not_invented() -> None:
    """A family tools pin and a concrete one are both legal documents.

    The server does not choose between them and must not refuse either:
    which of the two a context carries is the client's statement about
    how the environment resolves per platform.
    """
    concrete = replace(
        ENVIRONMENT,
        tools=PackagePin(
            name="mcuhome-build-tools_linux-amd64", version="2.4.0", sha256=TOOLS_SHA256
        ),
    )
    for environment in (ENVIRONMENT, concrete):
        assert isinstance(environment, EnvironmentPin)
        contextstore._check_pin_spelling(pins(build_environment=environment))
