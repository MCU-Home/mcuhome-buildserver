# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""What a client is told while remote builds are unavailable.

This server picks the container it builds in by the image a build context
names, and a context names its build environment as **packages** now. So
there is nothing for it to start, and the honest answer is a typed
refusal at ``send-context`` — the first verb that needs to know which
environment serves the session.

The rest of the suite records the same state by *skipping*: every test
that needed a finished build is kept, running-ready, behind one shared
reason. This module is the other half of that record and the part that
must not be a skip — it pins the refusal itself, so that the day the
answer changes, something says so out loud instead of a skip count
quietly dropping by one.

What is asserted here is deliberately what a **client** can see: the
typed code it branches on, and a message a person can act on. Nothing
about how the refusal is produced.
"""

from __future__ import annotations

import pytest

from mcuhome.buildserver import sessions
from tests.python.conftest import (
    BUILDER_UNSATISFIABLE,
    auth,
    base_context,
    call,
    send_archive,
)


async def open_session(ws) -> str:
    frame = await call(
        ws, "open-session", {"protocol_version": sessions.SESSION_PROTOCOL_VERSION}, frame_id="o"
    )
    return frame["payload"]["session"]["id"]


async def refused(client) -> dict:
    """Send a context and return the refusal ``send-context`` answers with."""
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        return await send_archive(
            ws, "send-context", session_id, base_context(), allow_refusal=True
        )


async def test_send_context_refuses_with_the_typed_code(client) -> None:
    """The code is what a client branches on, so it is what is pinned.

    ``version.builder-unsatisfiable`` and not a new code of its own: from
    the client's side this is the same thing the code has always meant —
    this server will not be building that context, and waiting does not
    change it.
    """
    frame = await refused(client)
    assert frame["type"] == "error", frame
    assert frame["error"]["code"] == BUILDER_UNSATISFIABLE


async def test_the_refusal_says_what_is_wrong_and_what_to_do_instead(client) -> None:
    """A person reads this message, so it has to carry both halves.

    The state ("remote builds are unavailable, this server does not run
    package-built build environments") and the way forward ("build
    locally"). A refusal that stated only the first would leave somebody
    with a broken setup and nothing to try.
    """
    message = (await refused(client))["error"]["message"]
    assert "Remote builds are unavailable" in message
    assert "package-built build environments" in message
    assert "mcuhome device build" in message


async def test_the_refusal_names_the_environment_the_context_asked_for(client) -> None:
    """The two packages, by name, so the message is about *this* context."""
    message = (await refused(client))["error"]["message"]
    assert "mcuhome-build-workspace" in message
    assert "mcuhome-build-tools" in message


@pytest.mark.parametrize("verb", ["lock-context", "verify", "build"])
async def test_the_verbs_behind_it_are_unreachable_rather_than_broken(client, verb: str) -> None:
    """Everything downstream refuses too, and refuses in the state machine's words.

    The context never reached the session, so these verbs are not being
    turned off here — they are simply out of order, which is what the
    session's own state machine already says. This test exists so that a
    later change cannot make one of them start doing half a build against
    an environment nobody selected.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, base_context(), allow_refusal=True)
        frame = await call(ws, verb, {"session_id": session_id}, frame_id="v")
    assert frame["type"] == "error", frame
    assert frame["error"]["code"].startswith(("context.", "session.", "state.")), frame


async def test_the_session_survives_the_refusal(client) -> None:
    """A refused context is not a broken connection.

    The client may close the session, ask for capabilities, or send a
    different context; the server has refused one document, not given up.
    """
    async with client.ws_connect("/ws", headers=auth()) as ws:
        session_id = await open_session(ws)
        await send_archive(ws, "send-context", session_id, base_context(), allow_refusal=True)
        closed = await call(ws, "close-session", {"session_id": session_id}, frame_id="c")
    assert closed["type"] == "result", closed
