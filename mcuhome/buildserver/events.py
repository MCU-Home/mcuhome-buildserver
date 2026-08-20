# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The invocation's event stream: NDJSON on disk, read from the backend side.

Build-container contract §8. The program appends one JSON object per
line to the file the request document named — UTF-8, flushed after every
line, append-only, never truncated — and every object carries an
``event`` name and a monotonic ``seq`` starting at 1.

**Why a named file rather than NDJSON on stdout**, which is what
contract v1 said as first drafted: file descriptor 1 belongs to west,
cmake, ninja, gn and zap, so a program whose events share it corrupts
its own stream and never notices locally. A named file removes the
failure mode structurally, survives an out-of-memory kill readably, and
gives a reconnecting client the resume-from-offset ADR 0019 §2 requires
anyway.

**The file is the replay buffer, and there is no other one** (E46). It
stays on disk for the life of the session, so ``attach-session``
answers a client's "I last saw seq N" by reading it from N — no
in-memory ring, nothing to size, and nothing that a reconnect can find
already evicted.

Two backend duties this module carries, both from §8:

* **Lines longer than 8192 bytes and non-objects are discarded and
  counted, never treated as an abort.** A program that writes rubbish
  into its own event stream has not failed its build, and a backend
  that stopped on one would turn a cosmetic defect into a lost
  invocation.
* **Unknown names are relayed opaquely.** A backend "passes an event
  whose name it does not know through to its client verbatim, with its
  fields intact, and never drops it, never rewrites it and never treats
  it as an error" — which is what lets a third-party program report its
  own phases under ``x-`` names through a server that has never heard
  of them.

And one thing this module deliberately does not do: infer. "A backend
MUST NOT infer anything from a name it did not receive" — an absent
``build.memory.region`` may mean the program emits no events at all, or
that an incremental build relinked nothing. The result document is
where the question of what was produced is answered.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "MAX_LINE_BYTES",
    "REGISTRY",
    "EventReader",
    "event_name",
    "replay",
]

#: §8, exactly: "Lines longer than 8192 bytes and non-objects are
#: discarded and counted by the backend, never treated as an abort."
MAX_LINE_BYTES = 8192

#: Event names are dotted, ``[a-z][a-z0-9.-]*``, with ``x-`` for third
#: parties. The ``x-`` prefix starts with a letter and carries a hyphen,
#: so one expression covers both.
_NAME = re.compile(r"[a-z][a-z0-9.-]*\Z")

#: The names contract v1 seeds the append-only registry with, together
#: with the fields each carries beyond ``event`` and ``seq``. This
#: server relays every event whatever its name, so the table is
#: documentation and a test vector rather than a filter — but it is the
#: list a reader of this module needs to know what a stream looks like.
REGISTRY: dict[str, tuple[str, ...]] = {
    "invocation.started": ("action",),
    "context.checked": ("context",),
    "patch.layer.applied": ("layer", "count"),
    "generate.written": ("files",),
    "build.image.started": ("image", "current", "total"),
    "build.memory.region": ("image", "region", "used", "total", "percent"),
    "artifact.collected": ("role", "path", "size"),
    "invocation.finished": ("status",),
}


def event_name(line: dict[str, Any]) -> str | None:
    """The relayable name of one parsed event object, or ``None``.

    ``None`` is "discard and count": an object with no ``event``, with a
    non-string one, or with one outside the frozen grammar is not
    something a backend can relay under a name, and §8 makes the answer
    to unrelayable input a counter rather than an abort.
    """
    found = line.get("event")
    if not isinstance(found, str) or _NAME.fullmatch(found) is None:
        return None
    return found


@dataclass
class EventReader:
    """One invocation's event file, read forward as the program appends.

    The reader holds a byte offset and a partial-line buffer, which is
    what makes it correct against a file being appended to while it is
    read: a poll that lands mid-line keeps the fragment and finishes it
    on the next one. The file is never truncated by the program (§8), so
    an offset is a stable address into it.
    """

    path: Path
    #: Where the next read starts. Public because ``attach-session``'s
    #: replay and the live relay read the same file and must not fight
    #: over one cursor — the replay makes its own reader.
    offset: int = 0
    #: How many lines were discarded for being too long or not objects.
    #: Counted rather than reported per line, because §8 makes the count
    #: the whole of the backend's duty about them.
    dropped: int = 0
    _partial: bytes = field(default=b"", repr=False)
    #: True once a line was discarded for exceeding :data:`MAX_LINE_BYTES`
    #: and the rest of it has not arrived yet.
    _skipping: bool = field(default=False, repr=False)

    def read(self) -> tuple[dict[str, Any], ...]:
        """Every complete, usable event object appended since the last call.

        Never raises: the file may not exist yet (a program that emits
        no events never creates it — the backend does, but a
        conformance test may not), may be being written to, and may be
        gone because the session was closed underneath. All three are
        "no new events", which is the same thing a poll that found
        nothing new says.
        """
        try:
            with self.path.open("rb") as handle:
                handle.seek(self.offset)
                chunk = handle.read()
        except OSError:
            return ()
        if not chunk:
            return ()
        self.offset += len(chunk)
        return tuple(self._consume(chunk))

    def _consume(self, chunk: bytes) -> list[dict[str, Any]]:
        buffer = self._partial + chunk
        self._partial = b""
        found: list[dict[str, Any]] = []
        *complete, tail = buffer.split(b"\n")
        for raw in complete:
            if self._skipping:
                # The tail of a line already discarded for its length.
                # It was counted when it was refused; the remainder is
                # not a second event.
                self._skipping = False
                continue
            parsed = self._parse(raw)
            if parsed is None:
                self.dropped += 1
            else:
                found.append(parsed)
        if len(tail) > MAX_LINE_BYTES:
            # Refused *before* the line is complete, which is the whole
            # point of the cap: a program that writes an unterminated
            # megabyte must not be able to make this server hold it.
            self.dropped += 1
            self._skipping = True
            self._partial = b""
        else:
            self._partial = tail
        return found

    def _parse(self, raw: bytes) -> dict[str, Any] | None:
        if len(raw) > MAX_LINE_BYTES:
            return None
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(data, dict) or event_name(data) is None:
            return None
        return data


def replay(path: Path, *, from_seq: int) -> tuple[dict[str, Any], ...]:
    """Every event of one invocation from *from_seq* onwards.

    The resume ADR 0019 §2 requires, served out of the file the program
    wrote rather than out of memory (E46). ``seq`` is only required to
    be **monotonic**, not gapless — a dropped event leaves a gap, and
    §8 says the gap is harmless — so the filter is ``>=`` and never
    "the Nth line".

    An event whose ``seq`` is not a whole number is relayed rather than
    dropped: the name is what a consumer matches on, and refusing to
    replay an event because its ordering field is unreadable would lose
    information over a field nobody has to use.
    """
    reader = EventReader(path=path)
    return tuple(line for line in reader.read() if _at_or_after(line, from_seq))


def _at_or_after(line: dict[str, Any], from_seq: int) -> bool:
    seq = line.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int):
        return True
    return seq >= from_seq
