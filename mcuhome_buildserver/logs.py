# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Per-job log sidecars and the resumable follow of ADR 0006 decision 6.

A build log is twenty minutes of compiler output. Two failure modes come
free with the obvious implementation and neither is acceptable:

* a browser that reconnects replays the whole log from the beginning;
* a browser that was disconnected for thirty seconds silently loses the
  part it missed, and nothing in the page says so.

ADR 0006 decision 6 fixes both with one mechanism: **the log is a file
and a position in it.** A client states the byte offset it already has,
receives everything after it, and is switched to the live stream —
"history-then-live with byte offsets". A reconnecting browser resumes
where it was.

The subtle part is the join, and it is where a naive implementation
loses bytes: read the history, then subscribe, and everything written
between the two steps is gone. :meth:`JobLog.follow` closes the window
by doing it the other way round and without awaiting in between — it
takes the current length, registers the follower *from that length*, and
only then reads the range below it. Live output at or after the mark
reaches the follower; everything below it is in the history read. No
gap, and no line delivered twice.

Offsets are **byte** offsets, not character offsets, because the file is
the authority and a client's resume point has to survive a server
restart. The text a client sees is UTF-8 decoded with replacement, split
wherever the operating system happened to break the pipe.
"""

from __future__ import annotations

import codecs
import logging
from collections.abc import Callable
from pathlib import Path

__all__ = ["LOG_FILE", "MAX_HISTORY_BYTES", "JobLog"]

logger = logging.getLogger(__name__)

#: The sidecar's name inside a job directory.
LOG_FILE = "log.txt"

#: The most history one ``follow_job`` answers with. A client that is
#: further behind pages: the result says ``eof: false`` and carries the
#: offset to ask from next. Bounded because a single WebSocket frame
#: holding a whole Zephyr build log is a memory spike on both ends.
MAX_HISTORY_BYTES = 256 * 1024

#: Called with (offset, text) for every live chunk. Must never block and
#: never raise: it is invoked from the middle of reading a pipe.
Follower = Callable[[int, str], None]


class JobLog:
    """One job's log file, its length, and whoever is watching it live."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle = None
        self._size = path.stat().st_size if path.exists() else 0
        self._followers: dict[object, Follower] = {}
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    @property
    def size(self) -> int:
        """Bytes written so far — the offset a new follower starts at."""
        return self._size

    # -- writing -----------------------------------------------------

    def open(self) -> None:
        """Start (or resume) appending. Idempotent."""
        if self._handle is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = self.path.open("ab")
            self._size = self.path.stat().st_size

    def append(self, data: bytes) -> None:
        """Write one chunk and hand it to every live follower.

        Flushed on every chunk, not buffered: the file is what a
        ``follow_job`` reads, and a client resuming mid-build must not
        be told that the last four kilobytes do not exist yet.
        """
        if not data:
            return
        self.open()
        handle = self._handle
        if handle is None:  # pragma: no cover - open() just set it
            return
        offset = self._size
        handle.write(data)
        handle.flush()
        self._size += len(data)

        if not self._followers:
            # Still decode, so that a follower attaching later does not
            # inherit a decoder positioned mid-character.
            self._decoder.decode(data)
            return
        text = self._decoder.decode(data)
        if not text:
            return
        for follower in list(self._followers.values()):
            try:
                follower(offset, text)
            except Exception:  # pragma: no cover - a follower must not break a build
                logger.exception("a log follower raised; dropping its chunk")

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        self._followers.clear()

    # -- reading -----------------------------------------------------

    def read(self, offset: int, limit: int = MAX_HISTORY_BYTES) -> tuple[str, int, bool]:
        """History from *offset*: ``(text, next_offset, reached_the_end)``.

        Blocking file I/O — small, and the caller runs it in a thread.
        """
        offset = max(0, min(offset, self._size))
        try:
            with self.path.open("rb") as handle:
                handle.seek(offset)
                data = handle.read(limit)
        except FileNotFoundError:
            return "", offset, True
        text = data.decode("utf-8", errors="replace")
        next_offset = offset + len(data)
        return text, next_offset, next_offset >= self._size

    def follow(self, key: object, follower: Follower) -> int:
        """Register *follower* and return the offset it starts receiving at.

        **Synchronous on purpose.** The caller reads history up to the
        returned offset afterwards; if this coroutine yielded, a chunk
        written in between would be delivered to neither.
        """
        self._followers[key] = follower
        return self._size

    def unfollow(self, key: object) -> None:
        self._followers.pop(key, None)

    @property
    def follower_count(self) -> int:
        return len(self._followers)
