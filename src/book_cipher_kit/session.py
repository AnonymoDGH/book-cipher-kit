"""session -- multi-message sessions over one shared book.

Real correspondence is not one message: it is a conversation. This module
adds the bookkeeping a conversation needs:

* a session file that stores many messages in order, each with an id,
  a timestamp, and a checksum of its positions,
* one-book-one-message discipline: every message consumes a page range,
  and the session refuses to reuse a range (the book-cipher equivalent of
  reusing a one-time pad),
* session export/import in a single JSON document.

The on-disk format is versioned JSON so future releases can migrate.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Sequence

from .core import BookCipherError, decode, encode
from .formats import _pack

Position = tuple[int, int, int]

SESSION_FORMAT = "bookcipher-session/1"


class SessionError(BookCipherError):
    """Raised for session-level problems (id collisions, range reuse)."""


def _checksum(positions: Sequence[Position]) -> str:
    """Short checksum over the packed positions, for tamper spotting."""
    return hashlib.sha256(_pack(list(positions))).hexdigest()[:16]


class Session:
    """An ordered set of messages encoded against one book.

    Parameters
    ----------
    book_fingerprint:
        Fingerprint of the shared book. Stored so an imported session can
        verify it is being read against the right edition.
    """

    def __init__(self, book_fingerprint: str, *, name: str = "session"):
        self.book_fingerprint = book_fingerprint
        self.name = name
        self.messages: list[dict] = []
        self._used_ranges: list[tuple[int, int]] = []

    # -- message lifecycle ------------------------------------------------

    def add_message(
        self,
        text: str,
        lines: Sequence[str],
        *,
        seed: int | None = None,
        message_id: str | None = None,
        page_start: int = 0,
        page_end: int | None = None,
    ) -> dict:
        """Encode and append one message.

        page_start / page_end
            The line range this message may draw from. Ranges must not
            overlap any previously used range; reuse is refused because
            two messages drawn from the same lines invite depth attacks.
        """
        end = page_end if page_end is not None else len(lines)
        if page_start < 0 or end > len(lines) or page_start >= end:
            raise SessionError(
                f"Page range [{page_start}, {end}) is outside the book"
            )
        for used_start, used_end in self._used_ranges:
            if page_start < used_end and used_start < end:
                raise SessionError(
                    f"Page range [{page_start}, {end}) overlaps an already "
                    f"used range [{used_start}, {used_end}) -- one book, "
                    "one message per range."
                )

        message_id = message_id or f"msg-{len(self.messages) + 1:03d}"
        if any(m["id"] == message_id for m in self.messages):
            raise SessionError(f"Duplicate message id {message_id!r}")

        avoid = set(range(0, page_start)) | set(range(end, len(lines)))
        from .index import BookIndex
        index = BookIndex(list(lines))
        positions = index.encode(text, seed=seed, avoid_lines=avoid or None)

        record = {
            "id": message_id,
            "ts": time.time(),
            "chars": len(text),
            "page_range": [page_start, end],
            "checksum": _checksum(positions),
            "positions": [list(p) for p in positions],
        }
        self.messages.append(record)
        self._used_ranges.append((page_start, end))
        return record

    def get_message(self, message_id: str) -> dict:
        """Fetch one message record by id."""
        for m in self.messages:
            if m["id"] == message_id:
                return m
        raise SessionError(f"No message with id {message_id!r}")

    def decode_message(self, message_id: str, lines: Sequence[str]) -> str:
        """Decode one message, verifying its checksum first."""
        record = self.get_message(message_id)
        positions = [tuple(p) for p in record["positions"]]
        if _checksum(positions) != record["checksum"]:
            raise SessionError(
                f"Checksum mismatch on {message_id!r} -- the session file "
                "was tampered with or corrupted."
            )
        return decode(positions, lines)

    def verify_all(self, lines: Sequence[str]) -> list[str]:
        """Verify every message checksum; return a list of problems."""
        problems: list[str] = []
        for m in self.messages:
            positions = [tuple(p) for p in m["positions"]]
            if _checksum(positions) != m["checksum"]:
                problems.append(f"{m['id']}: checksum mismatch")
        return problems

    def summary(self) -> dict:
        """High-level session statistics."""
        return {
            "name": self.name,
            "book_fingerprint": self.book_fingerprint,
            "messages": len(self.messages),
            "total_chars": sum(m["chars"] for m in self.messages),
            "ids": [m["id"] for m in self.messages],
        }

    # -- persistence ------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "format": SESSION_FORMAT,
            "name": self.name,
            "book_fingerprint": self.book_fingerprint,
            "messages": self.messages,
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2), encoding="utf-8"
        )

    @classmethod
    def load(cls, path: str | Path) -> "Session":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("format") != SESSION_FORMAT:
            raise SessionError("Not a bookcipher-session/1 file")
        obj = cls(data["book_fingerprint"], name=data.get("name", "session"))
        obj.messages = data["messages"]
        obj._used_ranges = [tuple(m["page_range"]) for m in obj.messages]
        return obj


__all__ = ["SESSION_FORMAT", "SessionError", "Session"]
