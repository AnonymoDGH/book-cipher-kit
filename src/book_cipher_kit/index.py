"""BookIndex -- a reusable, queryable index over one book.

Building the character index is the expensive step of a book cipher. This
module wraps it in an object you build once and reuse: fast lookups,
statistics, constrained position selection, and a serialized form you can
cache on disk so a 200k-word book does not get re-indexed on every command.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Iterable, Sequence

from .core import (
    BookCipherError,
    CharacterNotFoundError,
    SPACE_MARKER,
    _char_index,
    _word_lines,
    fingerprint,
    word_count,
)


class BookIndex:
    """An index over one book: character positions plus derived statistics.

    Parameters
    ----------
    lines:
        The book as a list of lines (already normalized).
    """

    def __init__(self, lines: Sequence[str]):
        self.lines: list[str] = list(lines)
        self._index: dict[str, list[tuple[int, int, int]]] = _char_index(self.lines)
        self._word_lines: list[int] = _word_lines(self.lines)
        self._fingerprint: str | None = None

    # -- basic accessors -------------------------------------------------

    @property
    def fingerprint(self) -> str:
        """Edition fingerprint of the indexed book (cached)."""
        if self._fingerprint is None:
            self._fingerprint = fingerprint(self.lines)
        return self._fingerprint

    @property
    def alphabet(self) -> list[str]:
        """Every encodable character, sorted."""
        return sorted(self._index)

    @property
    def word_lines(self) -> list[int]:
        """Line numbers containing at least one word."""
        return list(self._word_lines)

    def positions_for(self, ch: str) -> list[tuple[int, int, int]]:
        """Every position carrying 'ch' (case-insensitive)."""
        return list(self._index.get(ch.lower(), []))

    def count(self, ch: str) -> int:
        """How many times 'ch' can be carried."""
        return len(self._index.get(ch.lower(), []))

    def total_positions(self) -> int:
        """Total encodable character occurrences in the book."""
        return sum(len(v) for v in self._index.values())

    def words(self) -> int:
        """Total word count of the book."""
        return word_count(self.lines)

    # -- encoding --------------------------------------------------------

    def encode(
        self,
        message: str,
        seed: int | None = None,
        *,
        avoid_lines: set[int] | None = None,
        prefer_rare: bool = False,
    ) -> list[tuple[int, int, int]]:
        """Encode a message using this index.

        avoid_lines
            Optional set of line numbers to never use -- the "torn page"
            mode, for when part of the shared book is damaged or missing.
        prefer_rare
            When true, characters are drawn weighted toward their rarer
            occurrences (positions on lines that have fewer encodable
            characters), which flattens the statistical profile of the
            output at the cost of variety.
        """
        if not self._word_lines:
            raise BookCipherError("The book has no words to work with.")
        rng = random.Random(seed)
        positions: list[tuple[int, int, int]] = []
        space_candidates = self._filtered(self._word_lines, avoid_lines)
        if not space_candidates:
            raise BookCipherError("No usable lines left after filtering.")
        for ch in message.lower():
            if ch == " ":
                positions.append((rng.choice(space_candidates),) + SPACE_MARKER)
                continue
            options = self._filtered(self._index.get(ch, []), avoid_lines)
            if not options:
                raise CharacterNotFoundError(ch)
            if prefer_rare and len(options) > 1:
                weights = [1.0 / max(1, len(self.lines[p[0]].split())) for p in options]
                positions.append(_weighted_choice(rng, options, weights))
            else:
                positions.append(rng.choice(options))
        return positions

    @staticmethod
    def _filtered(
        options: list[tuple[int, int, int]] | list[int],
        avoid_lines: set[int] | None,
    ) -> list:
        if not avoid_lines:
            return list(options)
        if options and isinstance(options[0], int):
            return [li for li in options if li not in avoid_lines]
        return [p for p in options if p[0] not in avoid_lines]

    # -- statistics ------------------------------------------------------

    def histogram(self) -> dict[str, int]:
        """Character -> occurrence count, sorted most common first."""
        return {
            ch: len(v)
            for ch, v in sorted(self._index.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        }

    def rarest(self, n: int = 5) -> list[tuple[str, int]]:
        """The n rarest encodable characters -- the book's weak spots."""
        items = sorted(self._index.items(), key=lambda kv: (len(kv[1]), kv[0]))
        return [(ch, len(v)) for ch, v in items[:n]]

    def line_density(self) -> list[int]:
        """Encodable characters per line -- useful for torn-page mode."""
        density = [0] * len(self.lines)
        for positions in self._index.values():
            for li, _, _ in positions:
                density[li] += 1
        return density

    def coverage_report(self) -> dict:
        """Alphabet coverage, like core.coverage() but from the index."""
        letters = set("abcdefghijklmnopqrstuvwxyz")
        found = letters & set(self._index)
        return {
            "found": sorted(found),
            "missing": sorted(letters - found),
            "percent": round(100 * len(found) / len(letters)),
            "extras": sorted(set(self._index) - letters),
            "total_positions": self.total_positions(),
            "words": self.words(),
            "fingerprint": self.fingerprint,
        }

    # -- serialization ---------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize the index (positions only; lines stay in the book)."""
        return {
            "version": 1,
            "fingerprint": self.fingerprint,
            "positions": {ch: [list(p) for p in v] for ch, v in self._index.items()},
            "word_lines": self._word_lines,
        }

    def save(self, path: str | Path) -> None:
        """Write the serialized index to disk as JSON."""
        Path(path).write_text(json.dumps(self.to_dict()), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path, lines: Sequence[str]) -> "BookIndex":
        """Load a cached index and verify it matches the given book.

        Raises BookCipherError when the fingerprint disagrees -- using a
        stale cache against a changed book would silently corrupt messages.
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        obj = cls.__new__(cls)
        obj.lines = list(lines)
        obj._fingerprint = fingerprint(obj.lines)
        if data.get("fingerprint") != obj._fingerprint:
            raise BookCipherError(
                "Cached index fingerprint does not match the book -- rebuild it."
            )
        obj._index = {ch: [tuple(p) for p in v] for ch, v in data["positions"].items()}
        obj._word_lines = list(data["word_lines"])
        return obj


def _weighted_choice(rng: random.Random, options: list, weights: list[float]):
    """Weighted random choice without relying on random.choices stability."""
    total = sum(weights)
    x = rng.random() * total
    acc = 0.0
    for opt, w in zip(options, weights):
        acc += w
        if x <= acc:
            return opt
    return options[-1]


__all__ = ["BookIndex"]
