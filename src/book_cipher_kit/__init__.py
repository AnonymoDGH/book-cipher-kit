"""Book Cipher Kit — the cipher that needs no key, only a shared book.

Each character of a message is encoded as a position inside a word of a book:
(line, word, character). Without the same edition of the same book, the
positions are meaningless. The classic unbreakable-ish cipher, as a CLI.

Pure standard library.
"""

from __future__ import annotations

import random
from pathlib import Path

SEPARATOR = " "  # encodes a space between words


def load_book(path: str | Path) -> list[str]:
    return Path(path).read_text(encoding="utf-8").splitlines()


def _char_index(lines: list[str]) -> dict[str, list[tuple[int, int, int]]]:
    """Map every lowercase character to every (line, word, char) position
    where it appears in the book."""
    index: dict[str, list[tuple[int, int, int]]] = {}
    for li, line in enumerate(lines):
        for wi, word in enumerate(line.split()):
            for ci, ch in enumerate(word.lower()):
                if ch.isalnum() or ch in ".,;:!?()'\"":
                    index.setdefault(ch, []).append((li, wi, ci))
    return index


def _word_lines(lines: list[str]) -> list[int]:
    return [li for li, line in enumerate(lines) if line.split()]


def encode(message: str, lines: list[str], seed: int | None = None,
           index: dict | None = None) -> list[tuple[int, int, int]]:
    """Encode a message into (line, word, char) positions."""
    idx = index or _char_index(lines)
    rng = random.Random(seed)
    candidates = _word_lines(lines)
    if not candidates:
        raise ValueError("The book has no words to work with.")

    positions: list[tuple[int, int, int]] = []
    for ch in message.lower():
        if ch == " ":
            positions.append((rng.choice(candidates), -1, -1))
            continue
        if ch not in idx:
            raise ValueError(
                f"Character {ch!r} does not appear in the book — "
                "pick another book or rephrase."
            )
        positions.append(rng.choice(idx[ch]))
    return positions


def decode(positions: list[tuple[int, int, int]], lines: list[str]) -> str:
    """Reverse (line, word, char) positions into the original message."""
    out: list[str] = []
    for li, wi, ci in positions:
        if wi == -1:  # space marker
            out.append(" ")
            continue
        words = lines[li].split()
        if not (0 <= wi < len(words)):
            raise ValueError(f"Word {wi} out of range on line {li}")
        word = words[wi]
        if not (0 <= ci < len(word)):
            raise ValueError(f"Char {ci} out of range in word {word!r}")
        out.append(word[ci].lower())  # el índice vive en minúsculas
    return "".join(out)


def positions_to_text(positions: list[tuple[int, int, int]]) -> str:
    return "\n".join(f"{li}.{wi}.{ci}" for li, wi, ci in positions) + "\n"


def text_to_positions(text: str) -> list[tuple[int, int, int]]:
    positions = []
    for line in text.strip().splitlines():
        part = line.strip()
        if not part:
            continue
        li, wi, ci = part.split(".")
        positions.append((int(li), int(wi), int(ci)))
    return positions


def coverage(lines: list[str]) -> dict[str, float]:
    """Report what fraction of the lowercase alphabet the book can encode."""
    idx = _char_index(lines)
    letters = set("abcdefghijklmnopqrstuvwxyz")
    found = letters & set(idx)
    return {
        "found": sorted(found),
        "missing": sorted(letters - found),
        "percent": round(100 * len(found) / len(letters)),
    }


__all__ = [
    "SEPARATOR",
    "load_book", "encode", "decode",
    "positions_to_text", "text_to_positions", "coverage",
]
