"""Core primitives of the book cipher: books, positions, encode, decode.

This module is the heart of the kit. Everything else -- indexes, formats,
steganography, analysis -- builds on the small contract defined here:

* a *book* is a list of lines of text,
* a *position* is a (line, word, char) triple of integers,
* encode() turns a message into positions,
* decode() turns positions back into the message.

Positions are plain tuples so they serialize trivially and stay compatible
with every format module in the package.
"""

from __future__ import annotations

import hashlib
import random
import unicodedata
from pathlib import Path
from typing import Iterable, Sequence

SEPARATOR = " "  # encodes a space between words

#: Characters that the indexer is willing to encode. Letters and digits plus
#: the common punctuation that survives a str.split() word boundary.
ENCODABLE_PUNCT = ".,;:!?()'\"-"

#: The marker pair for an inter-word space. Any line number works; the
#: (-1, -1) word/char pair is what decode() looks for.
SPACE_MARKER = (-1, -1)


class BookCipherError(ValueError):
    """Base class for every error the kit raises.

    It subclasses ValueError so old code that catches ValueError keeps
    working, while new code can be more precise.
    """


class CharacterNotFoundError(BookCipherError):
    """A message character does not appear anywhere in the book."""

    def __init__(self, ch: str, hint: str = ""):
        self.ch = ch
        super().__init__(
            f"Character {ch!r} does not appear in the book -- "
            f"pick another book or rephrase.{(' ' + hint) if hint else ''}"
        )


class PositionOutOfRangeError(BookCipherError):
    """A position points outside the book it is decoded against."""


def normalize_line(line: str) -> str:
    """Normalize one line of a book for stable indexing.

    Unicode is folded to NFKC (so curly quotes and ligatures behave like
    their plain cousins) and trailing whitespace is dropped. The line's
    internal spacing is preserved on purpose: re-wrapping a book changes
    every position, and this kit treats whitespace as sacred.
    """
    return unicodedata.normalize("NFKC", line).rstrip()


def load_book(path: str | Path, *, normalize: bool = True) -> list[str]:
    """Load a book from disk as a list of lines.

    Parameters
    ----------
    path:
        Path to a UTF-8 text file. A BOM is tolerated.
    normalize:
        When true (default) each line passes through normalize_line().
        Turn it off only when you need byte-exact fidelity with a file you
        did not produce.
    """
    text = Path(path).read_text(encoding="utf-8-sig")
    lines = text.splitlines()
    if normalize:
        lines = [normalize_line(ln) for ln in lines]
    return lines


def book_from_text(text: str, *, normalize: bool = True) -> list[str]:
    """Build a book directly from a string (handy in tests and pipelines)."""
    lines = text.splitlines()
    if normalize:
        lines = [normalize_line(ln) for ln in lines]
    return lines


def _indexable_char(ch: str) -> bool:
    """True when a character can carry a message symbol."""
    return ch.isalnum() or ch in ENCODABLE_PUNCT


def _char_index(lines: Sequence[str]) -> dict[str, list[tuple[int, int, int]]]:
    """Map every lowercase character to every (line, word, char) position
    where it appears in the book.

    The index is the expensive part of a book cipher; build it once with
    book_cipher_kit.index.BookIndex when encoding more than one message
    against the same book.
    """
    index: dict[str, list[tuple[int, int, int]]] = {}
    for li, line in enumerate(lines):
        for wi, word in enumerate(line.split()):
            for ci, ch in enumerate(word.lower()):
                if _indexable_char(ch):
                    index.setdefault(ch, []).append((li, wi, ci))
    return index


def _word_lines(lines: Sequence[str]) -> list[int]:
    """Line numbers that contain at least one word (space-marker candidates)."""
    return [li for li, line in enumerate(lines) if line.split()]


def encode(
    message: str,
    lines: Sequence[str],
    seed: int | None = None,
    index: dict | None = None,
) -> list[tuple[int, int, int]]:
    """Encode a message into (line, word, char) positions.

    Every character is mapped to a randomly chosen occurrence of that
    character in the book. Spaces become a space-marker triple pointing at a
    random non-empty line. The same seed reproduces the same positions.

    Raises
    ------
    CharacterNotFoundError
        If some character of the message never appears in the book.
    BookCipherError
        If the book has no words at all.
    """
    idx = index if index is not None else _char_index(lines)
    rng = random.Random(seed)
    candidates = _word_lines(lines)
    if not candidates:
        raise BookCipherError("The book has no words to work with.")

    positions: list[tuple[int, int, int]] = []
    for ch in message.lower():
        if ch == " ":
            positions.append((rng.choice(candidates),) + SPACE_MARKER)
            continue
        if ch not in idx:
            raise CharacterNotFoundError(ch)
        positions.append(rng.choice(idx[ch]))
    return positions


def decode(positions: Iterable[tuple[int, int, int]], lines: Sequence[str]) -> str:
    """Reverse (line, word, char) positions into the original message.

    Raises PositionOutOfRangeError with the offending triple in the message
    when a position does not fit the book -- the usual symptom of decoding
    with the wrong edition.
    """
    out: list[str] = []
    for li, wi, ci in positions:
        if wi == -1:  # space marker
            out.append(" ")
            continue
        if not (0 <= li < len(lines)):
            raise PositionOutOfRangeError(
                f"Line {li} out of range (book has {len(lines)} lines)"
            )
        words = lines[li].split()
        if not (0 <= wi < len(words)):
            raise PositionOutOfRangeError(f"Word {wi} out of range on line {li}")
        word = words[wi]
        if not (0 <= ci < len(word)):
            raise PositionOutOfRangeError(f"Char {ci} out of range in word {word!r}")
        out.append(word[ci].lower())
    return "".join(out)


def positions_to_text(positions: Iterable[tuple[int, int, int]]) -> str:
    """Serialize positions as one 'line.word.char' triple per line."""
    return "\n".join(f"{li}.{wi}.{ci}" for li, wi, ci in positions) + "\n"


def text_to_positions(text: str) -> list[tuple[int, int, int]]:
    """Parse the text produced by positions_to_text().

    Blank lines are skipped; anything malformed raises BookCipherError with
    the offending line quoted, because a single typo in the field is the
    most common way a book cipher breaks.
    """
    positions: list[tuple[int, int, int]] = []
    for raw in text.strip().splitlines():
        part = raw.strip()
        if not part:
            continue
        fields = part.split(".")
        if len(fields) != 3:
            raise BookCipherError(f"Malformed position line: {raw!r}")
        try:
            li, wi, ci = (int(f) for f in fields)
        except ValueError as exc:
            raise BookCipherError(f"Malformed position line: {raw!r}") from exc
        positions.append((li, wi, ci))
    return positions


def validate_positions(
    positions: Iterable[tuple[int, int, int]], lines: Sequence[str]
) -> list[str]:
    """Check positions against a book without raising.

    Returns a list of human-readable problems (empty when everything
    decodes). Useful for the doctor command and for diagnosing
    wrong-edition failures.
    """
    problems: list[str] = []
    for n, (li, wi, ci) in enumerate(positions):
        if wi == -1:
            continue
        if not (0 <= li < len(lines)):
            problems.append(f"#{n}: line {li} beyond end of book ({len(lines)} lines)")
            continue
        words = lines[li].split()
        if not (0 <= wi < len(words)):
            problems.append(f"#{n}: word {wi} beyond end of line {li} ({len(words)} words)")
            continue
        if not (0 <= ci < len(words[wi])):
            problems.append(f"#{n}: char {ci} beyond end of word {words[wi]!r}")
    return problems


def coverage(lines: Sequence[str]) -> dict:
    """Report what fraction of the lowercase alphabet the book can encode.

    The result carries the found letters, the missing ones, the percentage,
    and the extra symbols (digits/punctuation) the book also offers.
    """
    idx = _char_index(lines)
    letters = set("abcdefghijklmnopqrstuvwxyz")
    found = letters & set(idx)
    extras = sorted(set(idx) - letters)
    return {
        "found": sorted(found),
        "missing": sorted(letters - found),
        "percent": round(100 * len(found) / len(letters)),
        "extras": extras,
        "total_positions": sum(len(v) for v in idx.values()),
    }


def fingerprint(lines: Sequence[str]) -> str:
    """Edition fingerprint: SHA-256 over the normalized word stream.

    Two books with the same fingerprint decode each other's positions for
    sure. Two books that look the same but differ by a re-wrap, a typo or
    a chapter heading get different fingerprints -- which is exactly the
    failure mode this kit exists to catch early.
    """
    h = hashlib.sha256()
    for line in lines:
        for word in line.split():
            h.update(word.lower().encode("utf-8"))
            h.update(b"\x00")
        h.update(b"\x01")
    return h.hexdigest()


def word_count(lines: Sequence[str]) -> int:
    """Total number of whitespace-separated words in the book."""
    return sum(len(line.split()) for line in lines)


def char_histogram(lines: Sequence[str]) -> dict[str, int]:
    """How many encodable occurrences each character has, sorted by count."""
    idx = _char_index(lines)
    return {ch: len(v) for ch, v in sorted(idx.items(), key=lambda kv: (-len(kv[1]), kv[0]))}


def find_char(lines: Sequence[str], ch: str, limit: int = 10) -> list[tuple[int, int, int]]:
    """First 'limit' positions where 'ch' occurs -- a debugging aid."""
    return _char_index(lines).get(ch.lower(), [])[:limit]


def diff_books(a: Sequence[str], b: Sequence[str]) -> dict:
    """Compare two editions of a book.

    Returns how many lines differ, the first few differing line numbers,
    and whether the two still decode each other's character positions
    (they do when every word, in order, is identical -- whitespace aside).
    """
    words_a = [w for line in a for w in line.split()]
    words_b = [w for line in b for w in line.split()]
    same_words = words_a == words_b
    first_diffs: list[int] = []
    for i in range(max(len(a), len(b))):
        la = a[i] if i < len(a) else None
        lb = b[i] if i < len(b) else None
        if la != lb:
            first_diffs.append(i)
        if len(first_diffs) >= 10:
            break
    return {
        "lines_a": len(a),
        "lines_b": len(b),
        "same_word_stream": same_words,
        "first_differing_lines": first_diffs,
        "fingerprint_a": fingerprint(a),
        "fingerprint_b": fingerprint(b),
    }


__all__ = [
    "SEPARATOR", "ENCODABLE_PUNCT", "SPACE_MARKER",
    "BookCipherError", "CharacterNotFoundError", "PositionOutOfRangeError",
    "normalize_line", "load_book", "book_from_text",
    "encode", "decode",
    "positions_to_text", "text_to_positions", "validate_positions",
    "coverage", "fingerprint", "word_count", "char_histogram",
    "find_char", "diff_books",
]
