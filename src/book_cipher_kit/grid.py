"""Book-derived straddling checkerboard: compact numeric encoding.

The classic book cipher's weakness is payload size: three numbers per
character. A straddling checkerboard fixes that by giving the book's most
frequent characters single-digit codes and the rest two-digit codes,
roughly halving the digit stream.

This module builds the checkerboard *from the book itself* instead of a
memorized table:

* The 8 most frequent encodable characters in the book get the single
  digits 0-7 (ties broken alphabetically for determinism).
* The remaining characters fill a 10-column second tier addressed by the
  two "escape" digits 8 and 9, giving up to 20 more slots.
* A space maps to a dedicated two-digit escape pair.

Because the table derives from the book's histogram, both parties rebuild
the identical checkerboard from the identical edition -- and an attacker
with a different edition builds a different one, which shows up as decode
garbage. That is the point: the table is edition-bound.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

from .core import ENCODABLE_PUNCT, BookCipherError, normalize_line

__all__ = [
    "GridError",
    "Checkerboard",
    "build_checkerboard",
    "digits_to_text",
    "text_to_digits",
]

#: Digits that prefix the second tier rows.
ESCAPE_A = "8"
ESCAPE_B = "9"

#: Two-digit code reserved for the space character.
SPACE_CODE = ESCAPE_A + ESCAPE_B  # "89"


class GridError(BookCipherError):
    """Raised for checkerboard build or decode problems."""


class Checkerboard:
    """A straddling checkerboard derived from one book.

    Attributes:
        top: The up-to-8 characters with single-digit codes, index = code.
        rows: Two strings of up to 10 characters each for the 8x and 9x
            codes (row A first, then row B).
        char_to_code: Mapping from character to its digit string.
    """

    def __init__(self, top: str, row_a: str, row_b: str) -> None:
        self.top = top
        self.rows = (row_a, row_b)
        self.char_to_code: Dict[str, str] = {}
        self.code_to_char: Dict[str, str] = {}
        for i, ch in enumerate(top):
            self.char_to_code[ch] = str(i)
            self.code_to_char[str(i)] = ch
        for prefix, row in ((ESCAPE_A, row_a), (ESCAPE_B, row_b)):
            for i, ch in enumerate(row):
                code = prefix + str(i)
                self.char_to_code[ch] = code
                self.code_to_char[code] = ch
        self.char_to_code[" "] = SPACE_CODE
        self.code_to_char[SPACE_CODE] = " "

    def encode(self, text: str) -> str:
        """Encode text to a digit string.

        Raises:
            GridError: When a character has no slot in this checkerboard.
        """
        out: List[str] = []
        for ch in text.lower():
            code = self.char_to_code.get(ch)
            if code is None:
                raise GridError(
                    f"character {ch!r} has no checkerboard slot in this book")
            out.append(code)
        return "".join(out)

    def decode(self, digits: str) -> str:
        """Decode a digit string back to text.

        The stream is parsed greedily: an 8 or 9 always starts a two-digit
        code, anything else is a single-digit top-row code.

        Raises:
            GridError: On a truncated escape pair or an unknown code.
        """
        out: List[str] = []
        i = 0
        n = len(digits)
        while i < n:
            d = digits[i]
            if d in (ESCAPE_A, ESCAPE_B):
                if i + 1 >= n:
                    raise GridError("truncated escape pair at end of stream")
                code = digits[i:i + 2]
                i += 2
            else:
                code = d
                i += 1
            ch = self.code_to_char.get(code)
            if ch is None:
                raise GridError(f"unknown checkerboard code {code!r}")
            out.append(ch)
        return "".join(out)

    def describe(self) -> str:
        """A human-readable rendering of the table for verification."""
        lines = ["Straddling checkerboard (edition-bound):"]
        top = "  ".join(f"{i}={ch}" for i, ch in enumerate(self.top))
        lines.append(f"  top: {top}")
        for prefix, row in ((ESCAPE_A, self.rows[0]), (ESCAPE_B, self.rows[1])):
            cells = "  ".join(f"{prefix}{i}={ch}" for i, ch in enumerate(row))
            lines.append(f"  {prefix}x: {cells}")
        lines.append(f"  space: {SPACE_CODE}")
        return "\n".join(lines)


def _encodable_chars(lines: Sequence[str]) -> List[str]:
    """All distinct lowercase encodable characters present in the book."""
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789" + ENCODABLE_PUNCT)
    found: set = set()
    for line in lines:
        for ch in normalize_line(line).lower():
            if ch in allowed:
                found.add(ch)
    return sorted(found)


def build_checkerboard(lines: Sequence[str],
                       extra: Optional[Sequence[str]] = None) -> Checkerboard:
    """Build a checkerboard from a book's character frequencies.

    Args:
        lines: The book as a list of lines.
        extra: Optional extra characters to guarantee slots for (e.g. the
            characters a planned message needs). They are appended after
            the frequency-ranked ones if not already present.

    Returns:
        A Checkerboard whose slots cover the 8 most frequent characters
        plus up to 20 more.

    Raises:
        GridError: When the book provides no characters or the needed
            character set exceeds the 28 available slots.
    """
    freq: Dict[str, int] = {}
    for line in lines:
        for ch in normalize_line(line).lower():
            if ch.isalnum() or ch in ENCODABLE_PUNCT:
                freq[ch] = freq.get(ch, 0) + 1
    if not freq:
        raise GridError("book contains no encodable characters")
    ranked = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))
    chars = [ch for ch, _ in ranked]
    if extra:
        for ch in extra:
            ch = ch.lower()
            if ch != " " and ch not in chars:
                chars.append(ch)
    if len(chars) > 28:
        raise GridError(
            f"book needs {len(chars)} slots but the checkerboard holds 28; "
            "encode with positions instead")
    top = "".join(chars[:8])
    rest = chars[8:]
    row_a = "".join(rest[:10])
    row_b = "".join(rest[10:20])
    return Checkerboard(top, row_a, row_b)


def text_to_digits(text: str, lines: Sequence[str]) -> str:
    """Convenience: build a checkerboard from the book and encode text."""
    board = build_checkerboard(lines, extra=[c for c in text.lower()
                                             if c != " "])
    return board.encode(text)


def digits_to_text(digits: str, lines: Sequence[str]) -> str:
    """Convenience: rebuild the checkerboard from the book and decode."""
    return build_checkerboard(lines).decode(digits)
