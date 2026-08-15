"""Tests for book_cipher_kit.grid -- book-derived straddling checkerboard."""

from __future__ import annotations

import pytest

from book_cipher_kit import book_from_text
from book_cipher_kit.grid import (
    SPACE_CODE,
    Checkerboard,
    GridError,
    build_checkerboard,
    digits_to_text,
    text_to_digits,
)

BOOK = (
    "The quick brown fox jumps over the lazy dog again and again.\n"
    "Pack my box with five dozen liquor jugs. Six big devils from Japan\n"
    "quickly forgot how to waltz. Amazingly few discotheques provide\n"
    "jukeboxes. The five boxing wizards jump quickly.\n"
)


@pytest.fixture
def lines():
    return book_from_text(BOOK)


class TestBuild:
    def test_top_row_is_most_frequent(self, lines):
        board = build_checkerboard(lines)
        # The top row holds the 8 most frequent characters; 'e' and 'o'
        # dominate this book, so both must be single-digit.
        assert "e" in board.top
        assert "o" in board.top
        assert len(board.top) == 8

    def test_deterministic(self, lines):
        a = build_checkerboard(lines)
        b = build_checkerboard(lines)
        assert a.top == b.top
        assert a.rows == b.rows

    def test_empty_book(self):
        with pytest.raises(GridError):
            build_checkerboard([])

    def test_extra_chars_get_slots(self, lines):
        board = build_checkerboard(lines, extra=["z", "q"])
        assert "z" in board.char_to_code
        assert "q" in board.char_to_code

    def test_too_many_chars(self):
        # 30 distinct letters+digits exceeds the 28 slots.
        text = " ".join(chr(c) for c in range(ord("a"), ord("z") + 1)) + " 01234"
        lines = book_from_text(text)
        with pytest.raises(GridError):
            build_checkerboard(lines)


class TestEncodeDecode:
    def test_roundtrip(self, lines):
        board = build_checkerboard(lines)
        msg = "meet at dawn"
        digits = board.encode(msg)
        assert digits.isdigit()
        assert board.decode(digits) == msg

    def test_space_code(self, lines):
        board = build_checkerboard(lines)
        digits = board.encode("a b")
        assert SPACE_CODE in digits

    def test_compaction(self, lines):
        board = build_checkerboard(lines)
        # 'o', 'n', 'e' are all top-row letters in this book.
        msg = "one"
        digits = board.encode(msg)
        assert len(digits) == 3  # one digit each

    def test_unknown_char(self, lines):
        board = build_checkerboard(lines)
        with pytest.raises(GridError):
            board.encode("meet@noon")

    def test_truncated_escape(self, lines):
        board = build_checkerboard(lines)
        with pytest.raises(GridError):
            board.decode("8")

    def test_unknown_code(self, lines):
        board = build_checkerboard(lines)
        # Build a code that points at an empty slot.
        empty = None
        for prefix in ("8", "9"):
            for d in "0123456789":
                if prefix + d not in board.code_to_char:
                    empty = prefix + d
                    break
            if empty:
                break
        if empty is None:
            pytest.skip("checkerboard fully populated")
        with pytest.raises(GridError):
            board.decode(empty)


class TestConvenience:
    def test_text_to_digits_roundtrip(self, lines):
        msg = "meet at dawn"
        digits = text_to_digits(msg, lines)
        assert digits_to_text(digits, lines) == msg

    def test_describe(self, lines):
        board = build_checkerboard(lines)
        text = board.describe()
        assert "top:" in text and "space:" in text


class TestEditionBinding:
    def test_different_edition_different_table(self):
        book_a = book_from_text("alpha beta gamma delta epsilon zeta eta theta\n")
        book_b = book_from_text("one two three four five six seven eight\n")
        a = build_checkerboard(book_a)
        b = build_checkerboard(book_b)
        assert a.top != b.top
