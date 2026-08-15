"""Tests for book_cipher_kit.obfuscate -- disguised position carriers."""

from __future__ import annotations

import pytest

from book_cipher_kit import BookCipherError, book_from_text, decode, encode
from book_cipher_kit.obfuscate import (
    SCHEMES,
    from_invoice,
    from_schedule,
    from_server_log,
    from_shopping_list,
    hide,
    reveal,
    to_invoice,
    to_schedule,
    to_server_log,
    to_shopping_list,
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


# Positions with word numbers <= 5: lossless in every scheme (the
# schedule scheme's room alphabet has 6 entries).
SMALL_POSITIONS = [(0, 4, 2), (1, 3, 1), (2, 5, 0), (3, 0, 5), (0, -1, -1)]


class TestShopping:
    def test_roundtrip(self):
        text = to_shopping_list(SMALL_POSITIONS, seed=1)
        assert from_shopping_list(text) == SMALL_POSITIONS

    def test_looks_like_shopping(self):
        text = to_shopping_list(SMALL_POSITIONS, seed=1)
        assert "shopping list" in text
        assert "$" in text

    def test_deterministic(self):
        a = to_shopping_list(SMALL_POSITIONS, seed=2)
        b = to_shopping_list(SMALL_POSITIONS, seed=2)
        assert a == b

    def test_malformed_line(self):
        with pytest.raises(BookCipherError):
            from_shopping_list("- apples: many kg, $x.00\n")

    def test_empty(self):
        assert from_shopping_list("# just a header\n") == []


class TestServerLog:
    def test_roundtrip(self):
        text = to_server_log(SMALL_POSITIONS, seed=1)
        assert from_server_log(text) == SMALL_POSITIONS

    def test_large_line_numbers(self):
        # Line numbers up to 719 fit in a 12-hour clock.
        positions = [(719, 2, 3), (60, 0, 0)]
        text = to_server_log(positions, seed=1)
        assert from_server_log(text) == positions

    def test_looks_like_a_log(self):
        text = to_server_log(SMALL_POSITIONS, seed=1)
        assert "[INFO]" in text or "[DEBUG]" in text or "[WARN]" in text
        assert "status=" in text

    def test_malformed(self):
        with pytest.raises(BookCipherError):
            from_server_log("not a log line at all\n")


class TestInvoice:
    def test_roundtrip(self):
        text = to_invoice(SMALL_POSITIONS, seed=1)
        assert from_invoice(text) == SMALL_POSITIONS

    def test_large_word_numbers(self):
        # Invoice is lossless for large word numbers.
        positions = [(5, 40, 12), (100, 250, 30)]
        text = to_invoice(positions, seed=1)
        assert from_invoice(text) == positions

    def test_total_present(self):
        text = to_invoice(SMALL_POSITIONS, seed=1)
        assert "TOTAL" in text

    def test_no_sku_lines(self):
        with pytest.raises(BookCipherError):
            from_invoice("INVOICE #1\nnothing here\n")


class TestSchedule:
    def test_roundtrip(self):
        text = to_schedule(SMALL_POSITIONS, seed=1)
        assert from_schedule(text) == SMALL_POSITIONS

    def test_looks_like_schedule(self):
        text = to_schedule(SMALL_POSITIONS, seed=1)
        assert "room" in text and "min" in text

    def test_unknown_room(self):
        with pytest.raises(BookCipherError):
            from_schedule("09:00  sync       room Z  (5 min)\n")

    def test_word_numbers_wrap_modulo_rooms(self):
        # Documented behavior: word numbers are stored mod 6 (room count).
        positions = [(0, 7, 2)]  # 7 % 6 == 1
        text = to_schedule(positions, seed=1)
        assert from_schedule(text) == [(0, 1, 2)]


class TestRegistry:
    @pytest.mark.parametrize("scheme", sorted(SCHEMES))
    def test_hide_reveal_roundtrip(self, scheme):
        text = hide(SMALL_POSITIONS, scheme, seed=3)
        assert reveal(text, scheme) == SMALL_POSITIONS

    def test_unknown_scheme(self):
        with pytest.raises(BookCipherError):
            hide(SMALL_POSITIONS, "menu")
        with pytest.raises(BookCipherError):
            reveal("x", "menu")

    def test_end_to_end_with_book(self, lines):
        msg = "meet at dawn"
        positions = encode(msg, lines, seed=1)
        # Constrain to small word numbers by picking a message whose
        # encoding fits; invoice handles any word number regardless.
        text = hide(positions, "invoice", seed=1)
        assert decode(reveal(text, "invoice"), lines) == msg
