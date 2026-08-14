import random
import string

import pytest

from book_cipher_kit import (
    coverage, decode, encode, load_book,
    positions_to_text, text_to_positions,
)

BOOK = (
    "The quick brown fox jumps over the lazy dog again and again.\n"
    "Pack my box with five dozen liquor jugs. Six big devils from Japan\n"
    "quickly forgot how to waltz. Amazingly few discotheques provide\n"
    "jukeboxes. The five boxing wizards jump quickly.\n"
    "How vexingly quick daft zebras jump! Sphinx of black quartz,\n"
    "judge my vow. Jackdaws love my big sphinx of quartz.\n"
)


@pytest.fixture
def lines(tmp_path):
    p = tmp_path / "book.txt"
    p.write_text(BOOK, encoding="utf-8")
    return load_book(p)


def test_roundtrip(lines):
    for msg in ("meet at dawn", "the package is loose", "zephyr"):
        assert decode(encode(msg, lines, seed=42), lines) == msg


def test_roundtrip_matches_lowercase(lines):
    msg = "The Lazy Dog Jumps"
    assert decode(encode(msg, lines, seed=7), lines) == msg.lower()


def test_deterministic_with_seed(lines):
    a = encode("same message", lines, seed=1)
    b = encode("same message", lines, seed=1)
    assert a == b


def test_positions_io_roundtrip(lines):
    positions = encode("box of liquor", lines, seed=3)
    text = positions_to_text(positions)
    assert text_to_positions(text) == positions


def test_missing_char_raises(lines):
    # The book has no digits, so this must fail loudly
    with pytest.raises(ValueError):
        encode("viva 2026", lines)


def test_coverage_is_reasonable(lines):
    c = coverage(lines)
    assert c["percent"] >= 90
    assert "z" in c["found"]
