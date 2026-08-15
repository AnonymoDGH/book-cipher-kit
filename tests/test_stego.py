"""Tests for book_cipher_kit.stego -- hiding positions as prose."""

from __future__ import annotations

import random

import pytest

from book_cipher_kit import BookCipherError, book_from_text, decode, encode
from book_cipher_kit.stego import (
    MAX_SENTENCE_WORDS,
    OFFSET,
    acrostic_to_message,
    cover_text_stats,
    cover_text_to_positions,
    message_to_acrostic,
    message_to_null_cipher,
    null_cipher_to_message,
    positions_to_cover_text,
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


class TestSentenceLengthCodec:
    def test_roundtrip_simple(self, lines):
        positions = encode("meet at dawn", lines, seed=42)
        text = positions_to_cover_text(positions, seed=1)
        assert cover_text_to_positions(text) == positions

    def test_roundtrip_preserves_message(self, lines):
        msg = "the package is loose"
        positions = encode(msg, lines, seed=7)
        text = positions_to_cover_text(positions, seed=3)
        assert decode(cover_text_to_positions(text), lines) == msg

    def test_deterministic(self, lines):
        positions = encode("same text", lines, seed=1)
        a = positions_to_cover_text(positions, seed=5)
        b = positions_to_cover_text(positions, seed=5)
        assert a == b

    def test_different_seeds_differ(self, lines):
        positions = encode("same text", lines, seed=1)
        a = positions_to_cover_text(positions, seed=5)
        b = positions_to_cover_text(positions, seed=6)
        assert a != b

    def test_space_markers(self, lines):
        positions = encode("a b c", lines, seed=2)
        text = positions_to_cover_text(positions, seed=0)
        assert cover_text_to_positions(text) == positions

    def test_large_coordinates(self):
        # Coordinates far beyond any sentence length must split into runs.
        positions = [(500, 300, 200), (1234, 56, 7)]
        text = positions_to_cover_text(positions, seed=4)
        assert cover_text_to_positions(text) == positions

    def test_stress_random_positions(self):
        rng = random.Random(9)
        stress = [
            (rng.randint(0, 500), rng.randint(0, 80), rng.randint(0, 15))
            for _ in range(40)
        ] + [(5, -1, -1)]
        text = positions_to_cover_text(stress, seed=2)
        assert cover_text_to_positions(text) == stress

    def test_zero_coordinates(self):
        positions = [(0, 0, 0)]
        text = positions_to_cover_text(positions, seed=0)
        assert cover_text_to_positions(text) == positions

    def test_every_sentence_grammatical_length(self):
        positions = [(i, i % 20, i % 9) for i in range(30)]
        text = positions_to_cover_text(positions, seed=8)
        import re
        for s in re.findall(r"[^.!?]*[.!?]", text):
            s = s.strip()
            if s:
                assert 1 <= len(s[:-1].split()) <= MAX_SENTENCE_WORDS

    def test_runs_end_with_exclamation(self):
        positions = [(3, 4, 5)]
        text = positions_to_cover_text(positions, seed=0)
        # 3 coordinates -> exactly 3 exclamation-terminated runs.
        assert text.count("!") == 3

    def test_truncated_text_raises(self, lines):
        positions = encode("hello world", lines, seed=1)
        text = positions_to_cover_text(positions, seed=1)
        # Drop the final terminator.
        broken = text.rstrip()
        if broken.endswith("!"):
            broken = broken[:-1] + "."
        with pytest.raises(BookCipherError):
            cover_text_to_positions(broken)

    def test_incomplete_run_raises(self):
        with pytest.raises(BookCipherError):
            cover_text_to_positions("The courier waits. No terminator here")

    def test_offset_documented(self):
        # A coordinate of -1 (space marker) encodes as a sum of 1.
        assert OFFSET == 2
        text = positions_to_cover_text([(0, -1, -1)], seed=0)
        assert cover_text_to_positions(text) == [(0, -1, -1)]


class TestAcrostic:
    def test_roundtrip(self):
        for msg in ("meet at dawn", "the eagle has landed", "zulu"):
            text = message_to_acrostic(msg, seed=3)
            assert acrostic_to_message(text) == msg

    def test_spaces_preserved(self):
        text = message_to_acrostic("ab cd", seed=1)
        assert acrostic_to_message(text) == "ab cd"

    def test_non_letters_dropped(self):
        text = message_to_acrostic("a1b2c3", seed=1)
        assert acrostic_to_message(text) == "abc"

    def test_deterministic(self):
        a = message_to_acrostic("same", seed=9)
        b = message_to_acrostic("same", seed=9)
        assert a == b

    def test_first_letters_carry_message(self):
        text = message_to_acrostic("hide", seed=0)
        initials = "".join(ln[0] for ln in text.splitlines() if ln.strip())
        assert initials.lower() == "hide"


class TestNullCipher:
    def test_roundtrip(self):
        for msg in ("meet at dawn", "the book is red"):
            text = message_to_null_cipher(msg, n=5, seed=3)
            assert null_cipher_to_message(text, n=5) == msg

    def test_stride_respected(self):
        text = message_to_null_cipher("abc", n=3, seed=1)
        assert null_cipher_to_message(text, n=3) == "abc"

    def test_bad_stride_raises(self):
        with pytest.raises(BookCipherError):
            message_to_null_cipher("x", n=1)

    def test_deterministic(self):
        a = message_to_null_cipher("same", n=4, seed=2)
        b = message_to_null_cipher("same", n=4, seed=2)
        assert a == b

    def test_wrong_stride_garbles(self):
        text = message_to_null_cipher("secret", n=5, seed=1)
        assert null_cipher_to_message(text, n=7) != "secret"


class TestCoverStats:
    def test_stats_shape(self, lines):
        positions = encode("a longer message for statistics", lines, seed=1)
        text = positions_to_cover_text(positions, seed=1)
        s = cover_text_stats(text)
        assert s["sentences"] > 0
        assert s["avg_sentence_words"] > 0
        assert 0 <= s["exclamation_fraction"] <= 1
        assert 0 <= s["vocabulary_richness"] <= 1
        assert s["min_sentence_words"] >= 1
        assert s["max_sentence_words"] <= MAX_SENTENCE_WORDS

    def test_empty_text(self):
        s = cover_text_stats("")
        assert s["sentences"] == 0

    def test_dense_payload_high_exclamation(self, lines):
        # Every coordinate is its own run, so dense payloads are dramatic.
        positions = encode("abcd", lines, seed=1)
        text = positions_to_cover_text(positions, seed=1)
        s = cover_text_stats(text)
        assert s["exclamation_fraction"] > 0.5
