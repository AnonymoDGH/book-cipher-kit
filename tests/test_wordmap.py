"""Tests for book_cipher_kit.wordmap -- verbal position transmission."""

from __future__ import annotations

import pytest

from book_cipher_kit import book_from_text, decode, encode
from book_cipher_kit.wordmap import (
    CHECK_MARKER,
    PAUSE_WORD,
    WORDMAP,
    WORD_INDEX,
    WordMapError,
    checksum_word,
    format_for_voice,
    parse_voice,
    positions_to_words,
    words_to_positions,
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


@pytest.fixture
def positions(lines):
    return encode("meet at dawn", lines, seed=3)


class TestWordList:
    def test_64_unique_words(self):
        assert len(WORDMAP) == 64
        assert len(set(WORDMAP)) == 64

    def test_index_roundtrip(self):
        for i, w in enumerate(WORDMAP):
            assert WORD_INDEX[w] == i

    def test_all_uppercase(self):
        assert all(w.isupper() and w.isalpha() for w in WORDMAP)


class TestPositionsToWords:
    def test_space_becomes_pause(self, positions):
        words = positions_to_words(positions)
        assert PAUSE_WORD in words  # "meet at dawn" has spaces

    def test_triple_becomes_three_words(self):
        words = positions_to_words([(1, 2, 3)])
        assert words == [WORDMAP[1], WORDMAP[2], WORDMAP[3]]

    def test_out_of_range_coordinate(self):
        with pytest.raises(WordMapError):
            positions_to_words([(64, 0, 0)])

    def test_negative_coordinate(self):
        with pytest.raises(WordMapError):
            positions_to_positions = None  # noqa: F841
            positions_to_words([(5, 70, 0)])


class TestRoundtrip:
    def test_words_roundtrip(self, positions):
        words = positions_to_words(positions)
        back = words_to_positions(words)
        assert len(back) == len(positions)
        # Spaces survive; real triples survive exactly.
        for orig, got in zip(positions, back):
            if orig[1] == -1:
                assert got[1] == -1
            else:
                assert got == orig

    def test_voice_roundtrip(self, positions, lines):
        text = format_for_voice(positions)
        back = parse_voice(text)
        assert decode(back, lines) == "meet at dawn"

    def test_checksum_appended(self, positions):
        text = format_for_voice(positions)
        words = text.split()
        assert CHECK_MARKER in words
        assert words[-2] == CHECK_MARKER

    def test_grouping(self, positions):
        text = format_for_voice(positions, group_size=4)
        assert "  " in text  # double space between groups
        flat = format_for_voice(positions, group_size=1)
        assert "  " not in flat


class TestChecksum:
    def test_checksum_deterministic(self, positions):
        assert checksum_word(positions) == checksum_word(positions)

    def test_checksum_catches_error(self, positions):
        text = format_for_voice(positions)
        words = text.split()
        # Corrupt one data word (not CHECK or the checksum itself).
        idx = 0
        words[idx] = "ZULU" if words[idx] != "ZULU" else "YANKEE"
        corrupted = " ".join(words)
        with pytest.raises(WordMapError):
            parse_voice(corrupted)

    def test_skip_checksum_verification(self, positions):
        text = format_for_voice(positions)
        words = text.split()
        words[0] = "ZULU" if words[0] != "ZULU" else "YANKEE"
        # Without verification the corrupted word still parses.
        parse_voice(" ".join(words), verify_checksum=False)


class TestErrors:
    def test_unknown_word(self):
        with pytest.raises(WordMapError):
            words_to_positions(["NOTAWORD", "ALPHA", "BRAVO"])

    def test_truncated_triple(self):
        with pytest.raises(WordMapError):
            words_to_positions(["ALPHA", "BRAVO"])

    def test_empty_voice(self):
        with pytest.raises(WordMapError):
            parse_voice("   ")

    def test_check_without_checksum(self):
        with pytest.raises(WordMapError):
            parse_voice("ALPHA BRAVO CHARLIE CHECK")

    def test_bad_group_size(self, positions):
        with pytest.raises(WordMapError):
            format_for_voice(positions, group_size=0)

    def test_case_insensitive(self, positions):
        text = format_for_voice(positions).lower()
        back = parse_voice(text)
        assert len(back) == len(positions)
