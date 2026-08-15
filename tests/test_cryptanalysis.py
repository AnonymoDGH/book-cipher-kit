"""Tests for book_cipher_kit.cryptanalysis -- attack yardsticks."""

from __future__ import annotations

import pytest

from book_cipher_kit import book_from_text, encode
from book_cipher_kit.cryptanalysis import (
    attack_report,
    chi_squared_english,
    english_score,
    entropy_rate,
    frequency_profile,
    hill_climb_words,
    index_of_coincidence,
    kasiski_runs,
    position_leakage,
)

BOOK = (
    "The quick brown fox jumps over the lazy dog again and again.\n"
    "Pack my box with five dozen liquor jugs. Six big devils from Japan\n"
    "quickly forgot how to waltz. Amazingly few discotheques provide\n"
    "jukeboxes. The five boxing wizards jump quickly.\n"
    "How vexingly quick daft zebras jump! Sphinx of black quartz,\n"
)

ENGLISH = (
    "the art of war is of vital importance to the state it is a matter of "
    "life and death a road either to safety or to ruin hence it is a subject "
    "of inquiry which can on no account be neglected"
)


@pytest.fixture
def lines():
    return book_from_text(BOOK)


class TestFrequency:
    def test_profile_sums_to_100(self):
        profile = frequency_profile(ENGLISH)
        assert abs(sum(profile.values()) - 100) < 0.5

    def test_profile_empty(self):
        assert frequency_profile("123 !!!") == {}

    def test_e_is_common(self):
        profile = frequency_profile(ENGLISH)
        assert profile["e"] > profile["z"]

    def test_chi_squared_english_vs_random(self):
        import random
        rng = random.Random(1)
        random_text = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(400))
        english_chi = chi_squared_english(ENGLISH * 3)
        random_chi = chi_squared_english(random_text)
        assert english_chi < random_chi

    def test_chi_squared_empty(self):
        assert chi_squared_english("123") == float("inf")


class TestIoC:
    def test_english_ioc_high(self):
        assert index_of_coincidence(ENGLISH * 2) > 0.055

    def test_random_ioc_low(self):
        import random
        rng = random.Random(2)
        random_text = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(500))
        assert index_of_coincidence(random_text) < 0.05

    def test_short_text(self):
        assert index_of_coincidence("a") == 0.0


class TestEntropy:
    def test_uniform_high(self):
        # 4 equally likely symbols -> 2 bits.
        assert entropy_rate(["a", "b", "c", "d"] * 100) == 2.0

    def test_constant_zero(self):
        assert entropy_rate(["a"] * 50) == 0.0

    def test_empty(self):
        assert entropy_rate([]) == 0.0


class TestEnglishScore:
    def test_english_scores_higher_than_noise(self):
        import random
        rng = random.Random(3)
        noise = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(200))
        assert english_score(ENGLISH) > english_score(noise)

    def test_short_returns_zero(self):
        assert english_score("ab") == 0.0


class TestKasiski:
    def test_finds_repeats(self):
        runs = kasiski_runs("abcabcabc")
        assert runs and runs[0]["gram"] == "abc"
        assert runs[0]["count"] == 3

    def test_no_repeats(self):
        assert kasiski_runs("abcdef", min_count=2) == []

    def test_short_text(self):
        assert kasiski_runs("ab") == []


class TestPositionLeakage:
    def test_shape(self, lines):
        positions = encode("measure the leakage here", lines, seed=1)
        leak = position_leakage(positions)
        assert leak["positions"] > 0
        assert leak["line_entropy"] >= 0
        assert 0 <= leak["char_index_ioc"] <= 1

    def test_empty(self):
        assert position_leakage([])["positions"] == 0


class TestHillClimbWords:
    def test_word_structure(self, lines):
        msg = "one two three"
        positions = encode(msg, lines, seed=1)
        result = hill_climb_words(positions)
        assert result["word_count"] == 3
        assert result["word_lengths"] == [3, 3, 5]
        assert result["signature"] == "3-3-5"
        assert result["total_chars"] == 11

    def test_single_word(self, lines):
        positions = encode("solo", lines, seed=1)
        result = hill_climb_words(positions)
        assert result["word_count"] == 1


class TestAttackReport:
    def test_without_book(self, lines):
        positions = encode("report without book", lines, seed=1)
        report = attack_report(positions)
        assert "position_leakage" in report
        assert "word_structure" in report
        assert "plaintext" not in report

    def test_with_book(self, lines):
        msg = "report with the book"
        positions = encode(msg, lines, seed=1)
        report = attack_report(positions, lines)
        assert report["plaintext"]["text"] == msg
        assert report["plaintext"]["iocs"] > 0
        assert report["plaintext"]["english_score"] >= 0
