"""Tests for book_cipher_kit.analysis -- security analysis of positions."""

from __future__ import annotations

import pytest

from book_cipher_kit import book_from_text, encode
from book_cipher_kit.analysis import (
    compare_sessions,
    edition_attack,
    line_histogram,
    position_entropy,
    position_spread,
    reuse_report,
    security_report,
    structure_analysis,
)

BOOK = (
    "The quick brown fox jumps over the lazy dog again and again.\n"
    "Pack my box with five dozen liquor jugs. Six big devils from Japan\n"
    "quickly forgot how to waltz. Amazingly few discotheques provide\n"
    "jukeboxes. The five boxing wizards jump quickly.\n"
    "How vexingly quick daft zebras jump! Sphinx of black quartz,\n"
)


@pytest.fixture
def lines():
    return book_from_text(BOOK)


class TestSpread:
    def test_shape(self, lines):
        positions = encode("a message spread across the book", lines, seed=1)
        s = position_spread(positions)
        assert s["real_positions"] > 0
        assert s["lines_used"] >= 1
        assert 0 < s["concentration"] <= 1
        assert s["words_used"] >= 1

    def test_only_spaces(self):
        s = position_spread([(0, -1, -1), (1, -1, -1)])
        assert s["real_positions"] == 0

    def test_empty(self):
        s = position_spread([])
        assert s["real_positions"] == 0

    def test_concentrated_message(self):
        # All characters from one line -> concentration 1.0
        positions = [(0, i, 0) for i in range(5)]
        s = position_spread(positions)
        assert s["lines_used"] == 1
        assert s["concentration"] == 1.0
        assert s["hottest_line"] == 0


class TestReuse:
    def test_no_reuse(self, lines):
        positions = encode("unique chars", lines, seed=1)
        r = reuse_report(positions)
        assert r["total"] == len(positions)
        assert r["reused_positions"] == 0

    def test_detects_reuse(self):
        positions = [(1, 2, 3), (4, 5, 6), (1, 2, 3)]
        r = reuse_report(positions)
        assert r["reused_positions"] == 1
        assert r["details"][0]["position"] == [1, 2, 3]
        assert r["details"][0]["count"] == 2

    def test_space_markers_not_counted(self):
        positions = [(0, -1, -1), (0, -1, -1)]
        r = reuse_report(positions)
        assert r["reused_positions"] == 0

    def test_reuse_fraction(self):
        positions = [(1, 1, 1)] * 4
        r = reuse_report(positions)
        assert r["reuse_fraction"] == 0.75  # 3 of 4 are repeats


class TestLineHistogram:
    def test_sorted_by_line(self, lines):
        positions = encode("histogram check across lines", lines, seed=2)
        hist = line_histogram(positions)
        line_nums = [li for li, _ in hist]
        assert line_nums == sorted(line_nums)
        assert sum(c for _, c in hist) == sum(1 for p in positions if p[1] != -1)


class TestEntropy:
    def test_positive_for_real_positions(self, lines):
        positions = encode("entropy test message", lines, seed=1)
        e = position_entropy(positions, len(lines))
        assert e["bits"] > 0
        assert e["bits_per_char"] > 0

    def test_zero_for_empty(self):
        e = position_entropy([], 10)
        assert e["bits"] == 0.0

    def test_zero_for_no_book(self, lines):
        positions = encode("test", lines, seed=1)
        e = position_entropy(positions, 0)
        assert e["bits"] == 0.0


class TestStructure:
    def test_message_length(self, lines):
        msg = "count these words"
        positions = encode(msg, lines, seed=1)
        s = structure_analysis(positions)
        assert s["message_length"] == len(msg.replace(" ", ""))
        assert s["word_count"] == len(msg.split())

    def test_word_lengths(self):
        # 'ab cd' -> word lengths [2, 2]
        positions = [(0, 0, 0), (0, 1, 0), (0, -1, -1), (0, 2, 0), (0, 3, 0)]
        s = structure_analysis(positions)
        assert s["word_lengths"] == [2, 2]

    def test_book_bounds(self):
        positions = [(10, 5, 3)]
        s = structure_analysis(positions)
        assert s["book_bounds"]["min_lines"] == 11
        assert s["book_bounds"]["min_words_on_some_line"] == 6
        assert s["book_bounds"]["min_word_length"] == 4

    def test_space_positions_recorded(self):
        positions = [(0, 0, 0), (0, -1, -1), (0, 1, 0)]
        s = structure_analysis(positions)
        assert s["space_positions"] == [1]


class TestEditionAttack:
    def test_success_with_right_book(self, lines):
        msg = "attack this message"
        positions = encode(msg, lines, seed=1)
        result = edition_attack(positions, lines)
        assert result["success"]
        assert result["plaintext"] == msg
        assert result["fit_fraction"] == 1.0

    def test_failure_with_wrong_book(self, lines):
        positions = encode("attack this", lines, seed=1)
        wrong = book_from_text("a short unrelated text")
        result = edition_attack(positions, wrong)
        assert not result["success"]
        assert result["plaintext"] is None

    def test_partial_fit(self, lines):
        # One valid, one out-of-range position.
        good = encode("a", lines, seed=1)[0]
        positions = [good, (9999, 0, 0)]
        result = edition_attack(positions, lines)
        assert not result["success"]
        assert result["fit"] == 1


class TestCompareSessions:
    def test_no_shared(self):
        a = [(0, 0, 0), (1, 1, 1)]
        b = [(2, 2, 2), (3, 3, 3)]
        c = compare_sessions(a, b)
        assert c["shared_positions"] == 0

    def test_shared_detected(self):
        a = [(0, 0, 0), (1, 1, 1)]
        b = [(1, 1, 1), (2, 2, 2)]
        c = compare_sessions(a, b)
        assert c["shared_positions"] == 1
        assert c["shared"] == [[1, 1, 1]]

    def test_space_markers_excluded(self):
        a = [(0, -1, -1)]
        b = [(0, -1, -1)]
        c = compare_sessions(a, b)
        assert c["shared_positions"] == 0


class TestSecurityReport:
    def test_strong_verdict(self, lines):
        positions = encode("a nicely spread message here", lines, seed=3)
        report = security_report(positions, lines)
        assert report["verdict"] in ("strong", "fair")
        assert "spread" in report and "reuse" in report

    def test_reuse_triggers_warning(self):
        positions = [(1, 2, 3)] * 6
        report = security_report(positions)
        assert any("reused" in w for w in report["warnings"])

    def test_concentration_triggers_warning(self):
        positions = [(0, i, 0) for i in range(10)]
        report = security_report(positions)
        assert any("concentrated" in w for w in report["warnings"])

    def test_no_book_note(self, lines):
        positions = encode("test", lines, seed=1)
        report = security_report(positions, None)
        assert any("structure analysis" in w for w in report["warnings"])

    def test_report_keys(self, lines):
        positions = encode("keys", lines, seed=1)
        report = security_report(positions, lines)
        for key in ("spread", "reuse", "structure", "entropy", "warnings", "verdict"):
            assert key in report
