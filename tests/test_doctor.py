"""Tests for book_cipher_kit.doctor -- decode session diagnostics."""

from __future__ import annotations

import pytest

from book_cipher_kit import book_from_text, encode, positions_to_text
from book_cipher_kit.doctor import (
    CHECK_FAIL,
    CHECK_OK,
    CHECK_WARN,
    diagnose_book,
    diagnose_pair,
    diagnose_positions_text,
    format_report,
    report_is_healthy,
)

BOOK = (
    "The quick brown fox jumps over the lazy dog again and again.\n"
    "Pack my box with five dozen liquor jugs. Six big devils from Japan\n"
    "quickly forgot how to waltz. Amazingly few discotheques provide\n"
    "jukeboxes. The five boxing wizards jump quickly.\n"
)


@pytest.fixture
def book_file(tmp_path):
    p = tmp_path / "book.txt"
    p.write_text(BOOK, encoding="utf-8")
    return p


def _status(checks, name):
    for c in checks:
        if c["check"] == name:
            return c["status"]
    return None


class TestDiagnoseBook:
    def test_healthy_book(self, book_file):
        checks = diagnose_book(book_file)
        assert report_is_healthy(checks)
        assert _status(checks, "book exists") == CHECK_OK
        assert _status(checks, "book readable") == CHECK_OK
        assert _status(checks, "alphabet coverage") == CHECK_OK

    def test_missing_book(self, tmp_path):
        checks = diagnose_book(tmp_path / "nope.txt")
        assert not report_is_healthy(checks)
        assert _status(checks, "book exists") == CHECK_FAIL

    def test_empty_book(self, tmp_path):
        p = tmp_path / "empty.txt"
        p.write_text("", encoding="utf-8")
        checks = diagnose_book(p)
        assert _status(checks, "book has words") == CHECK_FAIL

    def test_small_book_warns(self, tmp_path):
        p = tmp_path / "small.txt"
        p.write_text("just a few words here", encoding="utf-8")
        checks = diagnose_book(p)
        assert _status(checks, "book has words") == CHECK_WARN

    def test_low_coverage_fails(self, tmp_path):
        p = tmp_path / "partial.txt"
        p.write_text("aaa bbb ccc ddd " * 50, encoding="utf-8")
        checks = diagnose_book(p)
        assert _status(checks, "alphabet coverage") == CHECK_FAIL

    def test_binary_file_fails(self, tmp_path):
        p = tmp_path / "binary.txt"
        p.write_bytes(b"\xff\xfe\x00\x01" * 100)
        checks = diagnose_book(p)
        assert _status(checks, "book readable") == CHECK_FAIL


class TestDiagnosePositions:
    def test_healthy_payload(self):
        lines = book_from_text(BOOK)
        text = positions_to_text(encode("hello there", lines, seed=1))
        checks = diagnose_positions_text(text)
        assert report_is_healthy(checks)
        assert _status(checks, "payload parses") == CHECK_OK

    def test_empty_payload(self):
        checks = diagnose_positions_text("")
        assert not report_is_healthy(checks)

    def test_malformed_payload(self):
        checks = diagnose_positions_text("1.2\n3.4\n")
        assert _status(checks, "payload parses") == CHECK_FAIL

    def test_negative_line_detected(self):
        checks = diagnose_positions_text("-5.0.0\n")
        assert _status(checks, "coordinate sanity") == CHECK_FAIL

    def test_format_detected(self):
        checks = diagnose_positions_text("1.2.3\n")
        assert _status(checks, "format detected") == CHECK_OK


class TestDiagnosePair:
    def test_matching_pair(self, book_file):
        lines = book_from_text(BOOK)
        text = positions_to_text(encode("decode me fully", lines, seed=2))
        checks = diagnose_pair(book_file, text)
        assert report_is_healthy(checks)
        assert _status(checks, "decode") == CHECK_OK
        assert _status(checks, "positions fit book") == CHECK_OK

    def test_wrong_edition(self, book_file):
        # Positions from a different book won't fit.
        other = book_from_text("alpha beta gamma delta\n" * 3)
        text = positions_to_text(encode("alpha beta", other, seed=1))
        checks = diagnose_pair(book_file, text)
        assert _status(checks, "positions fit book") == CHECK_FAIL

    def test_bad_book_short_circuits(self, tmp_path):
        text = "1.2.3\n"
        checks = diagnose_pair(tmp_path / "missing.txt", text)
        assert not report_is_healthy(checks)
        assert _status(checks, "decode") == CHECK_FAIL


class TestFormatReport:
    def test_renders_all_checks(self, book_file):
        checks = diagnose_book(book_file)
        text = format_report(checks)
        for c in checks:
            assert c["check"] in text

    def test_icons(self, book_file):
        checks = diagnose_book(book_file)
        text = format_report(checks)
        assert "[+]" in text

    def test_empty_report(self):
        assert format_report([]) == ""

    def test_healthy_flag(self, book_file):
        assert report_is_healthy(diagnose_book(book_file))
        assert not report_is_healthy([
            {"check": "x", "status": CHECK_FAIL, "detail": "bad"},
        ])
        # Warnings alone are still healthy.
        assert report_is_healthy([
            {"check": "x", "status": CHECK_WARN, "detail": "meh"},
        ])
