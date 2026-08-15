"""Tests for book_cipher_kit.core -- the encode/decode contract."""

from __future__ import annotations

import pytest

from book_cipher_kit import (
    BookCipherError,
    CharacterNotFoundError,
    PositionOutOfRangeError,
    book_from_text,
    char_histogram,
    coverage,
    decode,
    diff_books,
    encode,
    find_char,
    fingerprint,
    load_book,
    normalize_line,
    positions_to_text,
    text_to_positions,
    validate_positions,
    word_count,
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
def lines():
    return book_from_text(BOOK)


# ---------------------------------------------------------------------------
# roundtrips
# ---------------------------------------------------------------------------

class TestRoundtrip:
    def test_simple_messages(self, lines):
        for msg in ("meet at dawn", "the package is loose", "zephyr"):
            assert decode(encode(msg, lines, seed=42), lines) == msg

    def test_case_folds_to_lower(self, lines):
        msg = "The Lazy Dog Jumps"
        assert decode(encode(msg, lines, seed=7), lines) == msg.lower()

    def test_punctuation_roundtrip(self, lines):
        msg = "wait. come, now!"
        assert decode(encode(msg, lines, seed=11), lines) == msg

    def test_empty_message(self, lines):
        assert encode("", lines) == []
        assert decode([], lines) == ""

    def test_single_char(self, lines):
        for ch in "abcdefghijklmnopqrstuvwxyz":
            assert decode(encode(ch, lines, seed=1), lines) == ch

    def test_long_message(self, lines):
        msg = ("the quick brown fox " * 20).strip()
        assert decode(encode(msg, lines, seed=5), lines) == msg

    def test_many_seeds(self, lines):
        msg = "secret cargo"
        for seed in range(25):
            assert decode(encode(msg, lines, seed=seed), lines) == msg


# ---------------------------------------------------------------------------
# determinism and variety
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_same_seed_same_positions(self, lines):
        a = encode("same message", lines, seed=1)
        b = encode("same message", lines, seed=1)
        assert a == b

    def test_different_seeds_differ(self, lines):
        a = encode("same message", lines, seed=1)
        b = encode("same message", lines, seed=2)
        assert a != b

    def test_unseeded_varies(self, lines):
        results = {tuple(encode("randomness check", lines)) for _ in range(5)}
        assert len(results) > 1


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------

class TestErrors:
    def test_missing_char_raises_value_error(self, lines):
        # The book has no digits, so this must fail loudly
        with pytest.raises(ValueError):
            encode("viva 2026", lines)

    def test_missing_char_raises_specific_type(self, lines):
        with pytest.raises(CharacterNotFoundError) as excinfo:
            encode("viva 2026", lines)
        assert excinfo.value.ch == "2"

    def test_empty_book_raises(self):
        with pytest.raises(BookCipherError):
            encode("hello", ["", "   "])

    def test_decode_line_out_of_range(self, lines):
        with pytest.raises(PositionOutOfRangeError):
            decode([(999, 0, 0)], lines)

    def test_decode_word_out_of_range(self, lines):
        with pytest.raises(PositionOutOfRangeError):
            decode([(0, 999, 0)], lines)

    def test_decode_char_out_of_range(self, lines):
        with pytest.raises(PositionOutOfRangeError):
            decode([(0, 0, 999)], lines)

    def test_error_hierarchy(self):
        assert issubclass(CharacterNotFoundError, BookCipherError)
        assert issubclass(PositionOutOfRangeError, BookCipherError)
        assert issubclass(BookCipherError, ValueError)


# ---------------------------------------------------------------------------
# serialization
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_positions_io_roundtrip(self, lines):
        positions = encode("box of liquor", lines, seed=3)
        text = positions_to_text(positions)
        assert text_to_positions(text) == positions

    def test_text_format_shape(self):
        text = positions_to_text([(1, 2, 3), (4, -1, -1)])
        assert text == "1.2.3\n4.-1.-1\n"

    def test_blank_lines_skipped(self):
        assert text_to_positions("1.2.3\n\n  \n4.5.6\n") == [(1, 2, 3), (4, 5, 6)]

    def test_malformed_line_raises(self):
        with pytest.raises(BookCipherError):
            text_to_positions("1.2\n")

    def test_non_numeric_raises(self):
        with pytest.raises(BookCipherError):
            text_to_positions("a.b.c\n")

    def test_four_fields_raises(self):
        with pytest.raises(BookCipherError):
            text_to_positions("1.2.3.4\n")


# ---------------------------------------------------------------------------
# validate_positions
# ---------------------------------------------------------------------------

class TestValidate:
    def test_valid_positions_no_problems(self, lines):
        positions = encode("all good here", lines, seed=2)
        assert validate_positions(positions, lines) == []

    def test_reports_bad_line(self, lines):
        problems = validate_positions([(999, 0, 0)], lines)
        assert len(problems) == 1
        assert "line 999" in problems[0]

    def test_reports_bad_word(self, lines):
        problems = validate_positions([(0, 999, 0)], lines)
        assert len(problems) == 1
        assert "word 999" in problems[0]

    def test_reports_bad_char(self, lines):
        problems = validate_positions([(0, 0, 999)], lines)
        assert len(problems) == 1
        assert "char 999" in problems[0]

    def test_space_markers_ignored(self, lines):
        assert validate_positions([(0, -1, -1), (5, -1, -1)], lines) == []

    def test_multiple_problems_all_reported(self, lines):
        problems = validate_positions([(999, 0, 0), (0, 999, 0), (0, 0, 999)], lines)
        assert len(problems) == 3


# ---------------------------------------------------------------------------
# coverage and statistics
# ---------------------------------------------------------------------------

class TestCoverage:
    def test_coverage_is_reasonable(self, lines):
        c = coverage(lines)
        assert c["percent"] >= 90
        assert "z" in c["found"]

    def test_full_alphabet_book(self):
        lines = book_from_text("abcdefghijklmnopqrstuvwxyz")
        c = coverage(lines)
        assert c["percent"] == 100
        assert c["missing"] == []

    def test_partial_alphabet(self):
        lines = book_from_text("abc def ghi")
        c = coverage(lines)
        assert c["percent"] < 50
        assert "j" in c["missing"]

    def test_extras_reported(self):
        lines = book_from_text("abc 123 wow!")
        c = coverage(lines)
        assert "1" in c["extras"]
        assert "!" in c["extras"]

    def test_total_positions(self):
        lines = book_from_text("aaa bb c")
        c = coverage(lines)
        assert c["total_positions"] == 6  # 3 a's + 2 b's + 1 c


class TestStats:
    def test_word_count(self, lines):
        assert word_count(lines) > 40

    def test_word_count_empty(self):
        assert word_count(["", "  "]) == 0

    def test_char_histogram_sorted(self, lines):
        hist = char_histogram(lines)
        counts = list(hist.values())
        assert counts == sorted(counts, reverse=True)
        assert hist["e"] > hist["z"]

    def test_find_char_limit(self, lines):
        found = find_char(lines, "e", limit=3)
        assert len(found) <= 3
        for li, wi, ci in found:
            assert lines[li].split()[wi][ci].lower() == "e"

    def test_find_char_missing(self, lines):
        assert find_char(lines, "9") == []


# ---------------------------------------------------------------------------
# fingerprint and diff
# ---------------------------------------------------------------------------

class TestFingerprint:
    def test_same_book_same_fingerprint(self, lines):
        assert fingerprint(lines) == fingerprint(list(lines))

    def test_different_book_different_fingerprint(self, lines):
        other = book_from_text("completely different words here")
        assert fingerprint(lines) != fingerprint(other)

    def test_rewrap_changes_fingerprint(self, lines):
        # Re-wrapping keeps the word stream but changes line numbers,
        # which breaks positions -- so the fingerprint must change too.
        words = " ".join(w for line in lines for w in line.split())
        rewrapped = book_from_text("\n".join(
            " ".join(words.split()[i:i + 5]) for i in range(0, len(words.split()), 5)
        ))
        assert fingerprint(lines) != fingerprint(rewrapped)

    def test_word_stream_change_changes_fingerprint(self, lines):
        other = list(lines)
        other[0] = other[0] + " extra words"
        assert fingerprint(lines) != fingerprint(other)

    def test_fingerprint_is_hex(self, lines):
        fp = fingerprint(lines)
        assert len(fp) == 64
        int(fp, 16)  # must parse as hex


class TestDiff:
    def test_identical_books(self, lines):
        d = diff_books(lines, list(lines))
        assert d["same_word_stream"]
        assert d["first_differing_lines"] == []
        assert d["fingerprint_a"] == d["fingerprint_b"]

    def test_rewrapped_books_same_stream(self, lines):
        words = [w for line in lines for w in line.split()]
        rewrapped = [" ".join(words[i:i + 3]) for i in range(0, len(words), 3)]
        d = diff_books(lines, rewrapped)
        assert d["same_word_stream"]
        assert d["first_differing_lines"]  # lines differ textually

    def test_word_change_detected(self, lines):
        other = list(lines)
        other[0] = other[0].replace("quick", "slow")
        d = diff_books(lines, other)
        assert not d["same_word_stream"]
        assert 0 in d["first_differing_lines"]

    def test_length_difference_reported(self, lines):
        d = diff_books(lines, lines[:3])
        assert d["lines_a"] != d["lines_b"]


# ---------------------------------------------------------------------------
# loading and normalization
# ---------------------------------------------------------------------------

class TestLoading:
    def test_load_book_from_disk(self, tmp_path):
        p = tmp_path / "book.txt"
        p.write_text(BOOK, encoding="utf-8")
        lines = load_book(p)
        assert len(lines) == 6
        assert decode(encode("meet at dawn", lines, seed=1), lines) == "meet at dawn"

    def test_load_book_tolerates_bom(self, tmp_path):
        p = tmp_path / "book.txt"
        p.write_bytes(("\ufeff" + BOOK).encode("utf-8"))
        lines = load_book(p)
        assert not lines[0].startswith("\ufeff")

    def test_normalize_line_nfkc(self):
        # NFKC folds compatibility characters: ligatures and fullwidth forms.
        assert normalize_line("caf\u00e9  ") == "caf\u00e9"
        assert normalize_line("\ufb01le") == "file"          # fi ligature
        assert normalize_line("\uff21\uff22\uff23") == "ABC"  # fullwidth

    def test_normalize_preserves_internal_spacing(self):
        assert normalize_line("a  b") == "a  b"

    def test_load_without_normalize(self, tmp_path):
        p = tmp_path / "book.txt"
        p.write_text("line one   \nline two\n", encoding="utf-8")
        lines = load_book(p, normalize=False)
        assert lines[0] == "line one   "
