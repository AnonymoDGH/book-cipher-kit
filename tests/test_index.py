"""Tests for book_cipher_kit.index -- the reusable BookIndex."""

from __future__ import annotations

import pytest

from book_cipher_kit import BookCipherError, CharacterNotFoundError, book_from_text, decode
from book_cipher_kit.index import BookIndex

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


@pytest.fixture
def index(lines):
    return BookIndex(lines)


class TestBasics:
    def test_alphabet(self, index):
        alpha = index.alphabet
        assert "a" in alpha and "z" in alpha
        assert alpha == sorted(alpha)

    def test_positions_for(self, index):
        for li, wi, ci in index.positions_for("e"):
            assert index.lines[li].split()[wi][ci].lower() == "e"

    def test_positions_for_missing(self, index):
        assert index.positions_for("9") == []

    def test_count(self, index):
        assert index.count("e") > index.count("z")
        assert index.count("9") == 0

    def test_total_positions(self, index):
        assert index.total_positions() == sum(index.count(c) for c in index.alphabet)

    def test_words(self, index):
        assert index.words() > 40

    def test_word_lines(self, index):
        assert all(index.lines[li].split() for li in index.word_lines)

    def test_fingerprint_cached(self, index):
        fp1 = index.fingerprint
        fp2 = index.fingerprint
        assert fp1 == fp2 and len(fp1) == 64


class TestEncode:
    def test_roundtrip(self, index):
        for msg in ("meet at dawn", "the package is loose", "zephyr"):
            positions = index.encode(msg, seed=42)
            assert decode(positions, index.lines) == msg

    def test_deterministic(self, index):
        a = index.encode("same message", seed=1)
        b = index.encode("same message", seed=1)
        assert a == b

    def test_matches_core_encode(self, index, lines):
        from book_cipher_kit import encode
        a = index.encode("cross check", seed=7)
        b = encode("cross check", lines, seed=7)
        assert a == b

    def test_missing_char(self, index):
        with pytest.raises(CharacterNotFoundError):
            index.encode("viva 2026")

    def test_empty_book(self):
        idx = BookIndex(["", "  "])
        with pytest.raises(BookCipherError):
            idx.encode("hello")

    def test_avoid_lines(self, index):
        avoid = {0, 1, 2}
        positions = index.encode("the quick brown fox", seed=3, avoid_lines=avoid)
        for li, wi, ci in positions:
            if wi != -1:
                assert li not in avoid

    def test_avoid_all_lines_raises(self, index):
        avoid = set(range(len(index.lines)))
        with pytest.raises(BookCipherError):
            index.encode("hello", avoid_lines=avoid)

    def test_avoid_lines_char_not_there(self):
        # In this book 'z' lives only on line 1; avoiding it must fail.
        lines = book_from_text("alpha beta gamma\nonly zebra here\nmore words follow")
        idx = BookIndex(lines)
        z_lines = {p[0] for p in idx.positions_for("z")}
        assert z_lines == {1}
        with pytest.raises(CharacterNotFoundError):
            idx.encode("z", avoid_lines=z_lines)

    def test_prefer_rare_roundtrip(self, index):
        positions = index.encode("rare bird sighting", seed=5, prefer_rare=True)
        assert decode(positions, index.lines) == "rare bird sighting"

    def test_prefer_rare_differs_from_uniform(self, index):
        a = index.encode("the quick brown fox jumps", seed=5)
        b = index.encode("the quick brown fox jumps", seed=5, prefer_rare=True)
        assert a != b


class TestStatistics:
    def test_histogram_sorted(self, index):
        hist = index.histogram()
        counts = list(hist.values())
        assert counts == sorted(counts, reverse=True)

    def test_rarest(self, index):
        rarest = index.rarest(3)
        assert len(rarest) == 3
        counts = [c for _, c in rarest]
        assert counts == sorted(counts)

    def test_line_density(self, index):
        density = index.line_density()
        assert len(density) == len(index.lines)
        assert sum(density) == index.total_positions()

    def test_coverage_report(self, index):
        report = index.coverage_report()
        assert report["percent"] >= 90
        assert report["fingerprint"] == index.fingerprint
        assert report["words"] == index.words()


class TestSerialization:
    def test_save_load_roundtrip(self, index, tmp_path, lines):
        path = tmp_path / "index.json"
        index.save(path)
        loaded = BookIndex.load(path, lines)
        assert loaded.alphabet == index.alphabet
        assert loaded.fingerprint == index.fingerprint
        a = index.encode("cache check", seed=9)
        b = loaded.encode("cache check", seed=9)
        assert a == b

    def test_load_detects_stale_cache(self, index, tmp_path):
        path = tmp_path / "index.json"
        index.save(path)
        other_lines = book_from_text("a completely different book entirely")
        with pytest.raises(BookCipherError, match="fingerprint"):
            BookIndex.load(path, other_lines)

    def test_to_dict_structure(self, index):
        d = index.to_dict()
        assert d["version"] == 1
        assert d["fingerprint"] == index.fingerprint
        assert set(d["positions"]) == set(index.alphabet)
        assert d["word_lines"] == index.word_lines
