"""Tests for book_cipher_kit.corpus -- embedded and generated books."""

from __future__ import annotations

import pytest

from book_cipher_kit import decode, encode
from book_cipher_kit.corpus import (
    EMBEDDED_BOOKS,
    corpus_stats,
    describe_embedded,
    generate_prose,
    get_embedded,
    list_embedded,
    make_demo_book,
)


class TestEmbedded:
    def test_list_embedded(self):
        names = list_embedded()
        assert "sun_tzu" in names
        assert "aesop" in names
        assert names == sorted(names)

    def test_every_embedded_book_loads(self):
        for name in list_embedded():
            lines = get_embedded(name)
            assert lines, name
            assert all(isinstance(ln, str) for ln in lines)

    def test_every_embedded_book_encodes_common_text(self):
        # Every embedded book must encode common-letter text.
        for name in list_embedded():
            lines = get_embedded(name)
            msg = "the war begins at dawn"
            assert decode(encode(msg, lines, seed=1), lines) == msg, name

    def test_embedded_coverage_is_high(self):
        from book_cipher_kit import coverage
        for name in list_embedded():
            c = coverage(get_embedded(name))
            assert c["percent"] >= 80, name

    def test_unknown_name_raises(self):
        with pytest.raises(KeyError) as excinfo:
            get_embedded("moby_dick")
        assert "sun_tzu" in str(excinfo.value)

    def test_describe_embedded(self):
        for name in list_embedded():
            desc = describe_embedded(name)
            assert desc and isinstance(desc, str)

    def test_embedded_books_are_distinct(self):
        texts = {tuple(get_embedded(n)) for n in list_embedded()}
        assert len(texts) == len(EMBEDDED_BOOKS)

    def test_sun_tzu_size(self):
        lines = get_embedded("sun_tzu")
        words = sum(len(ln.split()) for ln in lines)
        assert words > 500  # a usable-sized book


class TestGenerateProse:
    def test_deterministic(self):
        a = generate_prose(paragraphs=3, seed=42)
        b = generate_prose(paragraphs=3, seed=42)
        assert a == b

    def test_different_seeds_differ(self):
        a = generate_prose(paragraphs=3, seed=1)
        b = generate_prose(paragraphs=3, seed=2)
        assert a != b

    def test_paragraph_count(self):
        lines = generate_prose(paragraphs=4, sentences_per_paragraph=3, seed=0)
        # 4 paragraphs separated by blank lines, minus trailing blank.
        blanks = sum(1 for ln in lines if not ln.strip())
        assert blanks == 3

    def test_line_width_respected(self):
        lines = generate_prose(paragraphs=5, seed=0, wrap=60)
        for ln in lines:
            assert len(ln) <= 60 + 20  # soft wrap: one word may overshoot

    def test_prose_encodable(self):
        lines = generate_prose(paragraphs=6, seed=7)
        msg = "the signal moves at dawn"
        assert decode(encode(msg, lines, seed=1), lines) == msg

    def test_zero_paragraphs(self):
        assert generate_prose(paragraphs=0, seed=0) == []

    def test_words_are_lowercase_friendly(self):
        lines = generate_prose(paragraphs=2, seed=3)
        words = [w for ln in lines for w in ln.split()]
        assert all(w.strip(".,!?") for w in words)


class TestCorpusStats:
    def test_stats_shape(self):
        lines = get_embedded("aesop")
        s = corpus_stats(lines)
        assert s["lines"] == len(lines)
        assert s["words"] > 0
        assert s["unique_words"] <= s["words"]
        assert s["avg_words_per_line"] > 0
        assert s["longest_line_words"] > 0
        assert s["chars"] > 0

    def test_stats_empty(self):
        s = corpus_stats([])
        assert s["lines"] == 0
        assert s["words"] == 0

    def test_non_empty_lines_counted(self):
        s = corpus_stats(["one two", "", "three", "  "])
        assert s["non_empty_lines"] == 2


class TestMakeDemoBook:
    def test_plain(self):
        lines = make_demo_book("gettysburg")
        assert lines == get_embedded("gettysburg")

    def test_padded(self):
        base = make_demo_book("gettysburg")
        padded = make_demo_book("gettysburg", extra_paragraphs=3, seed=1)
        assert len(padded) > len(base)
        assert padded[: len(base)] == base

    def test_padded_deterministic(self):
        a = make_demo_book("aesop", extra_paragraphs=2, seed=5)
        b = make_demo_book("aesop", extra_paragraphs=2, seed=5)
        assert a == b
