"""Tests for book_cipher_kit.bench -- benchmarking and capacity planning."""

from __future__ import annotations

import pytest

from book_cipher_kit import book_from_text
from book_cipher_kit.bench import (
    bits_per_character,
    capacity_plan,
    full_benchmark,
    payload_sizes,
    time_encoding,
    time_indexing,
)
from book_cipher_kit.corpus import make_demo_book

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


class TestTiming:
    def test_time_indexing(self, lines):
        r = time_indexing(lines, repeats=2)
        assert r["best_seconds"] >= 0
        assert r["mean_seconds"] >= r["best_seconds"]
        assert r["words"] > 0

    def test_time_encoding(self, lines):
        r = time_encoding(lines, "measure this", repeats=2)
        assert r["best_seconds"] >= 0
        assert r["chars_per_second"] > 0
        assert r["message_chars"] == len("measure this")


class TestPayloadSizes:
    def test_all_formats_present(self, lines):
        from book_cipher_kit.index import BookIndex
        positions = BookIndex(lines).encode("size check", seed=1)
        sizes = payload_sizes(positions)
        assert set(sizes) == {"text", "json", "csv", "hex", "base64"}
        assert all(v > 0 for v in sizes.values())

    def test_text_is_most_compact(self):
        # Plain dotted triples carry no framing overhead, so text wins
        # on size for large payloads.
        big = [(i, i % 40, i % 9) for i in range(500)]
        sizes = payload_sizes(big)
        assert sizes["text"] == min(sizes.values())

    def test_size_ordering_is_stable(self):
        # hex (24 chars/triple) is the bulkiest; base64 (16/triple) next.
        big = [(i, i % 40, i % 9) for i in range(500)]
        sizes = payload_sizes(big)
        assert sizes["text"] < sizes["base64"] < sizes["hex"]


class TestCapacityPlan:
    def test_plan_shape(self, lines):
        plan = capacity_plan(lines, message_chars=20)
        assert plan["message_chars"] == 20
        assert plan["lines_per_message"] >= 1
        assert plan["messages_per_book"] >= 0
        assert plan["book_words"] > 0

    def test_bigger_message_fewer_messages(self, lines):
        small = capacity_plan(lines, message_chars=10)
        big = capacity_plan(lines, message_chars=100)
        assert big["messages_per_book"] <= small["messages_per_book"]

    def test_invalid_message_size(self, lines):
        with pytest.raises(ValueError):
            capacity_plan(lines, message_chars=0)

    def test_larger_book_more_capacity(self):
        small_book = make_demo_book("gettysburg")
        big_book = make_demo_book("gettysburg", extra_paragraphs=20, seed=1)
        small = capacity_plan(small_book, message_chars=30)
        big = capacity_plan(big_book, message_chars=30)
        assert big["messages_per_book"] >= small["messages_per_book"]


class TestBitsPerCharacter:
    def test_positive(self, lines):
        r = bits_per_character(lines)
        assert r["bits_per_char"] >= 0
        assert r["sample_chars"] > 0


class TestFullBenchmark:
    def test_combined_report(self, lines):
        report = full_benchmark(lines)
        for key in ("indexing", "encoding", "payload_sizes", "capacity",
                    "bits_per_character", "coverage"):
            assert key in report
        assert report["coverage"]["percent"] >= 90
