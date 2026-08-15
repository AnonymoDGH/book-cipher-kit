"""Tests for book_cipher_kit.exchange -- edition verification ceremony."""

from __future__ import annotations

import random

import pytest

from book_cipher_kit import book_from_text, fingerprint
from book_cipher_kit.exchange import (
    CeremonyTranscript,
    ExchangeError,
    Probe,
    answer_probes,
    digest_word,
    make_probes,
    probe_word,
    verify_answers,
)

BOOK = (
    "The quick brown fox jumps over the lazy dog again and again.\n"
    "Pack my box with five dozen liquor jugs. Six big devils from Japan\n"
    "quickly forgot how to waltz. Amazingly few discotheques provide\n"
    "jukeboxes. The five boxing wizards jump quickly.\n"
)
SAME_BOOK = BOOK  # identical edition
WRONG_BOOK = (
    "A quick red fox leaps over a sleepy hound once more and more.\n"
    "Pack my box with five dozen liquor jugs. Six big devils from Japan\n"
    "quickly forgot how to waltz. Amazingly few discotheques provide\n"
    "jukeboxes. The five boxing wizards jump quickly.\n"
)


@pytest.fixture
def lines():
    return book_from_text(BOOK)


@pytest.fixture
def other_lines():
    return book_from_text(SAME_BOOK)


@pytest.fixture
def wrong_lines():
    return book_from_text(WRONG_BOOK)


class TestProbes:
    def test_probes_fit_book(self, lines):
        probes = make_probes(lines, count=10, rng=random.Random(1))
        assert len(probes) == 10
        for p in probes:
            assert probe_word(lines, p)  # answerable

    def test_deterministic(self, lines):
        a = make_probes(lines, rng=random.Random(3))
        b = make_probes(lines, rng=random.Random(3))
        assert a == b

    def test_zero_probes_rejected(self, lines):
        with pytest.raises(ExchangeError):
            make_probes(lines, count=0)

    def test_empty_book(self):
        with pytest.raises(ExchangeError):
            make_probes([])

    def test_probe_out_of_range(self, lines):
        with pytest.raises(ExchangeError):
            probe_word(lines, Probe(line=999, word=0))
        with pytest.raises(ExchangeError):
            probe_word(lines, Probe(line=0, word=999))


class TestDigest:
    def test_salt_changes_digest(self):
        assert digest_word("fox", "salt-a") != digest_word("fox", "salt-b")

    def test_case_insensitive(self):
        assert digest_word("Fox", "s") == digest_word("fox", "s")


class TestCeremony:
    def test_same_book_passes(self, lines, other_lines):
        probes = make_probes(lines, rng=random.Random(5))
        salt = "ceremony-1"
        answers = answer_probes(other_lines, probes, salt)
        ok, bad = verify_answers(lines, probes, answers, salt)
        assert ok and bad == []

    def test_wrong_book_fails(self, lines, wrong_lines):
        probes = make_probes(lines, count=8, rng=random.Random(5))
        salt = "ceremony-2"
        answers = answer_probes(wrong_lines, probes, salt)
        ok, bad = verify_answers(lines, probes, answers, salt)
        assert not ok
        assert bad  # at least one mismatch (line 0 differs)

    def test_wrong_salt_fails(self, lines, other_lines):
        probes = make_probes(lines, rng=random.Random(7))
        answers = answer_probes(other_lines, probes, "salt-1")
        ok, _ = verify_answers(lines, probes, answers, "salt-2")
        assert not ok

    def test_answer_count_mismatch(self, lines):
        probes = make_probes(lines, rng=random.Random(9))
        with pytest.raises(ExchangeError):
            verify_answers(lines, probes, ["x"], "salt")

    def test_shorter_edition_fails_probe(self, lines):
        short = book_from_text("only one line here\n")
        probes = [Probe(line=3, word=0)]
        with pytest.raises(ExchangeError):
            answer_probes(short, probes, "salt")


class TestTranscript:
    def test_roundtrip(self, lines, other_lines):
        probes = make_probes(lines, rng=random.Random(11))
        salt = "ceremony-3"
        answers = answer_probes(other_lines, probes, salt)
        ok, _ = verify_answers(lines, probes, answers, salt)
        t = CeremonyTranscript(salt=salt, book_fingerprint=fingerprint(lines),
                               probes=list(probes), answers=answers, result=ok)
        text = t.to_text()
        parsed = CeremonyTranscript.from_text(text)
        assert parsed.salt == salt
        assert parsed.probes == list(probes)
        assert parsed.answers == answers
        assert parsed.result is True

    def test_reverify(self, lines, other_lines):
        probes = make_probes(lines, rng=random.Random(13))
        answers = answer_probes(other_lines, probes, "s")
        t = CeremonyTranscript(salt="s", probes=list(probes), answers=answers)
        assert t.reverify(lines)

    def test_bad_magic(self):
        with pytest.raises(ExchangeError):
            CeremonyTranscript.from_text('{"magic": "nope"}')

    def test_empty_transcript_reverify(self, lines):
        t = CeremonyTranscript(salt="s")
        assert not t.reverify(lines)
