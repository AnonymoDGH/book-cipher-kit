"""Tests for book_cipher_kit.session -- multi-message sessions."""

from __future__ import annotations

import pytest

from book_cipher_kit import book_from_text, fingerprint
from book_cipher_kit.session import Session, SessionError

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
def session(lines):
    return Session(fingerprint(lines), name="test-session")


class TestAddMessage:
    def test_add_and_decode(self, session, lines):
        session.add_message("first message", lines, seed=1, page_start=0, page_end=3)
        assert session.decode_message("msg-001", lines) == "first message"

    def test_auto_ids(self, session, lines):
        session.add_message("one", lines, seed=1, page_start=0, page_end=2)
        session.add_message("two", lines, seed=2, page_start=2, page_end=4)
        assert session.summary()["ids"] == ["msg-001", "msg-002"]

    def test_custom_id(self, session, lines):
        session.add_message("x", lines, seed=1, message_id="alpha",
                            page_start=0, page_end=2)
        assert session.decode_message("alpha", lines) == "x"

    def test_duplicate_id_rejected(self, session, lines):
        session.add_message("x", lines, seed=1, message_id="dup",
                            page_start=0, page_end=2)
        with pytest.raises(SessionError, match="Duplicate"):
            session.add_message("y", lines, seed=2, message_id="dup",
                                page_start=2, page_end=4)

    def test_range_reuse_rejected(self, session, lines):
        session.add_message("x", lines, seed=1, page_start=0, page_end=3)
        with pytest.raises(SessionError, match="overlaps"):
            session.add_message("y", lines, seed=2, page_start=2, page_end=5)

    def test_adjacent_ranges_ok(self, session, lines):
        session.add_message("x", lines, seed=1, page_start=0, page_end=3)
        session.add_message("y", lines, seed=2, page_start=3, page_end=6)
        assert session.summary()["messages"] == 2

    def test_bad_range_rejected(self, session, lines):
        with pytest.raises(SessionError):
            session.add_message("x", lines, page_start=5, page_end=2)
        with pytest.raises(SessionError):
            session.add_message("x", lines, page_start=0, page_end=999)

    def test_message_stays_in_range(self, session, lines):
        session.add_message("range check", lines, seed=1, page_start=2, page_end=4)
        record = session.get_message("msg-001")
        for li, wi, ci in record["positions"]:
            if wi != -1:
                assert 2 <= li < 4


class TestIntegrity:
    def test_tamper_detected(self, session, lines):
        session.add_message("integrity", lines, seed=1, page_start=0, page_end=3)
        session.messages[0]["positions"][0] = [9, 9, 9]
        with pytest.raises(SessionError, match="[Cc]hecksum"):
            session.decode_message("msg-001", lines)

    def test_verify_all_clean(self, session, lines):
        session.add_message("a", lines, seed=1, page_start=0, page_end=2)
        session.add_message("b", lines, seed=2, page_start=2, page_end=4)
        assert session.verify_all(lines) == []

    def test_verify_all_finds_tamper(self, session, lines):
        session.add_message("a", lines, seed=1, page_start=0, page_end=2)
        session.messages[0]["checksum"] = "0" * 16
        problems = session.verify_all(lines)
        assert len(problems) == 1
        assert "msg-001" in problems[0]


class TestPersistence:
    def test_save_load_roundtrip(self, session, lines, tmp_path):
        session.add_message("persist me", lines, seed=1, page_start=0, page_end=3)
        path = tmp_path / "session.json"
        session.save(path)
        loaded = Session.load(path)
        assert loaded.name == "test-session"
        assert loaded.book_fingerprint == session.book_fingerprint
        assert loaded.decode_message("msg-001", lines) == "persist me"

    def test_load_rejects_foreign_format(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text('{"format": "something-else"}', encoding="utf-8")
        with pytest.raises(SessionError):
            Session.load(path)

    def test_used_ranges_restored(self, session, lines, tmp_path):
        session.add_message("x", lines, seed=1, page_start=0, page_end=3)
        path = tmp_path / "session.json"
        session.save(path)
        loaded = Session.load(path)
        with pytest.raises(SessionError, match="overlaps"):
            loaded.add_message("y", lines, seed=2, page_start=1, page_end=4)


class TestSummary:
    def test_summary_shape(self, session, lines):
        session.add_message("hello world", lines, seed=1, page_start=0, page_end=3)
        s = session.summary()
        assert s["messages"] == 1
        assert s["total_chars"] == len("hello world")
        assert s["book_fingerprint"] == fingerprint(lines)
