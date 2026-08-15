"""Tests for book_cipher_kit.audit -- hash-chained operations log."""

from __future__ import annotations

import pytest

from book_cipher_kit.audit import (
    GENESIS_HASH,
    MAGIC,
    AuditError,
    AuditLog,
    AuditRecord,
)


@pytest.fixture
def log():
    lg = AuditLog(book_fingerprint="abc123")
    lg.append("open-book", "gettysburg", timestamp="2024-01-01T00:00:00+00:00")
    lg.append("encode", "meet at dawn", timestamp="2024-01-01T00:01:00+00:00")
    lg.append("encrypt", "kdf=200000", timestamp="2024-01-01T00:02:00+00:00")
    return lg


class TestAppend:
    def test_seq_increments(self, log):
        assert [r.seq for r in log.records] == [1, 2, 3]

    def test_chain_links(self, log):
        # Each record's hash depends on the previous hash.
        assert log.records[0].hash != log.records[1].hash
        assert log.is_intact()

    def test_genesis_hash(self):
        lg = AuditLog()
        assert lg.head_hash() == GENESIS_HASH

    def test_detail_whitespace_flattened(self):
        lg = AuditLog()
        rec = lg.append("encode", "multi\nline\tdetail", timestamp="t0")
        assert "\n" not in rec.detail and "\t" not in rec.detail

    def test_default_timestamp(self):
        lg = AuditLog()
        rec = lg.append("doctor")
        assert rec.timestamp  # non-empty ISO-ish string


class TestVerify:
    def test_intact(self, log):
        ok, problems = log.verify()
        assert ok and problems == []

    def test_tampered_detail_detected(self, log):
        rec = log.records[1]
        log.records[1] = AuditRecord(rec.seq, rec.timestamp, rec.op,
                                     "ALTERED", rec.hash)
        ok, problems = log.verify()
        assert not ok
        assert any("hash mismatch" in p for p in problems)

    def test_deleted_record_detected(self, log):
        del log.records[1]
        ok, problems = log.verify()
        assert not ok

    def test_reordered_detected(self, log):
        log.records[0], log.records[1] = log.records[1], log.records[0]
        ok, problems = log.verify()
        assert not ok


class TestQueries:
    def test_tail(self, log):
        assert len(log.tail(2)) == 2
        assert log.tail(2)[-1].op == "encrypt"
        assert log.tail(99) == log.records

    def test_ops_histogram(self, log):
        hist = log.ops_histogram()
        assert hist == {"open-book": 1, "encode": 1, "encrypt": 1}

    def test_unknown_ops(self, log):
        log.append("frobnicate", timestamp="t9")
        assert log.unknown_ops() == ["frobnicate"]


class TestSerialization:
    def test_roundtrip(self, log):
        text = log.to_text()
        assert MAGIC in text
        parsed = AuditLog.from_text(text)
        assert parsed.book_fingerprint == "abc123"
        assert parsed.records == log.records
        assert parsed.is_intact()

    def test_bad_magic(self):
        with pytest.raises(AuditError):
            AuditLog.from_text('{"magic": "nope"}\n')

    def test_empty(self):
        with pytest.raises(AuditError):
            AuditLog.from_text("")

    def test_count_mismatch(self, log):
        text = log.to_text()
        lines = text.strip().splitlines()
        broken = "\n".join(lines[:-1])
        with pytest.raises(AuditError):
            AuditLog.from_text(broken)

    def test_tamper_after_export_detected(self, log):
        text = log.to_text()
        parsed = AuditLog.from_text(text)
        rec = parsed.records[0]
        parsed.records[0] = AuditRecord(rec.seq, rec.timestamp, "evil",
                                        rec.detail, rec.hash)
        assert not parsed.is_intact()
