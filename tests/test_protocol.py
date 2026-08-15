"""Tests for book_cipher_kit.protocol -- the end-to-end pipeline."""

from __future__ import annotations

import pytest

from book_cipher_kit import book_from_text
from book_cipher_kit.audit import AuditLog
from book_cipher_kit.protocol import (
    PROTOCOL_VERSION,
    PipelineConfig,
    ProtocolError,
    describe_envelope,
    receive_message,
    send_message,
)

BOOK = (
    "The quick brown fox jumps over the lazy dog again and again.\n"
    "Pack my box with five dozen liquor jugs. Six big devils from Japan\n"
    "quickly forgot how to waltz. Amazingly few discotheques provide\n"
    "jukeboxes. The five boxing wizards jump quickly.\n"
)
OTHER_BOOK = (
    "A quick red fox leaps over a sleepy hound once more and more.\n"
    "Pack my box with five dozen liquor jugs. Six big devils from Japan\n"
)

IT = 1000  # fast KDF for tests


@pytest.fixture
def lines():
    return book_from_text(BOOK)


@pytest.fixture
def other_lines():
    return book_from_text(OTHER_BOOK)


class TestSendReceive:
    def test_plain_roundtrip(self, lines):
        env = send_message("meet at dawn", lines)
        assert receive_message(env, lines) == "meet at dawn"

    def test_encrypted_roundtrip(self, lines):
        cfg = PipelineConfig(passphrase="hunter2", kdf_iterations=IT)
        env = send_message("secret plan", lines, config=cfg)
        assert receive_message(env, lines, passphrase="hunter2") == "secret plan"

    def test_encrypted_needs_passphrase(self, lines):
        cfg = PipelineConfig(passphrase="hunter2", kdf_iterations=IT)
        env = send_message("secret plan", lines, config=cfg)
        with pytest.raises(ProtocolError):
            receive_message(env, lines)

    def test_disguised_roundtrip(self, lines):
        # "invoice" is the only fully lossless scheme (qty = word + 1, no
        # modulo), so it roundtrips any message the index produces.
        cfg = PipelineConfig(scheme="invoice", seed=7)
        env = send_message("meet at dawn", lines, config=cfg)
        assert "invoice" in env  # scheme recorded
        assert receive_message(env, lines) == "meet at dawn"

    def test_invoice_roundtrip_longer_message(self, lines):
        cfg = PipelineConfig(scheme="invoice", seed=3)
        env = send_message("the quick brown fox", lines, config=cfg)
        assert receive_message(env, lines) == "the quick brown fox"

    def test_lossy_scheme_small_words_roundtrip(self, lines):
        # shopping stores word mod 8, so it is lossless only while every
        # word index stays under 8. "dog" at seed 0 picks only low-index
        # words on this book, so it survives the modulo.
        cfg = PipelineConfig(scheme="shopping", seed=0)
        env = send_message("dog", lines, config=cfg)
        assert receive_message(env, lines) == "dog"

    def test_deterministic_with_seed(self, lines):
        a = send_message("hello", lines, config=PipelineConfig(seed=5))
        b = send_message("hello", lines, config=PipelineConfig(seed=5))
        assert a == b


class TestConfigValidation:
    def test_encrypt_and_disguise_conflict(self):
        cfg = PipelineConfig(passphrase="x", scheme="shopping")
        with pytest.raises(ProtocolError):
            cfg.validate()

    def test_unknown_scheme(self):
        cfg = PipelineConfig(scheme="nonexistent")
        with pytest.raises(ProtocolError):
            cfg.validate()

    def test_send_rejects_bad_config(self, lines):
        cfg = PipelineConfig(passphrase="x", scheme="shopping")
        with pytest.raises(ProtocolError):
            send_message("hi", lines, config=cfg)


class TestEditionBinding:
    def test_wrong_edition_rejected(self, lines, other_lines):
        env = send_message("meet at dawn", lines)
        with pytest.raises(ProtocolError, match="fingerprint mismatch"):
            receive_message(env, other_lines)


class TestEnvelopeErrors:
    def test_not_json(self, lines):
        with pytest.raises(ProtocolError):
            receive_message("not json at all", lines)

    def test_bad_magic(self, lines):
        with pytest.raises(ProtocolError):
            receive_message('{"magic": "nope"}', lines)

    def test_bad_version(self, lines):
        env = send_message("hi", lines)
        tampered = env.replace('"version": ' + str(PROTOCOL_VERSION),
                               '"version": 99')
        with pytest.raises(ProtocolError):
            receive_message(tampered, lines)

    def test_missing_stages(self, lines):
        with pytest.raises(ProtocolError):
            receive_message('{"magic": "bookcipher-protocol/1", '
                            '"version": 1, "payload": "x"}', lines)

    def test_unknown_stage(self, lines):
        env = send_message("hi", lines)
        tampered = env.replace('"encode"', '"warp"')
        with pytest.raises(ProtocolError):
            receive_message(tampered, lines)


class TestAuditIntegration:
    def test_send_and_receive_logged(self, lines):
        log = AuditLog()
        cfg = PipelineConfig(passphrase="pw", kdf_iterations=IT)
        env = send_message("audited", lines, config=cfg, log=log,
                           timestamp="t0")
        receive_message(env, lines, passphrase="pw", log=log, timestamp="t1")
        ops = [r.op for r in log.records]
        assert ops == ["encode", "encrypt", "decrypt", "decode"]
        assert log.is_intact()

    def test_disguise_logged(self, lines):
        log = AuditLog()
        cfg = PipelineConfig(scheme="log", seed=1)
        env = send_message("audited", lines, config=cfg, log=log,
                           timestamp="t0")
        receive_message(env, lines, log=log, timestamp="t1")
        ops = [r.op for r in log.records]
        assert ops == ["encode", "disguise", "reveal", "decode"]


class TestDescribe:
    def test_describe_plain(self, lines):
        env = send_message("hi", lines)
        text = describe_envelope(env)
        assert "encode" in text and "payload=" in text

    def test_describe_encrypted(self, lines):
        cfg = PipelineConfig(passphrase="pw", kdf_iterations=IT)
        env = send_message("hi", lines, config=cfg)
        text = describe_envelope(env)
        assert "encrypt" in text

    def test_describe_bad_envelope(self):
        with pytest.raises(ProtocolError):
            describe_envelope("garbage")
