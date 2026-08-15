"""Tests for book_cipher_kit.otp -- book-derived one-time pad layer."""

from __future__ import annotations

import pytest

from book_cipher_kit import book_from_text, fingerprint
from book_cipher_kit.otp import (
    PadError,
    PadLedger,
    derive_pad,
    pad_decrypt,
    pad_decrypt_from_text,
    pad_encrypt,
    pad_encrypt_to_text,
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


class TestDerivePad:
    def test_deterministic(self, lines):
        a = derive_pad(lines, 0, 3)
        b = derive_pad(lines, 0, 3)
        assert a == b

    def test_different_range_different_pad(self, lines):
        a = derive_pad(lines, 0, 3)
        b = derive_pad(lines, 3, 6)
        assert a != b

    def test_different_counter_different_pad(self, lines):
        a = derive_pad(lines, 0, 3, counter=0)
        b = derive_pad(lines, 0, 3, counter=1)
        assert a != b

    def test_length(self, lines):
        assert len(derive_pad(lines, 0, 3, length=100)) == 100

    def test_bad_range(self, lines):
        with pytest.raises(PadError):
            derive_pad(lines, 3, 3)
        with pytest.raises(PadError):
            derive_pad(lines, 0, 999)

    def test_bound_to_edition(self, lines):
        other = book_from_text(
            "a completely different book entirely\n"
            "with several lines of its own text\n"
            "so the same page range is valid here\n"
        )
        assert derive_pad(lines, 0, 3) != derive_pad(other, 0, 3)


class TestEncryptDecrypt:
    def test_roundtrip(self, lines):
        payload = pad_encrypt("meet at dawn", lines, 0, 3)
        assert pad_decrypt(payload, lines) == "meet at dawn"

    def test_text_roundtrip(self, lines):
        armored = pad_encrypt_to_text("the package is loose", lines, 1, 4)
        assert pad_decrypt_from_text(armored, lines) == "the package is loose"

    def test_unicode_message(self, lines):
        msg = "contraseña secreta ñ"
        assert pad_decrypt(pad_encrypt(msg, lines, 0, 2), lines) == msg

    def test_empty_message(self, lines):
        assert pad_decrypt(pad_encrypt("", lines, 0, 2), lines) == ""

    def test_wrong_book_garbage(self, lines):
        msg = "a longer message so random bytes almost never decode"
        payload = pad_encrypt(msg, lines, 0, 3)
        other = book_from_text(
            "an unrelated short text here\n"
            "with enough lines to cover the range\n"
            "and different words on every line\n"
        )
        # A wrong edition yields either invalid UTF-8 (PadError) or
        # garbage that is certainly not the plaintext.
        try:
            result = pad_decrypt(payload, other)
        except PadError:
            return
        assert result != msg

    def test_bad_magic(self, lines):
        with pytest.raises(PadError):
            pad_decrypt(b"NOTMAGIC" + b"\x00" * 20, lines)

    def test_ciphertext_differs_from_plaintext(self, lines):
        payload = pad_encrypt("hello world", lines, 0, 3)
        assert b"hello world" not in payload

    def test_fresh_each_call(self, lines):
        # Same page+counter is deterministic, but different counters differ.
        a = pad_encrypt("same", lines, 0, 3, counter=0)
        b = pad_encrypt("same", lines, 0, 3, counter=1)
        assert a != b


class TestPadLedger:
    def test_burn_and_refuse_reuse(self, lines):
        ledger = PadLedger(fingerprint(lines))
        ledger.burn(0, 3)
        assert ledger.is_burned(0, 3)
        assert ledger.is_burned(1, 2)  # overlap
        with pytest.raises(PadError, match="already burned"):
            ledger.burn(2, 5)

    def test_adjacent_ok(self, lines):
        ledger = PadLedger(fingerprint(lines))
        ledger.burn(0, 3)
        ledger.burn(3, 6)  # adjacent, not overlapping
        assert len(ledger.burned) == 2

    def test_encrypt_burns_atomically(self, lines):
        ledger = PadLedger(fingerprint(lines))
        armored = ledger.encrypt("one time", lines, 0, 3)
        assert pad_decrypt_from_text(armored, lines) == "one time"
        assert ledger.is_burned(0, 3)
        with pytest.raises(PadError):
            ledger.encrypt("again", lines, 1, 4)

    def test_wrong_book_rejected(self, lines):
        ledger = PadLedger(fingerprint(lines))
        other = book_from_text("different book")
        with pytest.raises(PadError, match="fingerprint"):
            ledger.encrypt("x", other, 0, 1)

    def test_remaining(self, lines):
        ledger = PadLedger(fingerprint(lines))
        total = len(lines)
        assert ledger.remaining(total) == total
        ledger.burn(0, 2)
        assert ledger.remaining(total) == total - 2

    def test_save_load(self, lines, tmp_path):
        ledger = PadLedger(fingerprint(lines))
        ledger.burn(0, 3)
        path = tmp_path / "ledger.json"
        ledger.save(path)
        loaded = PadLedger.load(path)
        assert loaded.book_fingerprint == ledger.book_fingerprint
        assert loaded.is_burned(0, 3)
        with pytest.raises(PadError):
            loaded.burn(1, 2)

    def test_load_rejects_foreign(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text('{"format": "other"}', encoding="utf-8")
        with pytest.raises(PadError):
            PadLedger.load(path)
