"""Tests for book_cipher_kit.mnemonic -- fingerprint word rendering."""

from __future__ import annotations

import hashlib

import pytest

from book_cipher_kit.mnemonic import (
    CHECK_WORD,
    MNEMONIC_WORDS,
    MnemonicError,
    fingerprint_mnemonic,
    hex_to_mnemonic,
    mnemonic_to_hex,
    verify_mnemonic,
)

DIGEST = hashlib.sha256(b"the art of war").hexdigest()


class TestWordList:
    def test_exactly_256_unique(self):
        assert len(MNEMONIC_WORDS) == 256
        assert len(set(MNEMONIC_WORDS)) == 256

    def test_all_lowercase_alpha(self):
        assert all(w.isalpha() and w.islower() for w in MNEMONIC_WORDS)


class TestHexToMnemonic:
    def test_default_six_words_plus_checksum(self):
        phrase = hex_to_mnemonic(DIGEST)
        tokens = phrase.split()
        assert len(tokens) == 8  # 6 data + check + checksum
        assert tokens[6] == CHECK_WORD

    def test_no_checksum(self):
        phrase = hex_to_mnemonic(DIGEST, words=4, with_checksum=False)
        assert len(phrase.split()) == 4

    def test_deterministic(self):
        assert hex_to_mnemonic(DIGEST) == hex_to_mnemonic(DIGEST)

    def test_case_insensitive_input(self):
        assert hex_to_mnemonic(DIGEST.upper()) == hex_to_mnemonic(DIGEST)

    def test_bad_hex(self):
        with pytest.raises(MnemonicError):
            hex_to_mnemonic("not-hex-at-all")

    def test_empty_digest(self):
        with pytest.raises(MnemonicError):
            hex_to_mnemonic("")

    def test_too_many_words(self):
        with pytest.raises(MnemonicError):
            hex_to_mnemonic("abcd", words=5)  # only 2 bytes

    def test_zero_words(self):
        with pytest.raises(MnemonicError):
            hex_to_mnemonic(DIGEST, words=0)


class TestRoundtrip:
    def test_roundtrip(self):
        phrase = hex_to_mnemonic(DIGEST, words=6)
        recovered = mnemonic_to_hex(phrase)
        assert DIGEST.startswith(recovered)
        assert len(recovered) == 12  # 6 bytes -> 12 hex chars

    def test_roundtrip_no_checksum(self):
        phrase = hex_to_mnemonic(DIGEST, words=3, with_checksum=False)
        recovered = mnemonic_to_hex(phrase)
        assert DIGEST.startswith(recovered)

    def test_case_and_spacing_tolerant(self):
        phrase = hex_to_mnemonic(DIGEST, words=4)
        assert mnemonic_to_hex(phrase.upper()) == mnemonic_to_hex(phrase)
        assert mnemonic_to_hex("  " + phrase + "  ") == mnemonic_to_hex(phrase)


def _corrupt_first(tokens):
    """Swap the first data word for a valid but different list word."""
    replacement = "acorn" if tokens[0] != "acorn" else "anchor"
    tokens[0] = replacement
    return tokens


class TestChecksum:
    def test_corrupted_word_detected(self):
        phrase = hex_to_mnemonic(DIGEST, words=6)
        tokens = _corrupt_first(phrase.split())
        # A valid-but-wrong word changes the computed checksum.
        with pytest.raises(MnemonicError):
            mnemonic_to_hex(" ".join(tokens))

    def test_skip_verification(self):
        phrase = hex_to_mnemonic(DIGEST, words=6)
        tokens = _corrupt_first(phrase.split())
        # Without verification the (wrong) phrase still parses.
        recovered = mnemonic_to_hex(" ".join(tokens), verify_checksum=False)
        assert not DIGEST.startswith(recovered)

    def test_check_without_checksum_word(self):
        with pytest.raises(MnemonicError):
            mnemonic_to_hex("acorn anchor " + CHECK_WORD)


class TestErrors:
    def test_empty_phrase(self):
        with pytest.raises(MnemonicError):
            mnemonic_to_hex("   ")

    def test_unknown_word(self):
        with pytest.raises(MnemonicError):
            mnemonic_to_hex("acorn notaword anchor")


class TestVerify:
    def test_verify_match(self):
        phrase = hex_to_mnemonic(DIGEST, words=6)
        assert verify_mnemonic(phrase, DIGEST)

    def test_verify_mismatch(self):
        phrase = hex_to_mnemonic(DIGEST, words=6)
        other = hashlib.sha256(b"a different book").hexdigest()
        assert not verify_mnemonic(phrase, other)

    def test_verify_garbage_returns_false(self):
        assert not verify_mnemonic("total garbage words", DIGEST)


class TestFingerprintMnemonic:
    def test_convenience(self):
        assert fingerprint_mnemonic(DIGEST) == hex_to_mnemonic(DIGEST)
