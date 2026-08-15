"""Tests for book_cipher_kit.crypto -- encrypted position payloads."""

from __future__ import annotations

import pytest

from book_cipher_kit import BookCipherError
from book_cipher_kit.crypto import (
    MAGIC,
    decode_payload,
    decrypt_from_text,
    decrypt_positions,
    encode_payload,
    encrypt_positions,
    encrypt_to_text,
    passphrase_fingerprint,
)

POSITIONS = [(0, 4, 2), (0, 0, 2), (12, -1, -1), (87, 12, 5)]
PW = "correct horse battery staple"

# Tests use a tiny KDF cost for speed; the security properties under test
# (authentication, tamper detection, binding) do not depend on the cost.
IT = 1000


class TestRoundtrip:
    def test_binary_roundtrip(self):
        payload = encrypt_positions(POSITIONS, PW, iterations=IT)
        assert decrypt_positions(payload, PW, iterations=IT) == POSITIONS

    def test_text_roundtrip(self):
        armored = encrypt_to_text(POSITIONS, PW, iterations=IT)
        assert decrypt_from_text(armored, PW, iterations=IT) == POSITIONS

    def test_empty_positions(self):
        payload = encrypt_positions([], PW, iterations=IT)
        assert decrypt_positions(payload, PW, iterations=IT) == []

    def test_large_payload(self):
        big = [(i, i % 40, i % 9) for i in range(1500)]
        assert decrypt_positions(
            encrypt_positions(big, PW, iterations=IT), PW, iterations=IT
        ) == big

    def test_unicode_passphrase(self):
        pw = "contraseña-secreta-ñ"
        assert decrypt_positions(
            encrypt_positions(POSITIONS, pw, iterations=IT), pw, iterations=IT
        ) == POSITIONS


class TestAuthentication:
    def test_wrong_passphrase_fails(self):
        payload = encrypt_positions(POSITIONS, PW, iterations=IT)
        with pytest.raises(BookCipherError, match="[Aa]uthentication|passphrase"):
            decrypt_positions(payload, "wrong passphrase", iterations=IT)

    def test_tampered_ciphertext_fails(self):
        payload = bytearray(encrypt_positions(POSITIONS, PW, iterations=IT))
        payload[len(payload) // 2] ^= 0xFF
        with pytest.raises(BookCipherError):
            decrypt_positions(bytes(payload), PW, iterations=IT)

    def test_tampered_tag_fails(self):
        payload = bytearray(encrypt_positions(POSITIONS, PW, iterations=IT))
        payload[-1] ^= 0x01
        with pytest.raises(BookCipherError):
            decrypt_positions(bytes(payload), PW, iterations=IT)

    def test_truncated_payload_fails(self):
        payload = encrypt_positions(POSITIONS, PW, iterations=IT)
        with pytest.raises(BookCipherError):
            decrypt_positions(payload[:20], PW, iterations=IT)

    def test_bad_magic_fails(self):
        payload = bytearray(encrypt_positions(POSITIONS, PW, iterations=IT))
        payload[0] = 0x00
        with pytest.raises(BookCipherError, match="magic"):
            decrypt_positions(bytes(payload), PW, iterations=IT)

    def test_empty_passphrase_refused(self):
        with pytest.raises(BookCipherError):
            encrypt_positions(POSITIONS, "")


class TestAssociatedData:
    def test_bound_data_roundtrip(self):
        ad = b"book-fingerprint-abc123"
        payload = encrypt_positions(POSITIONS, PW, associated_data=ad, iterations=IT)
        assert decrypt_positions(payload, PW, associated_data=ad, iterations=IT) == POSITIONS

    def test_wrong_bound_data_fails(self):
        payload = encrypt_positions(POSITIONS, PW, associated_data=b"edition-A", iterations=IT)
        with pytest.raises(BookCipherError):
            decrypt_positions(payload, PW, associated_data=b"edition-B", iterations=IT)

    def test_missing_bound_data_fails(self):
        payload = encrypt_positions(POSITIONS, PW, associated_data=b"edition-A", iterations=IT)
        with pytest.raises(BookCipherError):
            decrypt_positions(payload, PW, iterations=IT)


class TestRandomness:
    def test_payloads_differ(self):
        a = encrypt_positions(POSITIONS, PW, iterations=IT)
        b = encrypt_positions(POSITIONS, PW, iterations=IT)
        assert a != b  # fresh salt+nonce each time

    def test_fixed_salt_nonce_deterministic(self):
        salt = bytes(range(16))
        nonce = bytes(range(12))
        a = encrypt_positions(POSITIONS, PW, salt=salt, nonce=nonce, iterations=IT)
        b = encrypt_positions(POSITIONS, PW, salt=salt, nonce=nonce, iterations=IT)
        assert a == b

    def test_payload_layout(self):
        payload = encrypt_positions(POSITIONS, PW, iterations=IT)
        assert payload.startswith(MAGIC)
        # magic + salt(16) + nonce(12) + ciphertext(12*len) + tag(32)
        assert len(payload) == len(MAGIC) + 16 + 12 + 12 * len(POSITIONS) + 32


class TestArmor:
    def test_armor_roundtrip(self):
        payload = encrypt_positions(POSITIONS, PW, iterations=IT)
        assert decode_payload(encode_payload(payload)) == payload

    def test_armor_tolerates_whitespace(self):
        payload = encrypt_positions(POSITIONS, PW, iterations=IT)
        armored = encode_payload(payload)
        messed = "  " + armored.replace("\n", "  \n  ") + "  "
        assert decode_payload(messed) == payload

    def test_bad_armor(self):
        with pytest.raises(BookCipherError):
            decode_payload("!!! not base64 !!!")


class TestPassprint:
    def test_deterministic(self):
        assert passphrase_fingerprint(PW, IT) == passphrase_fingerprint(PW, IT)

    def test_different_passphrases_differ(self):
        assert passphrase_fingerprint(PW, IT) != passphrase_fingerprint(PW + "!", IT)

    def test_shape(self):
        fp = passphrase_fingerprint(PW, IT)
        assert len(fp) == 16
        int(fp, 16)
