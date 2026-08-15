"""crypto -- a second layer of protection for book-cipher positions.

A book cipher is only as secret as the book. This module adds an optional
second lock: the position list itself is encrypted with a stream cipher
derived from a passphrase, so even someone who has the book still needs
the passphrase to read the coordinates.

Design notes
------------
* The keystream is SHA-256 in counter mode (a standard, well-understood
  construction) keyed with PBKDF2-HMAC-SHA256.
* Every payload carries a random salt and an HMAC-SHA256 tag, so tampering
  is detected before decryption is attempted.
* Positions are first packed into the compact binary form from formats.py,
  so the ciphertext is short.

This is honest cryptography built from the standard library -- not a toy
XOR -- but for real secrets you should still prefer a vetted library like
age or GPG. This layer exists to make the kit complete and to teach the
construction.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
from typing import Sequence

from .core import BookCipherError
from .formats import _pack, _unpack

Position = tuple[int, int, int]

KDF_ITERATIONS = 200_000
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 32
MAGIC = b"BCKE1"  # Book Cipher Kit Encrypted, version 1


def _derive_keys(passphrase: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    """Derive an encryption key and a MAC key from the passphrase."""
    material = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, iterations, dklen=64
    )
    return material[:32], material[32:]


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """SHA-256 counter-mode keystream of exactly 'length' bytes."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(key + nonce + struct.pack(">Q", counter)).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt_positions(
    positions: Sequence[Position],
    passphrase: str,
    *,
    associated_data: bytes = b"",
    salt: bytes | None = None,
    nonce: bytes | None = None,
    iterations: int = KDF_ITERATIONS,
) -> bytes:
    """Encrypt positions into a self-describing binary payload.

    Layout: MAGIC | salt | nonce | ciphertext | tag

    associated_data
        Extra bytes that are authenticated but not encrypted -- for
        example the book's fingerprint, binding the ciphertext to one
        specific edition.
    """
    if not passphrase:
        raise BookCipherError("Refusing to encrypt with an empty passphrase.")
    salt = salt if salt is not None else os.urandom(SALT_BYTES)
    nonce = nonce if nonce is not None else os.urandom(NONCE_BYTES)
    enc_key, mac_key = _derive_keys(passphrase, salt, iterations)

    plaintext = _pack(positions)
    stream = _keystream(enc_key, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))

    mac = hmac.new(mac_key, digestmod="sha256")
    mac.update(MAGIC)
    mac.update(salt)
    mac.update(nonce)
    mac.update(struct.pack(">I", len(associated_data)))
    mac.update(associated_data)
    mac.update(ciphertext)
    tag = mac.digest()

    return MAGIC + salt + nonce + ciphertext + tag


def decrypt_positions(
    payload: bytes,
    passphrase: str,
    *,
    associated_data: bytes = b"",
    iterations: int = KDF_ITERATIONS,
) -> list[Position]:
    """Decrypt a payload produced by encrypt_positions().

    Raises BookCipherError on any of: bad magic, truncated payload,
    wrong passphrase (tag mismatch), or corrupt plaintext.
    """
    header = SALT_BYTES + NONCE_BYTES + TAG_BYTES
    if len(payload) < len(MAGIC) + header:
        raise BookCipherError("Payload too short to be a book-cipher payload.")
    if not payload.startswith(MAGIC):
        raise BookCipherError("Payload magic mismatch -- not a book-cipher payload.")

    body = payload[len(MAGIC):]
    salt = body[:SALT_BYTES]
    nonce = body[SALT_BYTES:SALT_BYTES + NONCE_BYTES]
    tag = body[-TAG_BYTES:]
    ciphertext = body[SALT_BYTES + NONCE_BYTES:-TAG_BYTES]

    enc_key, mac_key = _derive_keys(passphrase, salt, iterations)

    mac = hmac.new(mac_key, digestmod="sha256")
    mac.update(MAGIC)
    mac.update(salt)
    mac.update(nonce)
    mac.update(struct.pack(">I", len(associated_data)))
    mac.update(associated_data)
    mac.update(ciphertext)
    if not hmac.compare_digest(mac.digest(), tag):
        raise BookCipherError(
            "Authentication failed -- wrong passphrase or tampered payload."
        )

    stream = _keystream(enc_key, nonce, len(ciphertext))
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, stream))
    try:
        return _unpack(plaintext)
    except BookCipherError as exc:
        raise BookCipherError(f"Decrypted payload is corrupt: {exc}") from exc


def encode_payload(payload: bytes, *, line_width: int = 64) -> str:
    """Armor a binary payload as wrapped base64 for paper transport."""
    encoded = base64.b64encode(payload).decode("ascii")
    lines = [encoded[i:i + line_width] for i in range(0, len(encoded), line_width)]
    return "\n".join(lines) + "\n"


def decode_payload(armored: str) -> bytes:
    """Reverse encode_payload(); tolerates whitespace and blank lines."""
    joined = "".join(armored.split())
    try:
        return base64.b64decode(joined, validate=True)
    except Exception as exc:
        raise BookCipherError("Armored payload is not valid base64") from exc


def encrypt_to_text(
    positions: Sequence[Position],
    passphrase: str,
    *,
    associated_data: bytes = b"",
    iterations: int = KDF_ITERATIONS,
) -> str:
    """Encrypt and armor in one step -- the usual convenience path."""
    return encode_payload(
        encrypt_positions(
            positions, passphrase,
            associated_data=associated_data, iterations=iterations,
        )
    )


def decrypt_from_text(
    armored: str,
    passphrase: str,
    *,
    associated_data: bytes = b"",
    iterations: int = KDF_ITERATIONS,
) -> list[Position]:
    """De-armor and decrypt in one step."""
    return decrypt_positions(
        decode_payload(armored), passphrase,
        associated_data=associated_data, iterations=iterations,
    )


def passphrase_fingerprint(passphrase: str, iterations: int = KDF_ITERATIONS) -> str:
    """A short, safe-to-display fingerprint of a passphrase.

    Lets two people confirm they share the same passphrase without
    revealing it. Deliberately slow (same KDF cost, fixed salt).
    """
    fixed_salt = b"book-cipher-kit-passprint-v1"
    digest = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), fixed_salt, iterations, dklen=8
    )
    return digest.hex()


__all__ = [
    "KDF_ITERATIONS", "MAGIC",
    "encrypt_positions", "decrypt_positions",
    "encode_payload", "decode_payload",
    "encrypt_to_text", "decrypt_from_text",
    "passphrase_fingerprint",
]
