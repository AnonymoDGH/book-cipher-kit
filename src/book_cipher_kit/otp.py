"""otp -- a book-derived one-time pad layer.

A book cipher's weakness is that the same book encodes many messages. The
classic fix is the one-time pad: use key material exactly once. This module
derives pad material FROM the shared book itself, so the two parties need
no extra secret -- only the book and an agreement about which page to burn.

How it works
------------
* A *pad page* is a line range of the book.
* The pad is the SHA-256 of the book fingerprint, the page range, and a
  counter, expanded into a keystream. Because the fingerprint binds the
  exact edition, both sides derive identical bytes from the same book.
* The message is XORed with the keystream (after UTF-8 encoding), then
  armored as base64.
* A PadLedger records which pages have been burned, and refuses to burn
  the same page twice -- the one-time discipline enforced in code.

Security note: this is only as one-time as your page discipline. The
ledger exists precisely so that discipline is not a memory exercise.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from pathlib import Path
from typing import Sequence

from .core import BookCipherError, fingerprint

MAGIC = b"BKOTP1"  # Book One-Time Pad, version 1


class PadError(BookCipherError):
    """Raised when pad discipline would be violated."""


def derive_pad(
    book_lines: Sequence[str],
    page_start: int,
    page_end: int,
    counter: int = 0,
    length: int = 64,
) -> bytes:
    """Derive 'length' bytes of pad from a book page range.

    The derivation binds the exact edition (via fingerprint), the exact
    page range, and a counter, so two parties with the same book and the
    same agreement produce identical bytes without transmitting anything.
    """
    if page_start < 0 or page_end <= page_start:
        raise PadError(f"Invalid page range [{page_start}, {page_end})")
    if page_end > len(book_lines):
        raise PadError("Page range extends past the end of the book")
    fp = fingerprint(list(book_lines)).encode()
    seed = fp + struct.pack(">III", page_start, page_end, counter)
    out = bytearray()
    block = 0
    while len(out) < length:
        out.extend(hashlib.sha256(seed + struct.pack(">Q", block)).digest())
        block += 1
    return bytes(out[:length])


def _keystream(pad: bytes, length: int) -> bytes:
    """Expand a pad into a keystream of 'length' bytes via counter hashing."""
    out = bytearray()
    block = 0
    while len(out) < length:
        out.extend(hashlib.sha256(pad + struct.pack(">Q", block)).digest())
        block += 1
    return bytes(out[:length])


def pad_encrypt(
    message: str,
    book_lines: Sequence[str],
    page_start: int,
    page_end: int,
    counter: int = 0,
) -> bytes:
    """Encrypt a message with a book-derived one-time pad.

    Returns MAGIC | page_start | page_end | counter | ciphertext. The
    header is needed so the receiver knows which page to burn; it reveals
    only the page range, not the message.
    """
    plaintext = message.encode("utf-8")
    pad = derive_pad(book_lines, page_start, page_end, counter, length=32)
    stream = _keystream(pad, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
    header = MAGIC + struct.pack(">III", page_start, page_end, counter)
    return header + ciphertext


def pad_decrypt(payload: bytes, book_lines: Sequence[str]) -> str:
    """Decrypt a payload produced by pad_encrypt().

    The receiver re-derives the pad from the page range in the header and
    the shared book. A wrong edition yields garbage, not an error -- so
    callers should verify out-of-band or wrap this in an authenticated
    layer for real use.
    """
    header_len = len(MAGIC) + 12
    if len(payload) < header_len or not payload.startswith(MAGIC):
        raise PadError("Not a book-OTP payload (bad magic or truncated)")
    page_start, page_end, counter = struct.unpack(
        ">III", payload[len(MAGIC):header_len]
    )
    ciphertext = payload[header_len:]
    pad = derive_pad(book_lines, page_start, page_end, counter, length=32)
    stream = _keystream(pad, len(ciphertext))
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, stream))
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PadError(
            "Decryption produced invalid UTF-8 -- wrong book or edition"
        ) from exc


def pad_encrypt_to_text(message: str, book_lines: Sequence[str],
                        page_start: int, page_end: int, counter: int = 0) -> str:
    """Encrypt and armor as base64 for paper transport."""
    payload = pad_encrypt(message, book_lines, page_start, page_end, counter)
    return base64.b64encode(payload).decode("ascii") + "\n"


def pad_decrypt_from_text(armored: str, book_lines: Sequence[str]) -> str:
    """De-armor and decrypt."""
    try:
        payload = base64.b64decode("".join(armored.split()), validate=True)
    except Exception as exc:
        raise PadError("Armored payload is not valid base64") from exc
    return pad_decrypt(payload, book_lines)


class PadLedger:
    """Tracks which book pages have been burned, enforcing one-time use.

    The ledger is a JSON file. Every encrypt records the page range; any
    attempt to reuse a burned page is refused. This is the code-level
    enforcement of the one-time-pad discipline.
    """

    def __init__(self, book_fingerprint: str):
        self.book_fingerprint = book_fingerprint
        self.burned: list[tuple[int, int]] = []

    def is_burned(self, page_start: int, page_end: int) -> bool:
        """True if the range overlaps any already-burned range."""
        for s, e in self.burned:
            if page_start < e and s < page_end:
                return True
        return False

    def burn(self, page_start: int, page_end: int) -> None:
        """Record a page as burned; refuse overlaps."""
        if self.is_burned(page_start, page_end):
            raise PadError(
                f"Page range [{page_start}, {page_end}) already burned -- "
                "reusing pad material breaks the one-time guarantee."
            )
        self.burned.append((page_start, page_end))

    def encrypt(
        self,
        message: str,
        book_lines: Sequence[str],
        page_start: int,
        page_end: int,
    ) -> str:
        """Encrypt and burn the page atomically."""
        if fingerprint(list(book_lines)) != self.book_fingerprint:
            raise PadError("Book does not match this ledger's fingerprint")
        self.burn(page_start, page_end)
        return pad_encrypt_to_text(message, book_lines, page_start, page_end)

    def remaining(self, total_lines: int) -> int:
        """Number of book lines not yet burned."""
        used = sum(e - s for s, e in self.burned)
        return max(total_lines - used, 0)

    # -- persistence ------------------------------------------------------

    def save(self, path: str | Path) -> None:
        data = {
            "format": "bookcipher-pad-ledger/1",
            "book_fingerprint": self.book_fingerprint,
            "burned": [list(r) for r in self.burned],
        }
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "PadLedger":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("format") != "bookcipher-pad-ledger/1":
            raise PadError("Not a bookcipher-pad-ledger/1 file")
        obj = cls(data["book_fingerprint"])
        obj.burned = [tuple(r) for r in data["burned"]]
        return obj


__all__ = [
    "MAGIC", "PadError",
    "derive_pad", "pad_encrypt", "pad_decrypt",
    "pad_encrypt_to_text", "pad_decrypt_from_text", "PadLedger",
]
