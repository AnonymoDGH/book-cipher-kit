"""End-to-end message protocol: the whole pipeline in one call.

The kit's modules each do one job -- encode, encrypt, disguise, audit.
A real operator has to chain them by hand and remember the order. This
module defines the canonical send/receive pipeline so the order is fixed,
versioned, and reversible:

Send pipeline
-------------
1. encode: message -> position triples (against the shared book)
2. encrypt: triples -> passphrase-protected ciphertext (optional)
   OR
   disguise: triples -> an innocuous-looking document (optional)

Encryption and disguise are mutually exclusive outer layers: both hide
the triples, and stacking them would add cost without adding security
(the disguise adds no secrecy once the payload is encrypted, and the
encryption destroys the document structure the disguise needs).

3. audit: every step is appended to a hash-chained audit log

Receive pipeline
----------------
The exact reverse, driven by the envelope's own stage list: the receiver
never guesses which optional stages ran.

The wire envelope is a small JSON document with a magic header, the
pipeline description, and the payload, which makes it self-describing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List, Optional, Sequence

from . import audit, crypto, formats, obfuscate
from .core import (
    BookCipherError,
    decode,
    fingerprint,
)
from .index import BookIndex

__all__ = [
    "MAGIC",
    "PROTOCOL_VERSION",
    "ProtocolError",
    "PipelineConfig",
    "send_message",
    "receive_message",
    "describe_envelope",
]

MAGIC = "bookcipher-protocol/1"

#: Bumped when the envelope format changes incompatibly.
PROTOCOL_VERSION = 1


class ProtocolError(BookCipherError):
    """Raised when an envelope is malformed or the pipeline cannot run."""


@dataclass
class PipelineConfig:
    """Which optional stages a send should apply.

    Attributes:
        passphrase: When set, positions are encrypted with it. Mutually
            exclusive with scheme.
        scheme: When set, positions are disguised with this obfuscation
            scheme. Mutually exclusive with passphrase.
        seed: RNG seed for encode and disguise (determinism in tests).
        kdf_iterations: PBKDF2 cost when encrypting.
    """

    passphrase: Optional[str] = None
    scheme: Optional[str] = None
    seed: int = 0
    kdf_iterations: int = crypto.KDF_ITERATIONS

    def validate(self) -> None:
        """Reject contradictory or unknown options."""
        if self.passphrase is not None and self.scheme is not None:
            raise ProtocolError(
                "encrypt and disguise are mutually exclusive outer layers; "
                "pick one")
        if self.scheme is not None and self.scheme not in obfuscate.SCHEMES:
            raise ProtocolError(
                f"unknown disguise scheme {self.scheme!r}; "
                f"choose from {sorted(obfuscate.SCHEMES)}")


def send_message(message: str, lines: Sequence[str],
                 config: Optional[PipelineConfig] = None,
                 log: Optional[audit.AuditLog] = None,
                 timestamp: Optional[str] = None) -> str:
    """Run the full send pipeline and return a self-describing envelope.

    Args:
        message: The plaintext to transmit.
        lines: The shared book as a list of lines.
        config: Pipeline options; defaults to encode-only.
        log: Optional audit log to append each step to.
        timestamp: Optional fixed timestamp for audit records (tests).

    Returns:
        A JSON envelope string the receiver can process with
        receive_message.

    Raises:
        ProtocolError: On a bad config; BookCipherError subclasses on an
            unencodable message.
    """
    config = config or PipelineConfig()
    config.validate()
    book_fp = fingerprint(lines)

    if log is not None:
        log.append("encode", "book=" + book_fp[:12], timestamp=timestamp)
    index = BookIndex(list(lines))
    positions = index.encode(message, seed=config.seed)

    payload: str
    stages: List[str] = ["encode"]

    if config.passphrase is not None:
        if log is not None:
            log.append("encrypt", "kdf=" + str(config.kdf_iterations),
                       timestamp=timestamp)
        payload = crypto.encrypt_to_text(
            positions, config.passphrase,
            associated_data=book_fp.encode("ascii"),
            iterations=config.kdf_iterations)
        stages.append("encrypt")
    elif config.scheme is not None:
        if log is not None:
            log.append("disguise", "scheme=" + config.scheme,
                       timestamp=timestamp)
        payload = obfuscate.hide(positions, config.scheme, seed=config.seed)
        stages.append("disguise")
    else:
        payload = formats.serialize(positions, "json")

    envelope = {
        "magic": MAGIC,
        "version": PROTOCOL_VERSION,
        "book": book_fp,
        "stages": stages,
        "payload": payload,
    }
    if config.scheme is not None:
        # Record which disguise wrapped the payload so the receiver can
        # reveal it without guessing.
        envelope["scheme"] = config.scheme
    if config.passphrase is not None:
        # The receiver must run the same KDF cost to derive the key.
        envelope["kdf"] = config.kdf_iterations
    return json.dumps(envelope, sort_keys=True, indent=2) + "\n"


def receive_message(envelope_text: str, lines: Sequence[str],
                    passphrase: Optional[str] = None,
                    log: Optional[audit.AuditLog] = None,
                    timestamp: Optional[str] = None) -> str:
    """Run the full receive pipeline and return the plaintext.

    The envelope's stage list drives the reverse order automatically.

    Args:
        envelope_text: The JSON envelope from send_message.
        lines: The receiver's copy of the shared book.
        passphrase: Required when the sender encrypted.
        log: Optional audit log.
        timestamp: Optional fixed timestamp for audit records.

    Returns:
        The decoded plaintext message.

    Raises:
        ProtocolError: On a malformed envelope, a book-fingerprint
            mismatch (wrong edition), a missing passphrase, or an unknown
            stage.
    """
    try:
        envelope = json.loads(envelope_text)
    except json.JSONDecodeError as exc:
        raise ProtocolError("envelope is not valid JSON") from exc
    if envelope.get("magic") != MAGIC:
        raise ProtocolError("bad envelope magic")
    if envelope.get("version") != PROTOCOL_VERSION:
        raise ProtocolError(
            "envelope version " + str(envelope.get("version")) +
            " != " + str(PROTOCOL_VERSION))
    stages = envelope.get("stages")
    if not isinstance(stages, list) or not stages:
        raise ProtocolError("envelope has no stage list")
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        raise ProtocolError("envelope payload missing")

    book_fp = fingerprint(lines)
    sender_fp = envelope.get("book")
    if sender_fp and sender_fp != book_fp:
        raise ProtocolError(
            "book fingerprint mismatch: sender " + str(sender_fp)[:12] +
            "... vs receiver " + book_fp[:12] + "... -- wrong edition")

    data = payload
    for stage in reversed(stages):
        if stage == "disguise":
            if log is not None:
                log.append("reveal", timestamp=timestamp)
            scheme = envelope.get("scheme")
            if scheme is None:
                raise ProtocolError("disguise stage but no scheme recorded")
            data = obfuscate.reveal(data, str(scheme))
        elif stage == "encrypt":
            if passphrase is None:
                raise ProtocolError(
                    "envelope is encrypted but no passphrase given")
            if log is not None:
                log.append("decrypt", timestamp=timestamp)
            kdf = envelope.get("kdf", crypto.KDF_ITERATIONS)
            data = crypto.decrypt_from_text(
                data, passphrase,
                associated_data=book_fp.encode("ascii"),
                iterations=int(kdf))
        elif stage == "encode":
            if log is not None:
                log.append("decode", "book=" + book_fp[:12],
                           timestamp=timestamp)
            if isinstance(data, str):
                data = formats.deserialize(data)
            return decode(data, lines)
        else:
            raise ProtocolError("unknown stage " + repr(stage))
    raise ProtocolError("envelope stage list did not end at encode")


def describe_envelope(envelope_text: str) -> str:
    """Summarize an envelope without decrypting it (safe to show)."""
    try:
        envelope = json.loads(envelope_text)
    except json.JSONDecodeError as exc:
        raise ProtocolError("envelope is not valid JSON") from exc
    if envelope.get("magic") != MAGIC:
        raise ProtocolError("bad envelope magic")
    stages = envelope.get("stages", [])
    book = str(envelope.get("book", ""))[:12]
    size = len(str(envelope.get("payload", "")))
    arrow = " -> "
    return ("protocol v" + str(envelope.get("version")) +
            " | book=" + book + "... | stages=" + arrow.join(stages) +
            " | payload=" + str(size) + " chars")
