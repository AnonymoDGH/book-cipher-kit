"""Tamper-evident audit trail for book-cipher operations.

Every encode, decode, encrypt, or key event is appended as a record whose
hash chains to the previous record, forming a hash chain. Anyone with the
log can verify that no record was inserted, deleted, or altered after the
fact -- the classic "append-only ledger" trick applied to cipher hygiene.

Each record carries:

* a monotonically increasing sequence number,
* an ISO-8601 timestamp (caller-supplied for determinism in tests),
* an operation name and a redacted detail string,
* the SHA-256 chain hash: H(prev_hash || seq || timestamp || op || detail).

The genesis record uses a fixed all-zero previous hash, so two logs for
the same book start identically and diverge with the first operation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

__all__ = [
    "GENESIS_HASH",
    "AuditError",
    "AuditRecord",
    "AuditLog",
    "MAGIC",
]

MAGIC = "bookcipher-audit/1"

#: Previous-hash used for the very first record in a log.
GENESIS_HASH = "0" * 64

#: Operations the log understands; unknown ops are allowed but flagged.
KNOWN_OPS = frozenset({
    "open-book", "encode", "decode", "encrypt", "decrypt",
    "otp-derive", "otp-burn", "session-new", "session-add",
    "share-split", "share-combine", "doctor", "export", "import",
})


class AuditError(ValueError):
    """Raised when the audit log is structurally broken or tampered with."""


def _chain_hash(prev_hash: str, seq: int, timestamp: str, op: str,
                detail: str) -> str:
    """Compute the chain hash for one record."""
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(b"|")
    h.update(str(seq).encode("ascii"))
    h.update(b"|")
    h.update(timestamp.encode("utf-8"))
    h.update(b"|")
    h.update(op.encode("utf-8"))
    h.update(b"|")
    h.update(detail.encode("utf-8"))
    return h.hexdigest()


@dataclass(frozen=True)
class AuditRecord:
    """One immutable entry in the audit chain."""

    seq: int
    timestamp: str
    op: str
    detail: str
    hash: str

    def to_dict(self) -> Dict[str, object]:
        return {"seq": self.seq, "timestamp": self.timestamp,
                "op": self.op, "detail": self.detail, "hash": self.hash}

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "AuditRecord":
        try:
            return cls(seq=int(data["seq"]), timestamp=str(data["timestamp"]),
                       op=str(data["op"]), detail=str(data["detail"]),
                       hash=str(data["hash"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise AuditError(f"malformed audit record: {data!r}") from exc


@dataclass
class AuditLog:
    """An append-only, hash-chained operations log.

    The clock is injectable: pass a callable returning ISO timestamps for
    deterministic tests; the default uses datetime.now(timezone.utc).
    """

    book_fingerprint: str = ""
    records: List[AuditRecord] = field(default_factory=list)

    # -- appending ---------------------------------------------------------

    def append(self, op: str, detail: str = "",
               timestamp: Optional[str] = None) -> AuditRecord:
        """Append one record and return it.

        Args:
            op: Operation name (see KNOWN_OPS; others are allowed).
            detail: Free-form, ideally redacted, detail string. Newlines
                are flattened so one record stays one line on export.
            timestamp: ISO-8601 timestamp; defaults to current UTC time.
        """
        if timestamp is None:
            from datetime import datetime, timezone
            timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        ts = " ".join(str(timestamp).split())
        detail = " ".join(str(detail).split())
        prev = self.records[-1].hash if self.records else GENESIS_HASH
        seq = len(self.records) + 1
        rec = AuditRecord(seq=seq, timestamp=ts, op=op, detail=detail,
                          hash=_chain_hash(prev, seq, ts, op, detail))
        self.records.append(rec)
        return rec

    # -- verification ------------------------------------------------------

    def verify(self) -> Tuple[bool, List[str]]:
        """Walk the chain and report every inconsistency.

        Returns:
            (ok, problems) where problems is a list of human-readable
            strings, empty when the chain is intact.
        """
        problems: List[str] = []
        prev = GENESIS_HASH
        for i, rec in enumerate(self.records):
            if rec.seq != i + 1:
                problems.append(f"record {i}: seq {rec.seq} out of order")
            expected = _chain_hash(prev, rec.seq, rec.timestamp, rec.op,
                                   rec.detail)
            if rec.hash != expected:
                problems.append(f"record {i} (seq {rec.seq}): hash mismatch")
            prev = rec.hash
        return (not problems, problems)

    def is_intact(self) -> bool:
        """True when verify() finds no problems."""
        return self.verify()[0]

    # -- queries -----------------------------------------------------------

    def tail(self, n: int = 10) -> List[AuditRecord]:
        """The last n records (or fewer)."""
        return self.records[-n:]

    def ops_histogram(self) -> Dict[str, int]:
        """Count records per operation name."""
        hist: Dict[str, int] = {}
        for rec in self.records:
            hist[rec.op] = hist.get(rec.op, 0) + 1
        return hist

    def unknown_ops(self) -> List[str]:
        """Operation names outside KNOWN_OPS, in first-seen order."""
        seen: List[str] = []
        for rec in self.records:
            if rec.op not in KNOWN_OPS and rec.op not in seen:
                seen.append(rec.op)
        return seen

    def head_hash(self) -> str:
        """The current chain head hash (genesis hash when empty)."""
        return self.records[-1].hash if self.records else GENESIS_HASH

    # -- serialization -----------------------------------------------------

    def to_text(self) -> str:
        """Serialize to the portable JSON-lines format."""
        header = {"magic": MAGIC, "book": self.book_fingerprint,
                  "count": len(self.records), "head": self.head_hash()}
        lines = [json.dumps(header, sort_keys=True)]
        lines.extend(json.dumps(rec.to_dict(), sort_keys=True)
                     for rec in self.records)
        return "\n".join(lines) + "\n"

    @classmethod
    def from_text(cls, text: str) -> "AuditLog":
        """Parse to_text output, validating the header against the body.

        Raises:
            AuditError: On a bad magic, a count/head mismatch, or a
                malformed record line. The chain itself is NOT verified
                here; call verify() to check for tampering.
        """
        lines = [ln for ln in text.strip().splitlines() if ln.strip()]
        if not lines:
            raise AuditError("empty audit log")
        try:
            header = json.loads(lines[0])
        except json.JSONDecodeError as exc:
            raise AuditError("bad audit header") from exc
        if header.get("magic") != MAGIC:
            raise AuditError("bad audit magic")
        log = cls(book_fingerprint=str(header.get("book", "")))
        for ln in lines[1:]:
            try:
                log.records.append(AuditRecord.from_dict(json.loads(ln)))
            except json.JSONDecodeError as exc:
                raise AuditError(f"bad audit record line: {ln!r}") from exc
        if header.get("count") != len(log.records):
            raise AuditError("audit count mismatch: header lies about size")
        if header.get("head") != log.head_hash():
            raise AuditError("audit head mismatch: records were altered")
        return log
