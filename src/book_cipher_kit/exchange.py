"""Edition verification ceremony: prove you share the same book.

Before trusting a book cipher session, both parties should confirm they
hold the *same edition* of the book. Reading the whole book aloud is
impractical; sending the fingerprint over the same channel the book will
be used on leaks it to the eavesdropper.

This module implements a challenge-response ceremony that leaks almost
nothing:

1. The challenger picks random (line, word) probes and sends them.
2. The responder hashes the probed word with a per-ceremony salt and
   returns the digests.
3. The challenger computes the same digests from its own copy and
   compares. Matching digests on enough probes mean the books agree on
   those words; a wrong edition fails with overwhelming probability.

Because each response is salted and covers only a handful of words, an
eavesdropper learns digests of a few words -- not the book, and not even
which words (line numbers are relative to the shared book, which the
eavesdropper lacks). A replayed ceremony uses a fresh salt, so old
transcripts do not verify.

The module also provides a transcript record so a ceremony can be saved,
re-checked, and audited.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .core import BookCipherError, normalize_line

__all__ = [
    "ExchangeError",
    "Probe",
    "probe_word",
    "digest_word",
    "make_probes",
    "answer_probes",
    "verify_answers",
    "CeremonyTranscript",
]

MAGIC = "bookcipher-ceremony/1"

#: Default number of probes for a ceremony.
DEFAULT_PROBES = 8


class ExchangeError(BookCipherError):
    """Raised when a ceremony is malformed or fails verification."""


@dataclass(frozen=True)
class Probe:
    """One challenge: a (line, word) coordinate to hash."""

    line: int
    word: int


def probe_word(lines: Sequence[str], probe: Probe) -> str:
    """Return the word a probe points at, normalized.

    Raises:
        ExchangeError: When the probe falls outside the book -- the usual
            sign of a shorter edition.
    """
    if not (0 <= probe.line < len(lines)):
        raise ExchangeError(
            f"probe line {probe.line} out of range (book has {len(lines)} lines)")
    words = normalize_line(lines[probe.line]).split()
    if not (0 <= probe.word < len(words)):
        raise ExchangeError(
            f"probe word {probe.word} out of range on line {probe.line}")
    return words[probe.word].lower()


def digest_word(word: str, salt: str) -> str:
    """Salted SHA-256 digest of one normalized word."""
    h = hashlib.sha256()
    h.update(salt.encode("utf-8"))
    h.update(b"|")
    h.update(normalize_line(word).lower().encode("utf-8"))
    return h.hexdigest()


def make_probes(lines: Sequence[str], count: int = DEFAULT_PROBES,
                rng: Optional[random.Random] = None) -> List[Probe]:
    """Pick random probes that fit the book.

    Only lines that actually contain words are eligible, and each probe's
    word index is drawn from that line's real word count, so every probe
    is answerable by anyone holding this edition.

    Args:
        lines: The challenger's copy of the book.
        count: How many probes to issue.
        rng: Optional seeded RNG for deterministic tests.

    Raises:
        ExchangeError: When the book has no words to probe.
    """
    if count < 1:
        raise ExchangeError("need at least one probe")
    rng = rng or random.Random()
    eligible: List[Tuple[int, int]] = []
    for i, line in enumerate(lines):
        n = len(normalize_line(line).split())
        if n:
            eligible.append((i, n))
    if not eligible:
        raise ExchangeError("book has no words to probe")
    probes: List[Probe] = []
    for _ in range(count):
        line, nwords = rng.choice(eligible)
        probes.append(Probe(line=line, word=rng.randrange(nwords)))
    return probes


def answer_probes(lines: Sequence[str], probes: Sequence[Probe],
                  salt: str) -> List[str]:
    """Compute the responder's digests for a list of probes.

    Raises:
        ExchangeError: If any probe does not fit this copy of the book.
    """
    return [digest_word(probe_word(lines, p), salt) for p in probes]


def verify_answers(lines: Sequence[str], probes: Sequence[Probe],
                   answers: Sequence[str], salt: str) -> Tuple[bool, List[int]]:
    """Check a responder's answers against the challenger's own book.

    Returns:
        (all_ok, bad_indexes) where bad_indexes lists the probe positions
        whose digests disagreed. An empty bad list means the books agree
        on every probed word.
    """
    if len(probes) != len(answers):
        raise ExchangeError(
            f"{len(probes)} probes but {len(answers)} answers")
    bad: List[int] = []
    for i, (probe, answer) in enumerate(zip(probes, answers)):
        try:
            expected = digest_word(probe_word(lines, probe), salt)
        except ExchangeError:
            bad.append(i)
            continue
        if expected != answer:
            bad.append(i)
    return (not bad, bad)


@dataclass
class CeremonyTranscript:
    """A saved record of one verification ceremony.

    The transcript stores the salt, the probes, and both the expected and
    received digests so the ceremony can be re-verified offline and fed
    to the audit trail.
    """

    salt: str
    book_fingerprint: str = ""
    probes: List[Probe] = field(default_factory=list)
    answers: List[str] = field(default_factory=list)
    result: Optional[bool] = None

    def to_text(self) -> str:
        data = {
            "magic": MAGIC,
            "salt": self.salt,
            "book": self.book_fingerprint,
            "probes": [[p.line, p.word] for p in self.probes],
            "answers": self.answers,
            "result": self.result,
        }
        return json.dumps(data, sort_keys=True, indent=2) + "\n"

    @classmethod
    def from_text(cls, text: str) -> "CeremonyTranscript":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ExchangeError("bad ceremony transcript") from exc
        if data.get("magic") != MAGIC:
            raise ExchangeError("bad ceremony magic")
        try:
            t = cls(salt=str(data["salt"]),
                    book_fingerprint=str(data.get("book", "")),
                    result=data.get("result"))
            t.probes = [Probe(line=int(a), word=int(b))
                        for a, b in data.get("probes", [])]
            t.answers = [str(a) for a in data.get("answers", [])]
        except (KeyError, TypeError, ValueError) as exc:
            raise ExchangeError("malformed ceremony transcript") from exc
        return t

    def reverify(self, lines: Sequence[str]) -> bool:
        """Re-run verification against a book copy.

        Useful when the challenger wants to re-check a saved ceremony
        without re-running the live exchange.
        """
        if not self.probes or not self.answers:
            return False
        ok, _ = verify_answers(lines, self.probes, self.answers, self.salt)
        return ok
