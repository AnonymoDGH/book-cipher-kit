"""stego -- hide the positions themselves inside innocent-looking text.

The classic book-cipher failure is not cryptanalysis; it is a courier
carrying a suspicious list of numbers. This module removes the numbers
entirely by turning positions into prose.

Three independent schemes are provided:

1. Sentence-length arithmetic (the original one)
   Every coordinate becomes a run of sentences. Each sentence contributes
   its word count to a running sum, and a run ends at the first sentence
   that terminates with an exclamation mark. Coordinates are stored
   offset by two so that the space marker (-1) encodes as a sum of 1.
   The result reads like slightly breathless prose; to anyone without the
   convention it is just text.

2. Acrostic
   The message itself (not positions) is spelled out by the first letter
   of each line. Old, simple, and effective for short notes.

3. Null cipher (nth-word)
   The message is carried by every Nth word of a generated paragraph.
   Everything else is noise.

All schemes are deterministic under a seed and pure standard library.
"""

from __future__ import annotations

import random
import re
from typing import Iterable, Sequence

from .core import BookCipherError

Position = tuple[int, int, int]

# ---------------------------------------------------------------------------
# Sentence building blocks for exact-length prose
# ---------------------------------------------------------------------------

# Fragment pools, grouped by exact word count. Sentences are assembled from
# templates whose slot sizes sum to the target length, so the result is
# always grammatical -- never trimmed mid-phrase.

#: One-word openers.
_OPENERS1 = [
    "Meanwhile", "Soon", "Later", "Then", "Indeed", "Moreover", "Besides",
    "Afterward", "Tonight", "Today", "Tomorrow", "Quietly", "Slowly",
]

#: Two-word openers.
_OPENERS2 = [
    "At dawn", "At dusk", "In time", "At last", "Once more", "For now",
    "Above all", "Before long", "After that", "In turn",
]

#: One-word subjects.
_SUBJECTS1 = [
    "darkness", "silence", "someone", "nothing", "everything", "time",
    "fortune", "danger", "memory", "chance",
]

#: Two-word subjects.
_SUBJECTS2 = [
    "the courier", "the archivist", "a lantern", "the harbor", "the mapmaker",
    "the signal", "a stranger", "the keeper", "the letter", "a shadow",
    "the clock", "the bridge", "an echo", "the garden", "a compass",
    "the watcher", "the river", "a candle", "the ledger", "the gate",
]

#: One-word verbs that can take a bare object.
_VERBS1 = [
    "carries", "follows", "guards", "marks", "opens", "watches", "finds",
    "hides", "crosses", "measures", "remembers", "signals", "returns",
    "reveals", "keeps",
]

#: One-word objects.
_OBJECTS1 = ["everything", "nothing", "silence", "it", "truth", "word"]

#: Two-word objects.
_OBJECTS2 = [
    "the message", "a key", "the ledger", "an answer", "the route",
    "a warning", "the seal", "a name", "the packet", "a promise",
    "the cipher", "a token", "the record", "a sign", "the book",
]

#: Two-word pads, grammatically safe mid-sentence.
_PADS2 = [
    "all night", "in turn", "once again", "as always", "for now",
    "at dawn", "at dusk", "in silence", "with care", "at ease",
]

#: Three-word pads, grammatically safe mid-sentence.
_PADS3 = [
    "without a word", "in the rain", "under the arch", "past the gate",
    "by the dock", "near the archive", "against the wind", "just before midnight",
    "after the storm", "along the wall", "beyond the ridge", "inside the hall",
    "with steady hands", "in careful silence", "at the crossroads",
    "through the fog",
]

#: Two-word closers that end a sentence gracefully.
_CLOSERS2 = [
    "and waits", "and listens", "and holds", "and fades",
    "and endures", "and watches", "and rests", "and stands",
]

#: Two-word subject+verb interjections for very short sentences.
_SHORT2 = [
    "Someone comes", "Time passes", "Night falls", "Rain starts",
    "Lights dim", "Winds shift", "Doors close", "Steps echo",
    "Dawn breaks", "Signals fade", "Watchers wait", "Bells ring",
]

#: One-word interjections.
_SHORT1 = ["Listen", "Wait", "Look", "Hush", "Go", "Now"]

def _validate_pools() -> None:
    """Assert every pool entry has the word count its name promises.

    Runs at import time: a fragment with the wrong word count would
    silently corrupt every encoded run, so this check is cheap insurance.
    """
    for name, pool in (
        ("openers1", _OPENERS1), ("openers2", _OPENERS2),
        ("subjects1", _SUBJECTS1), ("subjects2", _SUBJECTS2),
        ("verbs1", _VERBS1), ("objects1", _OBJECTS1), ("objects2", _OBJECTS2),
        ("pads2", _PADS2), ("pads3", _PADS3), ("closers2", _CLOSERS2),
    ):
        expected = int(name[-1])
        for entry in pool:
            got = len(entry.split())
            if got != expected:
                raise AssertionError(
                    f"stego pool {name!r}: {entry!r} has {got} words, expected {expected}"
                )


_validate_pools()


#: Sentence templates: each is a tuple of (pool, word-count) slots.
#: The sum of the counts is the exact sentence length the template yields.
_TEMPLATES: dict[int, list[tuple]] = {}


def _register(*slots: tuple[str, int]) -> None:
    total = sum(count for _, count in slots)
    _TEMPLATES.setdefault(total, []).append(slots)


# Length 3
_register(("subjects2", 2), ("verbs1", 1))
# Length 4
_register(("subjects1", 1), ("verbs1", 1), ("objects2", 2))
_register(("subjects2", 2), ("verbs1", 1), ("objects1", 1))
# Length 5
_register(("subjects2", 2), ("verbs1", 1), ("objects2", 2))
_register(("openers1", 1), ("subjects1", 1), ("verbs1", 1), ("objects2", 2))
_register(("openers1", 1), ("subjects2", 2), ("verbs1", 1), ("objects1", 1))
# Length 6
_register(("openers1", 1), ("subjects2", 2), ("verbs1", 1), ("objects2", 2))
_register(("openers2", 2), ("subjects1", 1), ("verbs1", 1), ("objects2", 2))
_register(("openers2", 2), ("subjects2", 2), ("verbs1", 1), ("objects1", 1))
# Length 7
_register(("subjects2", 2), ("verbs1", 1), ("objects2", 2), ("pads2", 2))
_register(("openers2", 2), ("subjects2", 2), ("verbs1", 1), ("objects2", 2))
_register(("subjects2", 2), ("verbs1", 1), ("objects2", 2), ("closers2", 2))
# Length 8
_register(("subjects2", 2), ("verbs1", 1), ("objects2", 2), ("pads3", 3))
_register(("openers1", 1), ("subjects2", 2), ("verbs1", 1), ("objects2", 2), ("pads2", 2))
_register(("openers1", 1), ("subjects2", 2), ("verbs1", 1), ("objects2", 2), ("closers2", 2))
# Length 9
_register(("openers2", 2), ("subjects2", 2), ("verbs1", 1), ("objects2", 2), ("pads2", 2))
_register(("subjects2", 2), ("verbs1", 1), ("objects2", 2), ("pads2", 2), ("closers2", 2))
# Length 10
_register(("openers2", 2), ("subjects2", 2), ("verbs1", 1), ("objects2", 2), ("pads3", 3))
_register(("subjects2", 2), ("verbs1", 1), ("objects2", 2), ("pads3", 3), ("pads2", 2))
# Length 11
_register(("openers1", 1), ("subjects2", 2), ("verbs1", 1), ("objects2", 2), ("pads3", 3), ("pads2", 2))
_register(("subjects2", 2), ("verbs1", 1), ("objects2", 2), ("pads3", 3), ("closers2", 2))
# Length 12
_register(("openers2", 2), ("subjects2", 2), ("verbs1", 1), ("objects2", 2), ("pads3", 3), ("pads2", 2))

_POOLS = {
    "openers1": _OPENERS1, "openers2": _OPENERS2,
    "subjects1": _SUBJECTS1, "subjects2": _SUBJECTS2,
    "verbs1": _VERBS1, "objects1": _OBJECTS1, "objects2": _OBJECTS2,
    "pads2": _PADS2, "pads3": _PADS3, "closers2": _CLOSERS2,
}


def _build_sentence(rng: random.Random, words: int, excited: bool) -> str:
    """Build a grammatical sentence with exactly 'words' words.

    A template whose slot sizes sum to the target is chosen at random,
    then each slot is filled from its fragment pool. Lengths 1-2 use
    fixed interjections; lengths above the largest template are handled
    by the caller splitting the sum across several sentences.
    """
    if words <= 0:
        raise BookCipherError("Sentence length must be positive")
    if words == 1:
        core = [rng.choice(_SHORT1)]
    elif words == 2:
        core = rng.choice(_SHORT2).split()
    else:
        templates = _TEMPLATES.get(words)
        if not templates:
            raise BookCipherError(f"No sentence template for {words} words")
        slots = rng.choice(templates)
        core = []
        for pool_name, _count in slots:
            core.extend(rng.choice(_POOLS[pool_name]).split())
    punct = "!" if excited else "."
    text = " ".join(core)
    return text[0].upper() + text[1:] + punct


# ---------------------------------------------------------------------------
# Scheme 1: sentence-length arithmetic
# ---------------------------------------------------------------------------

#: Offset applied to every coordinate so -1 (space marker) encodes as 1.
OFFSET = 2

#: A single sentence may contribute at most this many words to a sum.
#: Must match the largest registered template length.
MAX_SENTENCE_WORDS = 12


def positions_to_cover_text(
    positions: Sequence[Position],
    seed: int = 0,
) -> str:
    """Encode positions as innocent prose.

    Each of the three coordinates of a position becomes a run of
    sentences whose word counts sum to coordinate + OFFSET; the final
    sentence of each run ends with '!'. Decoders without the convention
    see only mildly dramatic prose.
    """
    rng = random.Random(seed)
    sentences: list[str] = []
    for triple in positions:
        for value in triple:
            total = value + OFFSET
            if total < 1:
                raise BookCipherError(f"Coordinate {value} below the encodable minimum")
            parts = _split_sum(total, MAX_SENTENCE_WORDS)
            for i, part in enumerate(parts):
                excited = i == len(parts) - 1
                sentences.append(_build_sentence(rng, part, excited))
    return _wrap_sentences(sentences)


def _split_sum(total: int, max_part: int) -> list[int]:
    """Split 'total' into parts of at least 1 and at most max_part.

    The split is deterministic and avoids parts of 1 or 2 where possible,
    because one-word sentences read oddly.
    """
    if total <= max_part:
        return [total]
    parts: list[int] = []
    remaining = total
    while remaining > max_part:
        part = max_part - 5  # keep sentences a comfortable length
        parts.append(part)
        remaining -= part
    if remaining > 0:
        parts.append(remaining)
    return parts


_SENTENCE_RE = re.compile(r"[^.!?]*[.!?]")


def cover_text_to_positions(text: str) -> list[Position]:
    """Decode prose produced by positions_to_cover_text().

    Sentences are split on terminal punctuation; word counts are summed
    until an exclamation mark closes the run; each run yields one
    coordinate (sum - OFFSET); every three coordinates form a position.
    """
    sentences = [s.strip() for s in _SENTENCE_RE.findall(text) if s.strip()]
    values: list[int] = []
    acc = 0
    for s in sentences:
        words = len(s[:-1].split())
        acc += words
        if s.endswith("!"):
            values.append(acc - OFFSET)
            acc = 0
    if acc != 0:
        raise BookCipherError("Cover text ends mid-run: missing '!' terminator")
    if len(values) % 3 != 0:
        raise BookCipherError(
            f"Cover text decoded to {len(values)} coordinates, not a multiple of 3"
        )
    return [(values[i], values[i + 1], values[i + 2]) for i in range(0, len(values), 3)]


def _wrap_sentences(sentences: Sequence[str], width: int = 72) -> str:
    """Flow sentences into wrapped lines (paragraph style)."""
    lines: list[str] = []
    current: list[str] = []
    length = 0
    for s in sentences:
        if current and length + 1 + len(s) > width:
            lines.append(" ".join(current))
            current = [s]
            length = len(s)
        else:
            current.append(s)
            length += (1 if len(current) > 1 else 0) + len(s)
    if current:
        lines.append(" ".join(current))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Scheme 2: acrostic
# ---------------------------------------------------------------------------

#: Words keyed by first letter, for building acrostic lines.
_ACRO_WORDS: dict[str, list[str]] = {
    ch: [w for w in (
        "anchor", "bridge", "candle", "dawn", "ember", "ferry", "garden",
        "harbor", "island", "journey", "keeper", "lantern", "mirror",
        "needle", "orchard", "passage", "quarry", "river", "signal",
        "tower", "umbrella", "valley", "window", "xenon", "yonder", "zenith",
    ) if w.startswith(ch)] or ["note"]
    for ch in "abcdefghijklmnopqrstuvwxyz"
}


def message_to_acrostic(message: str, seed: int = 0) -> str:
    """Hide a message in the first letters of generated lines.

    Spaces in the message become blank lines, preserving word shape.
    Non-letters are dropped (acrostics carry letters only).
    """
    rng = random.Random(seed)
    lines: list[str] = []
    for ch in message.lower():
        if ch == " ":
            lines.append("")
            continue
        if not ch.isalpha():
            continue
        word = rng.choice(_ACRO_WORDS[ch])
        tail = rng.choice(_PADS3)
        line = f"{word.capitalize()} {tail}, {rng.choice(_CLOSERS2)}"
        lines.append(line)
    return "\n".join(lines) + "\n"


def acrostic_to_message(text: str) -> str:
    """Recover the message hidden in line-initial letters."""
    out: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            out.append(" ")
            continue
        out.append(line.strip()[0].lower())
    return "".join(out).strip()


# ---------------------------------------------------------------------------
# Scheme 3: null cipher (nth word)
# ---------------------------------------------------------------------------

def message_to_null_cipher(message: str, n: int = 5, seed: int = 0) -> str:
    """Hide a message in every Nth word of generated filler prose.

    The message characters are planted as words at positions n, 2n, 3n...
    (spelled out letter-names for clarity); all other words are filler.
    """
    if n < 2:
        raise BookCipherError("Null cipher stride must be at least 2")
    rng = random.Random(seed)
    symbols = [ch for ch in message.lower() if ch == " " or ch.isalnum()]
    words: list[str] = []
    filler_pool = [w for w in (_SUBJECTS2 + _OBJECTS2) for w in w.split()]
    idx = 0
    planted = 0
    while planted < len(symbols):
        slot = len(words) + 1
        if slot % n == 0:
            ch = symbols[planted]
            words.append(_LETTER_NAMES.get(ch, ch))
            planted += 1
        else:
            words.append(rng.choice(filler_pool))
        idx += 1
    return _wrap_sentences([" ".join(words) + "."], width=72)


_LETTER_NAMES = {
    " ": "pause",
    **{ch: ch for ch in "abcdefghijklmnopqrstuvwxyz0123456789"},
}


def null_cipher_to_message(text: str, n: int = 5) -> str:
    """Extract every Nth word from null-cipher text."""
    words = re.findall(r"[A-Za-z0-9]+", text)
    out: list[str] = []
    for i, w in enumerate(words, start=1):
        if i % n == 0:
            token = w.lower()
            out.append(" " if token == "pause" else token[:1])
    return "".join(out).rstrip()


# ---------------------------------------------------------------------------
# Cover-text quality metrics
# ---------------------------------------------------------------------------

def cover_text_stats(text: str) -> dict:
    """Measure how natural a piece of cover text looks.

    Returns sentence count, average/min/max sentence length in words,
    the fraction of sentences ending in '!' (the dramatic tell), and
    vocabulary richness. High exclamation fractions mean the hidden
    payload is dense.
    """
    sentences = [s.strip() for s in _SENTENCE_RE.findall(text) if s.strip()]
    lengths = [len(s[:-1].split()) for s in sentences]
    words = [w for s in sentences for w in s[:-1].lower().split()]
    excited = sum(1 for s in sentences if s.endswith("!"))
    return {
        "sentences": len(sentences),
        "avg_sentence_words": round(sum(lengths) / max(len(lengths), 1), 2),
        "min_sentence_words": min(lengths) if lengths else 0,
        "max_sentence_words": max(lengths) if lengths else 0,
        "exclamation_fraction": round(excited / max(len(sentences), 1), 3),
        "vocabulary_richness": round(len(set(words)) / max(len(words), 1), 3),
    }


__all__ = [
    "OFFSET", "MAX_SENTENCE_WORDS",
    "positions_to_cover_text", "cover_text_to_positions",
    "message_to_acrostic", "acrostic_to_message",
    "message_to_null_cipher", "null_cipher_to_message",
    "cover_text_stats",
]
