"""bench -- benchmark and capacity planning for book cipher sessions.

Answers the practical questions before a operation:

* How long does indexing take for a book of N words?
* How many messages of a given size can one book carry?
* What is the bits-per-character of the position stream?
* How large is the payload in each transport format?

All measurements are deterministic-friendly: timings use time.perf_counter
and the module never sleeps. The capacity planner is pure arithmetic, so
it is exact and testable.
"""

from __future__ import annotations

import time
from typing import Sequence

from . import formats
from .core import coverage, encode, fingerprint, word_count
from .index import BookIndex

Position = tuple[int, int, int]


def time_indexing(lines: Sequence[str], repeats: int = 3) -> dict:
    """Measure BookIndex construction time.

    Returns best/mean seconds over 'repeats' runs. Best is the usual
    number to quote; mean shows variance.
    """
    times: list[float] = []
    for _ in range(repeats):
        start = time.perf_counter()
        BookIndex(lines)
        times.append(time.perf_counter() - start)
    return {
        "best_seconds": round(min(times), 6),
        "mean_seconds": round(sum(times) / len(times), 6),
        "repeats": repeats,
        "words": word_count(lines),
    }


def time_encoding(lines: Sequence[str], message: str, seed: int = 0,
                  repeats: int = 3) -> dict:
    """Measure encode() time for one message, index built once."""
    index = BookIndex(lines)
    times: list[float] = []
    for i in range(repeats):
        start = time.perf_counter()
        index.encode(message, seed=seed + i)
        times.append(time.perf_counter() - start)
    return {
        "best_seconds": round(min(times), 6),
        "mean_seconds": round(sum(times) / len(times), 6),
        "message_chars": len(message),
        "chars_per_second": round(len(message) / max(min(times), 1e-9)),
    }


def payload_sizes(positions: Sequence[Position]) -> dict[str, int]:
    """Byte size of the position list in every transport format."""
    return {
        fmt: len(formats.serialize(positions, fmt).encode("utf-8"))
        for fmt in formats.FORMATS
    }


def capacity_plan(lines: Sequence[str], message_chars: int,
                  safety_factor: float = 2.0) -> dict:
    """Plan how many messages of a given size one book can carry.

    The one-book-one-range discipline means each message should draw from
    its own lines. The plan divides the book's lines into slices large
    enough to carry the message with a safety factor, and reports how many
    slices fit.

    Parameters
    ----------
    message_chars:
        Characters per message (spaces included).
    safety_factor:
        Multiply the minimum lines needed by this factor so rare letters
        still have room. 2.0 is a comfortable default.
    """
    if message_chars <= 0:
        raise ValueError("message_chars must be positive")
    index = BookIndex(lines)
    total_lines = len([ln for ln in lines if ln.split()])
    cov = index.coverage_report()
    # Rough model: a line carries ~ (encodable positions / lines) chars,
    # but a message needs distinct words; use words per line instead.
    words = index.words()
    words_per_line = max(words / max(total_lines, 1), 1.0)
    # Each character needs one word occurrence; with the safety factor:
    lines_per_message = max(1, int(message_chars / words_per_line * safety_factor) + 1)
    messages = total_lines // lines_per_message
    return {
        "book_lines": total_lines,
        "book_words": words,
        "alphabet_coverage": cov["percent"],
        "message_chars": message_chars,
        "lines_per_message": lines_per_message,
        "messages_per_book": messages,
        "total_chars_per_book": messages * message_chars,
        "fingerprint": fingerprint(lines)[:16],
    }


def bits_per_character(lines: Sequence[str], sample: str = "the quick brown fox jumps over the lazy dog",
                       seed: int = 0) -> dict:
    """Estimate the entropy carried per encoded character.

    Encodes a sample message and measures the Shannon entropy of the
    resulting line/word/char streams as a proxy for bits per character.
    """
    from .cryptanalysis import entropy_rate
    index = BookIndex(lines)
    positions = index.encode(sample, seed=seed)
    real = [p for p in positions if p[1] != -1]
    if not real:
        return {"bits_per_char": 0.0}
    line_ent = entropy_rate(p[0] for p in real)
    word_ent = entropy_rate(p[1] for p in real)
    char_ent = entropy_rate(p[2] for p in real)
    return {
        "sample_chars": len(real),
        "line_entropy": line_ent,
        "word_entropy": word_ent,
        "char_entropy": char_ent,
        "bits_per_char": round(line_ent + word_ent + char_ent, 3),
    }


def full_benchmark(lines: Sequence[str], message: str = "benchmark message for the book cipher",
                   seed: int = 0) -> dict:
    """Run every benchmark and return one combined report."""
    index = BookIndex(lines)
    positions = index.encode(message, seed=seed)
    return {
        "indexing": time_indexing(lines),
        "encoding": time_encoding(lines, message, seed=seed),
        "payload_sizes": payload_sizes(positions),
        "capacity": capacity_plan(lines, len(message)),
        "bits_per_character": bits_per_character(lines, message, seed=seed),
        "coverage": coverage(lines),
    }


__all__ = [
    "time_indexing", "time_encoding", "payload_sizes",
    "capacity_plan", "bits_per_character", "full_benchmark",
]
