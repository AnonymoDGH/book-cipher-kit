"""analysis -- measure the security properties of a book cipher session.

A book cipher's strength depends on how the positions are used. This module
answers the questions an analyst would ask:

* How much of the book does a message touch? (position spread)
* Are any positions reused? (reuse leaks character equality)
* What does the line-usage histogram look like? (hot lines are a tell)
* How much entropy does the position list carry?
* What can an attacker learn WITHOUT the book? (structure analysis)
* What can an attacker learn WITH a candidate book? (edition attack)

Everything is read-only and deterministic.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable, Sequence

from .core import decode, validate_positions

Position = tuple[int, int, int]


def position_spread(positions: Sequence[Position]) -> dict:
    """How a message's positions are distributed across the book.

    A message that draws all its characters from one line is far more
    vulnerable than one spread across the whole book: an attacker who
    guesses the edition only has to search that line.
    """
    real = [p for p in positions if p[1] != -1]
    if not real:
        return {"positions": len(positions), "real_positions": 0}
    lines_used = {p[0] for p in real}
    words_used = {(p[0], p[1]) for p in real}
    line_counts = Counter(p[0] for p in real)
    hottest_line, hottest_count = line_counts.most_common(1)[0]
    return {
        "positions": len(positions),
        "real_positions": len(real),
        "lines_used": len(lines_used),
        "words_used": len(words_used),
        "hottest_line": hottest_line,
        "hottest_line_hits": hottest_count,
        "concentration": round(hottest_count / len(real), 3),
    }


def reuse_report(positions: Sequence[Position]) -> dict:
    """Detect positions used more than once.

    Reusing a position is a real leak: it tells an attacker that two
    message characters are identical, shrinking the search space. The
    report lists every reused triple and how many times it appears.
    """
    counts = Counter(p for p in positions if p[1] != -1)
    reused = {p: c for p, c in counts.items() if c > 1}
    return {
        "total": len(positions),
        "unique": len(counts),
        "reused_positions": len(reused),
        "reuse_fraction": round(
            sum(c - 1 for c in reused.values()) / max(len(positions), 1), 3
        ),
        "details": [
            {"position": list(p), "count": c}
            for p, c in sorted(reused.items(), key=lambda kv: -kv[1])
        ],
    }


def line_histogram(positions: Sequence[Position]) -> list[tuple[int, int]]:
    """(line, hits) pairs sorted by line number, for real positions."""
    counts = Counter(p[0] for p in positions if p[1] != -1)
    return sorted(counts.items())


def position_entropy(positions: Sequence[Position], book_lines: int) -> dict:
    """Entropy of the position list under a simple model.

    Each real position is assumed uniform over (book_lines * avg_words *
    avg_chars) possibilities; the reported bits are the ideal entropy of
    the list. Compare against the message length to see how much
    redundancy the book adds.
    """
    real = [p for p in positions if p[1] != -1]
    if not real or book_lines <= 0:
        return {"bits": 0.0, "bits_per_char": 0.0}
    # Rough model: average word per line and char per word from the data.
    words = {(p[0], p[1]) for p in real}
    chars = len(real)
    space_per_line = max(len(words) / book_lines, 1.0)
    per_position = math.log2(max(book_lines * space_per_line * 5, 2))
    bits = per_position * chars
    return {
        "bits": round(bits, 1),
        "bits_per_char": round(per_position, 2),
        "model": "uniform over lines x observed words x ~5 chars",
    }


def structure_analysis(positions: Sequence[Position]) -> dict:
    """What an attacker can learn WITHOUT the book.

    Even raw triples leak structure: message length, word boundaries
    (space markers), and the maximum line/word/char values, which bound
    the size of the book. This report makes those leaks explicit.
    """
    spaces = [i for i, p in enumerate(positions) if p[1] == -1]
    word_lengths: list[int] = []
    current = 0
    for p in positions:
        if p[1] == -1:
            word_lengths.append(current)
            current = 0
        else:
            current += 1
    word_lengths.append(current)
    max_line = max((p[0] for p in positions if p[1] != -1), default=0)
    max_word = max((p[1] for p in positions if p[1] != -1), default=0)
    max_char = max((p[2] for p in positions if p[1] != -1), default=0)
    return {
        "message_length": sum(1 for p in positions if p[1] != -1),
        "word_count": len([w for w in word_lengths if w > 0]),
        "word_lengths": word_lengths,
        "space_positions": spaces,
        "book_bounds": {
            "min_lines": max_line + 1,
            "min_words_on_some_line": max_word + 1,
            "min_word_length": max_char + 1,
        },
        "note": "Word lengths alone narrow the plaintext heavily; "
                "this is why positions should travel encrypted or as prose.",
    }


def edition_attack(
    positions: Sequence[Position],
    candidate_lines: Sequence[str],
) -> dict:
    """Simulate an attacker trying a candidate book.

    Validates the positions against the candidate. If every position fits,
    the candidate decodes the message and the attack succeeds. The report
    says how many positions fit and, when all fit, shows the plaintext.
    """
    problems = validate_positions(positions, candidate_lines)
    fit = len(positions) - len(problems)
    result = {
        "candidate_lines": len(candidate_lines),
        "positions": len(positions),
        "fit": fit,
        "fit_fraction": round(fit / max(len(positions), 1), 3),
        "success": not problems,
        "plaintext": None,
    }
    if not problems:
        try:
            result["plaintext"] = decode(positions, candidate_lines)
        except Exception:
            result["success"] = False
    return result


def compare_sessions(
    a: Sequence[Position], b: Sequence[Position]
) -> dict:
    """Compare two position lists sent with the same book.

    Shared positions across two messages are gold for an attacker: each
    shared triple means the same character appears at both spots. This
    is the classic depth attack on book ciphers.
    """
    set_a = {p for p in a if p[1] != -1}
    set_b = {p for p in b if p[1] != -1}
    shared = set_a & set_b
    return {
        "a_positions": len(set_a),
        "b_positions": len(set_b),
        "shared_positions": len(shared),
        "shared_fraction_of_smaller": round(
            len(shared) / max(min(len(set_a), len(set_b)), 1), 3
        ),
        "shared": [list(p) for p in sorted(shared)],
    }


def security_report(
    positions: Sequence[Position],
    book_lines: Sequence[str] | None = None,
) -> dict:
    """Aggregate every analysis above into one report with a verdict."""
    spread = position_spread(positions)
    reuse = reuse_report(positions)
    structure = structure_analysis(positions)
    entropy = position_entropy(positions, len(book_lines) if book_lines else 0)
    warnings: list[str] = []
    if reuse["reused_positions"]:
        warnings.append(
            f"{reuse['reused_positions']} positions are reused -- "
            "reused positions leak character equality."
        )
    if spread.get("concentration", 0) > 0.5:
        warnings.append(
            "More than half the characters come from one line -- "
            "the message is concentrated and easier to locate."
        )
    if structure["message_length"] > 0 and not book_lines:
        warnings.append(
            "No book supplied: only structure analysis was possible."
        )
    verdict = "weak" if len(warnings) >= 2 else ("fair" if warnings else "strong")
    return {
        "spread": spread,
        "reuse": reuse,
        "structure": structure,
        "entropy": entropy,
        "warnings": warnings,
        "verdict": verdict,
    }


__all__ = [
    "position_spread", "reuse_report", "line_histogram",
    "position_entropy", "structure_analysis", "edition_attack",
    "compare_sessions", "security_report",
]
