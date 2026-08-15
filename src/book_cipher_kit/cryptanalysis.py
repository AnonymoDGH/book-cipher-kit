"""cryptanalysis -- attack tools for measuring book-cipher strength.

A kit that only encodes is half a kit. This module implements the attacks
an analyst would run against a book cipher, so you can measure how much
your own usage leaks. All attacks are read-only and work on position lists
or on plaintext, never on secrets you do not have.

Provided:

* frequency_profile   -- letter frequencies of a plaintext vs. English
* index_of_coincidence -- the classic IoC, distinguishes text from noise
* kasiski_runs        -- repeated n-gram runs in a plaintext
* position_leakage    -- how much a position list reveals structurally
* hill_climb_words    -- recover likely word lengths from space markers
* entropy_rate        -- Shannon entropy of a symbol stream
* english_score       -- how English-like a candidate plaintext is

These are the same tools used to break classical ciphers, repurposed here
as a defensive yardstick.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable, Sequence

from .core import decode

Position = tuple[int, int, int]

#: English letter frequencies (percent), standard reference table.
ENGLISH_FREQ = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702,
    "f": 2.228, "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153,
    "k": 0.772, "l": 4.025, "m": 2.406, "n": 6.749, "o": 7.507,
    "p": 1.929, "q": 0.095, "r": 5.987, "s": 6.327, "t": 9.056,
    "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150, "y": 1.974,
    "z": 0.074,
}

#: Common English bigrams for scoring.
COMMON_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
    "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
    "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
}


def frequency_profile(text: str) -> dict[str, float]:
    """Letter frequencies (percent) of the alphabetic content of text."""
    letters = [c for c in text.lower() if c.isalpha()]
    total = len(letters)
    if total == 0:
        return {}
    counts = Counter(letters)
    return {ch: round(100 * counts.get(ch, 0) / total, 3) for ch in "abcdefghijklmnopqrstuvwxyz"}


def chi_squared_english(text: str) -> float:
    """Chi-squared distance of text's letter frequencies from English.

    Lower is more English-like. Random text scores in the hundreds;
    real English typically under 30 for a decent sample.
    """
    profile = frequency_profile(text)
    if not profile:
        return float("inf")
    letters = [c for c in text.lower() if c.isalpha()]
    total = len(letters)
    chi2 = 0.0
    for ch, expected_pct in ENGLISH_FREQ.items():
        expected = expected_pct / 100 * total
        observed = letters.count(ch)
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    return round(chi2, 2)


def index_of_coincidence(text: str) -> float:
    """Friedman's Index of Coincidence.

    English prose ~ 0.065-0.070; uniform random ~ 0.038. A book cipher's
    plaintext is real prose, so its IoC is high -- but the position list
    itself should look random. Compare the two to see the leak.
    """
    letters = [c for c in text.lower() if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    numerator = sum(c * (c - 1) for c in counts.values())
    return round(numerator / (n * (n - 1)), 5)


def entropy_rate(symbols: Iterable) -> float:
    """Shannon entropy (bits per symbol) of a discrete stream."""
    seq = list(symbols)
    n = len(seq)
    if n == 0:
        return 0.0
    counts = Counter(seq)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 4)


def english_score(text: str) -> float:
    """Heuristic 0-1 score of how English-like a plaintext is.

    Combines bigram hits and vowel ratio. Useful for ranking candidate
    decryptions during an attack.
    """
    letters = [c for c in text.lower() if c.isalpha()]
    if len(letters) < 4:
        return 0.0
    bigrams = [text[i:i + 2].lower() for i in range(len(text) - 1)]
    alpha_bigrams = [b for b in bigrams if b.isalpha()]
    if not alpha_bigrams:
        return 0.0
    bigram_hits = sum(1 for b in alpha_bigrams if b in COMMON_BIGRAMS) / len(alpha_bigrams)
    vowels = sum(1 for c in letters if c in "aeiou") / len(letters)
    vowel_score = 1.0 - abs(vowels - 0.38) / 0.38  # English ~38% vowels
    return round(0.6 * bigram_hits + 0.4 * max(vowel_score, 0.0), 4)


def kasiski_runs(text: str, n: int = 3, min_count: int = 2) -> list[dict]:
    """Find repeated n-grams (Kasiski examination).

    Repeated trigrams at regular spacing hint at structure. For a book
    cipher plaintext this is normal prose; for a position stream it should
    be near-empty.
    """
    clean = "".join(c for c in text.lower() if c.isalpha())
    if len(clean) < n:
        return []
    counts: dict[str, list[int]] = {}
    for i in range(len(clean) - n + 1):
        gram = clean[i:i + n]
        counts.setdefault(gram, []).append(i)
    runs = []
    for gram, positions in counts.items():
        if len(positions) >= min_count:
            gaps = [positions[i + 1] - positions[i] for i in range(len(positions) - 1)]
            runs.append({"gram": gram, "count": len(positions), "gaps": gaps})
    runs.sort(key=lambda r: -r["count"])
    return runs[:50]


def position_leakage(positions: Sequence[Position]) -> dict:
    """Quantify what the raw position list leaks without the book.

    Measures entropy of the line/word/char streams and the IoC of the
    derived character stream. A well-spread message has high line entropy;
    a concentrated one has low.
    """
    real = [p for p in positions if p[1] != -1]
    if not real:
        return {"positions": 0}
    line_entropy = entropy_rate(p[0] for p in real)
    word_entropy = entropy_rate(p[1] for p in real)
    char_entropy = entropy_rate(p[2] for p in real)
    # Reconstruct the char-index stream; its IoC should be low if the
    # encoder spreads well, but it mirrors plaintext letter repetition.
    char_stream = [p[2] for p in real]
    return {
        "positions": len(real),
        "line_entropy": line_entropy,
        "word_entropy": word_entropy,
        "char_entropy": char_entropy,
        "char_index_ioc": round(
            _ioc_of_ints(char_stream), 5
        ),
        "note": "High line entropy = well spread. char_index_ioc near "
                "plaintext IoC means char choices track letter frequency.",
    }


def _ioc_of_ints(values: Sequence[int]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    counts = Counter(values)
    numerator = sum(c * (c - 1) for c in counts.values())
    return numerator / (n * (n - 1))


def hill_climb_words(positions: Sequence[Position]) -> dict:
    """Recover the plaintext's word-length structure from space markers.

    Space markers are the one part of a book cipher that needs no book to
    read: their positions in the list directly give word boundaries. This
    is the single biggest structural leak, and it is recoverable by anyone
    who intercepts the positions.
    """
    segments: list[int] = []
    current = 0
    for p in positions:
        if p[1] == -1:
            segments.append(current)
            current = 0
        else:
            current += 1
    segments.append(current)
    word_lengths = [s for s in segments if s > 0]
    return {
        "word_count": len(word_lengths),
        "word_lengths": word_lengths,
        "total_chars": sum(word_lengths),
        "signature": "-".join(str(w) for w in word_lengths),
        "note": "Word-length signatures narrow candidate plaintexts "
                "dramatically (e.g. 3-2-4 matches 'the us navy').",
    }


def attack_report(
    positions: Sequence[Position],
    lines: Sequence[str] | None = None,
) -> dict:
    """Aggregate every read-only attack into one defensive report.

    If the book is supplied, the plaintext is decoded and its classical
    statistics are included so you can compare plaintext vs. position
    leakage side by side.
    """
    report: dict = {
        "position_leakage": position_leakage(positions),
        "word_structure": hill_climb_words(positions),
    }
    if lines is not None:
        try:
            plaintext = decode(positions, lines)
        except Exception:
            plaintext = None
        if plaintext is not None:
            report["plaintext"] = {
                "text": plaintext,
                "iocs": index_of_coincidence(plaintext),
                "chi_squared": chi_squared_english(plaintext),
                "english_score": english_score(plaintext),
                "entropy": entropy_rate([c for c in plaintext.lower() if c.isalpha()]),
            }
    return report


__all__ = [
    "ENGLISH_FREQ", "COMMON_BIGRAMS",
    "frequency_profile", "chi_squared_english", "index_of_coincidence",
    "entropy_rate", "english_score", "kasiski_runs", "position_leakage",
    "hill_climb_words", "attack_report",
]
