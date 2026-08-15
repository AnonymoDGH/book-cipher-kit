"""doctor -- diagnose why a book cipher session is failing.

When a decode fails in the field, the cause is almost always one of a
small set of problems: wrong edition, wrong format, truncated payload,
wrong passphrase, or a book that cannot encode the message. The doctor
runs a battery of checks and reports each one with a clear verdict, so
the fix is obvious without reading source code.

The doctor never raises for expected conditions; it returns a structured
report. Callers decide how to present it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from . import formats
from .core import (
    BookCipherError,
    coverage,
    fingerprint,
    load_book,
    validate_positions,
    word_count,
)

CHECK_OK = "ok"
CHECK_WARN = "warn"
CHECK_FAIL = "fail"


def _check(name: str, status: str, detail: str) -> dict:
    return {"check": name, "status": status, "detail": detail}


def diagnose_book(path: str | Path) -> list[dict]:
    """Run every book-side check and return the list of results."""
    checks: list[dict] = []
    p = Path(path)

    if not p.exists():
        checks.append(_check("book exists", CHECK_FAIL, f"{p} not found"))
        return checks
    checks.append(_check("book exists", CHECK_OK, str(p)))

    try:
        lines = load_book(p)
    except UnicodeDecodeError as exc:
        checks.append(_check("book readable", CHECK_FAIL, f"not UTF-8: {exc}"))
        return checks
    checks.append(_check("book readable", CHECK_OK, f"{len(lines)} lines"))

    words = word_count(lines)
    if words == 0:
        checks.append(_check("book has words", CHECK_FAIL, "the book is empty"))
        return checks
    if words < 200:
        checks.append(_check(
            "book has words", CHECK_WARN,
            f"only {words} words -- small books have poor coverage",
        ))
    else:
        checks.append(_check("book has words", CHECK_OK, f"{words} words"))

    cov = coverage(lines)
    if cov["percent"] == 100:
        checks.append(_check("alphabet coverage", CHECK_OK, "all 26 letters present"))
    elif cov["percent"] >= 90:
        checks.append(_check(
            "alphabet coverage", CHECK_WARN,
            f"{cov['percent']}% -- missing: {''.join(cov['missing'])}",
        ))
    else:
        checks.append(_check(
            "alphabet coverage", CHECK_FAIL,
            f"{cov['percent']}% -- missing: {''.join(cov['missing'])}",
        ))

    fp = fingerprint(lines)
    checks.append(_check("fingerprint", CHECK_OK, fp[:16] + "..."))

    blank_ratio = sum(1 for ln in lines if not ln.strip()) / max(len(lines), 1)
    if blank_ratio > 0.5:
        checks.append(_check(
            "line density", CHECK_WARN,
            f"{round(blank_ratio * 100)}% blank lines -- check the file is not corrupted",
        ))
    else:
        checks.append(_check("line density", CHECK_OK, f"{round(blank_ratio * 100)}% blank"))

    return checks


def diagnose_positions_text(text: str) -> list[dict]:
    """Diagnose a positions payload given as text."""
    checks: list[dict] = []
    if not text.strip():
        checks.append(_check("payload present", CHECK_FAIL, "payload is empty"))
        return checks
    checks.append(_check("payload present", CHECK_OK, f"{len(text)} chars"))

    fmt = formats.sniff(text)
    checks.append(_check("format detected", CHECK_OK, fmt))

    try:
        positions = formats.deserialize(text, fmt)
    except BookCipherError as exc:
        checks.append(_check("payload parses", CHECK_FAIL, str(exc)))
        return checks
    checks.append(_check("payload parses", CHECK_OK, f"{len(positions)} positions"))

    if not positions:
        checks.append(_check("payload non-empty", CHECK_WARN, "zero positions decoded"))
        return checks

    spaces = sum(1 for p in positions if p[1] == -1)
    real = len(positions) - spaces
    checks.append(_check(
        "message shape", CHECK_OK,
        f"{real} characters, {spaces} spaces",
    ))

    negatives = [p for p in positions if p[0] < 0 or p[2] < -1]
    if negatives:
        checks.append(_check(
            "coordinate sanity", CHECK_FAIL,
            f"{len(negatives)} positions have negative line/char values",
        ))
    else:
        checks.append(_check("coordinate sanity", CHECK_OK, "no negative line/char values"))

    return checks


def diagnose_pair(
    book_path: str | Path, positions_text: str
) -> list[dict]:
    """Diagnose a book and a payload together -- the full decode path."""
    checks = diagnose_book(book_path)
    checks.extend(diagnose_positions_text(positions_text))

    if any(c["status"] == CHECK_FAIL for c in checks):
        checks.append(_check(
            "decode", CHECK_FAIL, "earlier checks failed; fix those first",
        ))
        return checks

    lines = load_book(book_path)
    try:
        positions = formats.deserialize(positions_text)
    except BookCipherError as exc:
        checks.append(_check("decode", CHECK_FAIL, str(exc)))
        return checks

    problems = validate_positions(positions, lines)
    if problems:
        checks.append(_check(
            "positions fit book", CHECK_FAIL,
            f"{len(problems)} of {len(positions)} positions out of range; "
            f"first: {problems[0]}",
        ))
        checks.append(_check(
            "likely cause", CHECK_WARN,
            "wrong edition or a re-wrapped book -- compare fingerprints",
        ))
    else:
        checks.append(_check("positions fit book", CHECK_OK, "all positions in range"))
        checks.append(_check("decode", CHECK_OK, "payload decodes cleanly"))

    return checks


def format_report(checks: Sequence[dict]) -> str:
    """Render a check list as aligned, human-readable text."""
    icons = {CHECK_OK: "[+]", CHECK_WARN: "[~]", CHECK_FAIL: "[-]"}
    width = max(len(c["check"]) for c in checks) if checks else 0
    lines = []
    for c in checks:
        lines.append(f"{icons[c['status']]} {c['check']:<{width}}  {c['detail']}")
    return "\n".join(lines)


def report_is_healthy(checks: Sequence[dict]) -> bool:
    """True when no check failed (warnings are tolerated)."""
    return all(c["status"] != CHECK_FAIL for c in checks)


__all__ = [
    "CHECK_OK", "CHECK_WARN", "CHECK_FAIL",
    "diagnose_book", "diagnose_positions_text", "diagnose_pair",
    "format_report", "report_is_healthy",
]
