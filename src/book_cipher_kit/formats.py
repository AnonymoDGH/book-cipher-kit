"""formats -- every way to carry a list of positions.

The same positions can travel as plain triples, JSON, CSV, compact hex,
base64, or as a "page-letter" style reference list. Each format has a
serialize/deserialize pair and a magic marker so the loader can sniff which
format a file uses. The doctor command uses sniff() to accept anything.
"""

from __future__ import annotations

import base64
import csv
import io
import json
import struct
from typing import Iterable, Sequence

from .core import BookCipherError

Position = tuple[int, int, int]

#: Magic bytes/strings used to sniff formats.
MAGIC_JSON = "bookcipher-positions/1"
MAGIC_HEX = "BCPH1:"
MAGIC_B64 = "BCPB1:"
MAGIC_CSV_HEADER = ["line", "word", "char"]


# ---------------------------------------------------------------------------
# Plain text (the classic one-triple-per-line format)
# ---------------------------------------------------------------------------

def to_text(positions: Iterable[Position]) -> str:
    """One 'line.word.char' triple per line."""
    return "\n".join(f"{li}.{wi}.{ci}" for li, wi, ci in positions) + "\n"


def from_text(text: str) -> list[Position]:
    """Parse the classic format. Blank lines are skipped."""
    out: list[Position] = []
    for raw in text.strip().splitlines():
        part = raw.strip()
        if not part:
            continue
        fields = part.split(".")
        if len(fields) != 3:
            raise BookCipherError(f"Malformed position line: {raw!r}")
        try:
            out.append((int(fields[0]), int(fields[1]), int(fields[2])))
        except ValueError as exc:
            raise BookCipherError(f"Malformed position line: {raw!r}") from exc
    return out


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def to_json(positions: Iterable[Position], *, indent: int | None = None) -> str:
    """JSON array with a format marker and the position list."""
    payload = {
        "format": MAGIC_JSON,
        "count": 0,
        "positions": [[li, wi, ci] for li, wi, ci in positions],
    }
    payload["count"] = len(payload["positions"])
    return json.dumps(payload, indent=indent) + "\n"


def from_json(text: str) -> list[Position]:
    """Parse the JSON format, verifying the marker and count."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BookCipherError(f"Not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or data.get("format") != MAGIC_JSON:
        raise BookCipherError("JSON missing the bookcipher-positions marker")
    raw = data.get("positions")
    if not isinstance(raw, list):
        raise BookCipherError("JSON 'positions' must be a list")
    out: list[Position] = []
    for item in raw:
        if not (isinstance(item, list) and len(item) == 3
                and all(isinstance(x, int) for x in item)):
            raise BookCipherError(f"Bad position entry: {item!r}")
        out.append((item[0], item[1], item[2]))
    if "count" in data and data["count"] != len(out):
        raise BookCipherError(
            f"JSON count mismatch: header says {data['count']}, found {len(out)}"
        )
    return out


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def to_csv(positions: Iterable[Position]) -> str:
    """CSV with a header row -- spreadsheet friendly."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(MAGIC_CSV_HEADER)
    for li, wi, ci in positions:
        writer.writerow([li, wi, ci])
    return buf.getvalue()


def from_csv(text: str) -> list[Position]:
    """Parse the CSV format. The header row is required."""
    reader = csv.reader(io.StringIO(text.strip()))
    rows = list(reader)
    if not rows or [c.strip().lower() for c in rows[0]] != MAGIC_CSV_HEADER:
        raise BookCipherError("CSV missing the line,word,char header")
    out: list[Position] = []
    for i, row in enumerate(rows[1:], start=2):
        if not row or all(not c.strip() for c in row):
            continue
        if len(row) != 3:
            raise BookCipherError(f"CSV row {i} has {len(row)} columns, expected 3")
        try:
            out.append((int(row[0]), int(row[1]), int(row[2])))
        except ValueError as exc:
            raise BookCipherError(f"CSV row {i} is not numeric: {row!r}") from exc
    return out


# ---------------------------------------------------------------------------
# Compact binary-ish formats (hex and base64)
# ---------------------------------------------------------------------------

def _pack(positions: Sequence[Position]) -> bytes:
    """Pack positions as big-endian signed 32-bit triples.

    Signed because space markers use -1 for word and char.
    """
    out = bytearray()
    for li, wi, ci in positions:
        out.extend(struct.pack(">iii", li, wi, ci))
    return bytes(out)


def _unpack(blob: bytes) -> list[Position]:
    if len(blob) % 12 != 0:
        raise BookCipherError("Binary payload length is not a multiple of 12 bytes")
    out: list[Position] = []
    for i in range(0, len(blob), 12):
        li, wi, ci = struct.unpack(">iii", blob[i:i + 12])
        out.append((li, wi, ci))
    return out


def to_hex(positions: Sequence[Position]) -> str:
    """Compact hex encoding with a magic prefix -- one long line."""
    return MAGIC_HEX + _pack(positions).hex() + "\n"


def from_hex(text: str) -> list[Position]:
    text = text.strip()
    if not text.startswith(MAGIC_HEX):
        raise BookCipherError(f"Hex payload must start with {MAGIC_HEX!r}")
    try:
        blob = bytes.fromhex(text[len(MAGIC_HEX):])
    except ValueError as exc:
        raise BookCipherError("Hex payload is not valid hex") from exc
    return _unpack(blob)


def to_base64(positions: Sequence[Position], *, line_width: int = 64) -> str:
    """Base64 of the packed triples, wrapped, with a magic prefix line."""
    encoded = base64.b64encode(_pack(positions)).decode("ascii")
    lines = [encoded[i:i + line_width] for i in range(0, len(encoded), line_width)]
    return MAGIC_B64 + "\n" + "\n".join(lines) + "\n"


def from_base64(text: str) -> list[Position]:
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    if not lines or lines[0] != MAGIC_B64.rstrip():
        raise BookCipherError(f"Base64 payload must start with {MAGIC_B64!r}")
    try:
        blob = base64.b64decode("".join(lines[1:]), validate=True)
    except Exception as exc:
        raise BookCipherError("Base64 payload is not valid base64") from exc
    return _unpack(blob)


# ---------------------------------------------------------------------------
# Sniffing and unified load/save
# ---------------------------------------------------------------------------

FORMATS = {
    "text": (to_text, from_text),
    "json": (to_json, from_json),
    "csv": (to_csv, from_csv),
    "hex": (to_hex, from_hex),
    "base64": (to_base64, from_base64),
}


def sniff(text: str) -> str:
    """Guess the format of a positions payload.

    Returns one of the keys of FORMATS. The heuristics are ordered from
    most specific to most general; anything that looks like dotted triples
    falls through to 'text'.
    """
    stripped = text.strip()
    if stripped.startswith(MAGIC_HEX):
        return "hex"
    if stripped.startswith(MAGIC_B64):
        return "base64"
    if stripped.startswith("{"):
        return "json"
    first = stripped.splitlines()[0] if stripped else ""
    if first.lower().startswith("line,word,char"):
        return "csv"
    return "text"


def serialize(positions: Sequence[Position], fmt: str = "text", **kwargs) -> str:
    """Serialize positions in the requested format."""
    if fmt not in FORMATS:
        raise BookCipherError(f"Unknown format {fmt!r}. Use: {', '.join(FORMATS)}")
    return FORMATS[fmt][0](positions, **kwargs) if fmt in ("json", "base64") else FORMATS[fmt][0](positions)


def deserialize(text: str, fmt: str | None = None) -> list[Position]:
    """Deserialize positions, sniffing the format when not given."""
    fmt = fmt or sniff(text)
    if fmt not in FORMATS:
        raise BookCipherError(f"Unknown format {fmt!r}. Use: {', '.join(FORMATS)}")
    return FORMATS[fmt][1](text)


__all__ = [
    "MAGIC_JSON", "MAGIC_HEX", "MAGIC_B64", "MAGIC_CSV_HEADER",
    "to_text", "from_text", "to_json", "from_json",
    "to_csv", "from_csv", "to_hex", "from_hex", "to_base64", "from_base64",
    "FORMATS", "sniff", "serialize", "deserialize",
]
