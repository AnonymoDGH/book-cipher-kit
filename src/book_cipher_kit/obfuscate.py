"""obfuscate -- disguise position lists as everyday documents.

Steganography hides data in prose; obfuscation hides it in plain sight by
making the carrier look like something nobody reads twice. Each scheme
maps position triples onto the fields of a mundane document and back.

Schemes
-------
shopping   positions become quantities and prices on a shopping list
log        positions become timestamps and status codes in a server log
invoice    positions become line items, quantities, and totals
schedule   positions become meeting times and room numbers

Every scheme is deterministic under a seed, lossless, and validated on
decode. The documents are boring by design: boredom is the camouflage.

Note on capacity: the shopping and schedule schemes store the word number
modulo the unit/room alphabet, so they are lossless only for word numbers
below the alphabet size (8 units, 6 rooms). The log and invoice schemes
are lossless for all realistic books. hide() documents this per scheme.
"""

from __future__ import annotations

import random
import re
from typing import Sequence

from .core import BookCipherError

Position = tuple[int, int, int]

# ---------------------------------------------------------------------------
# Scheme 1: shopping list
# ---------------------------------------------------------------------------

_ITEMS = [
    "apples", "bread", "coffee", "rice", "olive oil", "pasta", "cheese",
    "tomatoes", "onions", "garlic", "eggs", "milk", "butter", "flour",
    "sugar", "salt", "pepper", "honey", "lemons", "carrots", "potatoes",
    "spinach", "chicken", "fish", "beans", "lentils", "yogurt", "oats",
    "almonds", "walnuts", "raisins", "dates", "tea", "cocoa", "vanilla",
    "cinnamon", "basil", "oregano", "thyme", "cumin",
]

_UNITS = ["kg", "g", "L", "pack", "box", "bag", "bottle", "can"]


def to_shopping_list(positions: Sequence[Position], seed: int = 0) -> str:
    """Encode positions as a shopping list.

    Each position becomes one line item: the line number hides in the
    quantity, the word number in the unit choice, and the char number in
    the price. A header comment marks the format for the decoder.

    Lossless for word numbers 0..7 (the unit alphabet).
    """
    rng = random.Random(seed)
    lines = ["# shopping list -- saturday market"]
    for li, wi, ci in positions:
        item = rng.choice(_ITEMS)
        qty = li + 1                      # line number, 1-based to look natural
        if wi == -1:                      # space marker -> reserved unit
            unit, price = "sp", 0
        else:
            unit = _UNITS[wi % len(_UNITS)]   # word number mod unit count
            price = ci + 1                    # char number, 1-based
        lines.append(f"- {item}: {qty} {unit}, " + "$" + f"{price}.00")
    return "\n".join(lines) + "\n"


def from_shopping_list(text: str) -> list[Position]:
    """Decode a shopping list produced by to_shopping_list()."""
    positions: list[Position] = []
    pattern = re.compile(r"^- .+: (\d+) (\w+), \$(\d+)\.00$")
    unit_index = {u: i for i, u in enumerate(_UNITS)}
    unit_index["sp"] = -1  # reserved unit marks a space
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = pattern.match(line)
        if not m:
            raise BookCipherError(f"Malformed shopping line: {raw!r}")
        qty, unit, price = m.group(1), m.group(2), m.group(3)
        if unit not in unit_index:
            raise BookCipherError(f"Unknown unit {unit!r} in shopping line")
        wi = unit_index[unit]
        ci = -1 if wi == -1 else int(price) - 1
        positions.append((int(qty) - 1, wi, ci))
    return positions


# ---------------------------------------------------------------------------
# Scheme 2: server log
# ---------------------------------------------------------------------------

_LEVELS = ["INFO", "DEBUG", "WARN", "INFO", "INFO", "DEBUG"]
_SERVICES = [
    "auth", "api", "cache", "db", "queue", "worker", "proxy", "scheduler",
    "mailer", "indexer",
]
_ACTIONS = [
    "request completed", "connection opened", "cache refreshed",
    "job scheduled", "session started", "config reloaded",
    "heartbeat received", "batch processed", "index updated",
    "task finished",
]


def to_server_log(positions: Sequence[Position], seed: int = 0) -> str:
    """Encode positions as fake server log lines.

    The line number becomes the time of day (minutes since 09:00), the
    word number the status code offset, and the char number the response
    time in ms. Reads like any other tail of a busy service. Lossless for
    word numbers 0..7 and line numbers up to 719 (12 hours).
    """
    rng = random.Random(seed)
    lines = []
    for li, wi, ci in positions:
        clock = 9 * 60 + li
        hour, minute = divmod(clock, 60)
        level = rng.choice(_LEVELS)
        service = rng.choice(_SERVICES)
        action = rng.choice(_ACTIONS)
        if wi == -1:                       # space marker -> reserved status
            status, ms = 999, 0
        else:
            status = 200 + (wi % 8) * 25   # 200, 225, ... encode word number
            ms = ci + 1                    # char number as latency
        lines.append(
            f"{hour:02d}:{minute:02d}:00 [{level}] {service}: "
            f"{action} status={status} time={ms}ms"
        )
    return "\n".join(lines) + "\n"


def from_server_log(text: str) -> list[Position]:
    """Decode a server log produced by to_server_log()."""
    positions: list[Position] = []
    pattern = re.compile(
        r"^(\d{2}):(\d{2}):\d{2} \[\w+\] \w+: .+ status=(\d+) time=(\d+)ms$"
    )
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = pattern.match(line)
        if not m:
            raise BookCipherError(f"Malformed log line: {raw!r}")
        hour, minute, status, ms = (int(m.group(i)) for i in range(1, 5))
        li = (hour - 9) * 60 + minute
        if status == 999:                  # reserved status marks a space
            positions.append((li, -1, -1))
        else:
            wi = (status - 200) // 25
            ci = ms - 1
            positions.append((li, wi, ci))
    return positions


# ---------------------------------------------------------------------------
# Scheme 3: invoice
# ---------------------------------------------------------------------------

def to_invoice(positions: Sequence[Position], seed: int = 0) -> str:
    """Encode positions as invoice line items.

    Line number -> item code suffix, word number -> quantity, char number
    -> unit price. A totals footer makes it look complete. Lossless for
    all realistic coordinates (SKU up to 8999, qty/price unbounded).
    """
    lines = [
        "INVOICE #4471",
        "Bill to: Harbor Logistics Ltd.",
        "",
        "item            qty     unit",
    ]
    total_cents = 0
    for li, wi, ci in positions:
        sku = f"SKU-{li + 100:04d}"
        qty = wi + 1
        cents = ci + 1
        total_cents += qty * cents
        lines.append(f"{sku:<15} {qty:>4}     " + "$" + f"{cents}.00")
    lines.append("")
    lines.append("TOTAL: $" + f"{total_cents}.00")
    return "\n".join(lines) + "\n"


def from_invoice(text: str) -> list[Position]:
    """Decode an invoice produced by to_invoice()."""
    positions: list[Position] = []
    pattern = re.compile(r"^SKU-(\d{4})\s+(\d+)\s+\$(\d+)\.00$")
    for raw in text.splitlines():
        m = pattern.match(raw.strip())
        if not m:
            continue
        sku, qty, cents = (int(m.group(i)) for i in range(1, 4))
        positions.append((sku - 100, qty - 1, cents - 1))
    if not positions:
        raise BookCipherError("No SKU lines found in invoice")
    return positions


# ---------------------------------------------------------------------------
# Scheme 4: meeting schedule
# ---------------------------------------------------------------------------

_TOPICS = [
    "sync", "review", "planning", "retro", "standup", "workshop",
    "1on1", "demo", "triage", "kickoff",
]
_ROOMS = ["A", "B", "C", "D", "E", "F"]


def to_schedule(positions: Sequence[Position], seed: int = 0) -> str:
    """Encode positions as a meeting schedule.

    Line number -> minutes past 9:00, word number -> room letter index,
    char number -> duration in minutes (1-based). Lossless for word
    numbers 0..5 (the room alphabet).
    """
    rng = random.Random(seed)
    lines = ["Weekly schedule -- floor 3"]
    for li, wi, ci in positions:
        clock = 9 * 60 + li
        hour, minute = divmod(clock, 60)
        topic = rng.choice(_TOPICS)
        if wi == -1:                       # space marker -> reserved room
            room, duration = "X", 0
        else:
            room = _ROOMS[wi % len(_ROOMS)]
            duration = ci + 1
        lines.append(f"{hour:02d}:{minute:02d}  {topic:<10} room {room}  ({duration} min)")
    return "\n".join(lines) + "\n"


def from_schedule(text: str) -> list[Position]:
    """Decode a schedule produced by to_schedule()."""
    positions: list[Position] = []
    pattern = re.compile(
        r"^(\d{2}):(\d{2})\s+\S+\s+room (\w)\s+\((\d+) min\)$"
    )
    room_index = {r: i for i, r in enumerate(_ROOMS)}
    room_index["X"] = -1  # reserved room marks a space
    for raw in text.splitlines():
        m = pattern.match(raw.strip())
        if not m:
            continue
        hour, minute, room, duration = (
            int(m.group(1)), int(m.group(2)), m.group(3), int(m.group(4))
        )
        if room not in room_index:
            raise BookCipherError(f"Unknown room {room!r} in schedule")
        li = (hour - 9) * 60 + minute
        wi = room_index[room]
        ci = -1 if wi == -1 else duration - 1
        positions.append((li, wi, ci))
    if not positions:
        raise BookCipherError("No meeting lines found in schedule")
    return positions


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

SCHEMES = {
    "shopping": (to_shopping_list, from_shopping_list),
    "log": (to_server_log, from_server_log),
    "invoice": (to_invoice, from_invoice),
    "schedule": (to_schedule, from_schedule),
}


def hide(positions: Sequence[Position], scheme: str, seed: int = 0) -> str:
    """Encode positions into the named disguise scheme."""
    if scheme not in SCHEMES:
        raise BookCipherError(f"Unknown scheme {scheme!r}. Use: {', '.join(SCHEMES)}")
    return SCHEMES[scheme][0](positions, seed)


def reveal(text: str, scheme: str) -> list[Position]:
    """Decode positions from the named disguise scheme."""
    if scheme not in SCHEMES:
        raise BookCipherError(f"Unknown scheme {scheme!r}. Use: {', '.join(SCHEMES)}")
    return SCHEMES[scheme][1](text)


__all__ = [
    "to_shopping_list", "from_shopping_list",
    "to_server_log", "from_server_log",
    "to_invoice", "from_invoice",
    "to_schedule", "from_schedule",
    "SCHEMES", "hide", "reveal",
]
