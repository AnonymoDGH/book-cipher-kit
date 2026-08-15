"""Shamir secret sharing for book-cipher key material.

A passphrase, OTP ledger, or serialized position list can be split into
"n" shares of which any "k" reconstruct the secret. Sharing out the
*passphrase* that unlocks an encrypted position file means no single
share-holder can read the message alone -- a natural fit for a cipher
system built on physical books.

Implementation notes
--------------------
* The secret is processed byte-wise over the prime field GF(257). 257 is
  prime and strictly larger than every byte value, so each byte is a
  valid field element and Lagrange interpolation is exact.
* Randomness comes from "secrets" by default; tests may inject a seeded
  "random.Random" for determinism.
* Shares serialize to a compact text format with a magic header, the
  (k, n) parameters, a secret fingerprint, and one line per share.
"""

from __future__ import annotations

import hashlib
import random
import secrets
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "PRIME",
    "ShareError",
    "Share",
    "split_secret",
    "combine_shares",
    "share_fingerprint",
    "secret_fingerprint",
    "serialize_shares",
    "parse_shares",
    "verify_share_set",
]

#: The field modulus. 257 is prime and > 255, covering every byte value.
PRIME = 257

MAGIC = "bookcipher-shares/1"


class ShareError(ValueError):
    """Raised for malformed, inconsistent, or insufficient shares."""


@dataclass(frozen=True)
class Share:
    """One share: the x coordinate and one field element per secret byte."""

    x: int
    values: Tuple[int, ...]

    def __post_init__(self) -> None:
        if not 1 <= self.x < PRIME:
            raise ShareError(f"share x must be in 1..{PRIME - 1}, got {self.x}")
        for v in self.values:
            if not 0 <= v < PRIME:
                raise ShareError(f"share value out of field range: {v}")


def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    """Horner evaluation of coeffs[0] + coeffs[1]*x + ... mod PRIME."""
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % PRIME
    return acc


def _lagrange_at_zero(points: Sequence[Tuple[int, int]]) -> int:
    """Interpolate the polynomial through the points and return f(0)."""
    total = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (-xj)) % PRIME
            den = (den * (xi - xj)) % PRIME
        total = (total + yi * num * pow(den, PRIME - 2, PRIME)) % PRIME
    return total


def split_secret(secret: bytes, k: int, n: int,
                 rng: Optional[random.Random] = None) -> List[Share]:
    """Split a secret into n shares with reconstruction threshold k.

    Args:
        secret: The bytes to share. May be empty (yields shares of length 0).
        k: Minimum number of shares needed to reconstruct; 1 <= k <= n.
        n: Total number of shares; must be < PRIME (256 max).
        rng: Optional seeded random.Random for deterministic tests.

    Returns:
        A list of n Share objects with distinct x in 1..n.
    """
    if not 1 <= k <= n:
        raise ShareError(f"need 1 <= k <= n, got k={k} n={n}")
    if n >= PRIME:
        raise ShareError(f"n must be < {PRIME}, got {n}")
    shares: List[List[int]] = [[] for _ in range(n)]
    for byte in secret:
        coeffs = [byte]
        for _ in range(k - 1):
            if rng is not None:
                coeffs.append(rng.randrange(PRIME))
            else:
                coeffs.append(secrets.randbelow(PRIME))
        for i in range(n):
            shares[i].append(_eval_poly(coeffs, i + 1))
    return [Share(x=i + 1, values=tuple(shares[i])) for i in range(n)]


def combine_shares(shares: Iterable[Share]) -> bytes:
    """Reconstruct the secret from any k or more consistent shares.

    Raises:
        ShareError: If shares are empty, have mismatched lengths, or
            duplicate x coordinates.
    """
    share_list = list(shares)
    if not share_list:
        raise ShareError("no shares supplied")
    width = len(share_list[0].values)
    seen: set = set()
    for s in share_list:
        if len(s.values) != width:
            raise ShareError("share length mismatch")
        if s.x in seen:
            raise ShareError(f"duplicate share x={s.x}")
        seen.add(s.x)
    out = bytearray()
    for idx in range(width):
        points = [(s.x, s.values[idx]) for s in share_list]
        out.append(_lagrange_at_zero(points))
    return bytes(out)


def share_fingerprint(share: Share) -> str:
    """A short SHA-256 fingerprint identifying one share (for rosters)."""
    h = hashlib.sha256()
    h.update(share.x.to_bytes(2, "big"))
    h.update(len(share.values).to_bytes(4, "big"))
    for v in share.values:
        h.update(v.to_bytes(2, "big"))
    return h.hexdigest()[:16]


def secret_fingerprint(secret: bytes) -> str:
    """Fingerprint of the secret itself, stored in the share header."""
    return hashlib.sha256(secret).hexdigest()[:16]


def serialize_shares(shares: Sequence[Share], k: int, n: int,
                     fingerprint: str) -> str:
    """Render shares to the portable text format.

    Format::

        bookcipher-shares/1
        k=2 n=3 fp=abcdef0123456789
        x=1 v=12,200,7
        ...
    """
    lines = [MAGIC, f"k={k} n={n} fp={fingerprint}"]
    for s in shares:
        values = ",".join(str(v) for v in s.values)
        lines.append(f"x={s.x} v={values}")
    return "\n".join(lines) + "\n"


def parse_shares(text: str) -> Tuple[List[Share], int, int, str]:
    """Parse serialize_shares output.

    Returns:
        (shares, k, n, fingerprint).

    Raises:
        ShareError: On any structural problem.
    """
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    if not lines or lines[0] != MAGIC:
        raise ShareError("bad magic header")
    if len(lines) < 2:
        raise ShareError("missing parameter line")
    params: dict = {}
    for part in lines[1].split():
        if "=" not in part:
            raise ShareError(f"bad parameter token: {part!r}")
        key, _, val = part.partition("=")
        params[key] = val
    try:
        k = int(params["k"])
        n = int(params["n"])
        fp = params["fp"]
    except (KeyError, ValueError) as exc:
        raise ShareError("missing k/n/fp parameters") from exc
    shares: List[Share] = []
    for ln in lines[2:]:
        if not ln.startswith("x="):
            raise ShareError(f"bad share line: {ln!r}")
        xpart, _, vpart = ln.partition(" v=")
        try:
            x = int(xpart[2:])
            values = tuple(int(t) for t in vpart.split(",")) if vpart else ()
        except ValueError as exc:
            raise ShareError(f"unparseable share line: {ln!r}") from exc
        shares.append(Share(x=x, values=values))
    if len(shares) != n:
        raise ShareError(f"expected {n} shares, found {len(shares)}")
    return shares, k, n, fp


def verify_share_set(shares: Sequence[Share], k: int,
                     fingerprint: str) -> bool:
    """Check that a share set reconstructs to the fingerprinted secret.

    This is the recovery drill: combine the shares and compare the secret
    fingerprint. Returns False instead of raising when the set is short or
    inconsistent, so it can gate an interactive recovery ceremony.
    """
    if len(shares) < k:
        return False
    try:
        secret = combine_shares(shares[:k] if len(shares) > k else shares)
    except ShareError:
        return False
    return secret_fingerprint(secret) == fingerprint
