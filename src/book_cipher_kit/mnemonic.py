"""Mnemonic rendering of fingerprints for verbal comparison.

Two operators who each hold a copy of the book need to confirm they share
the same edition. The edition fingerprint is a 64-hex-digit SHA-256 --
impossible to read aloud and compare reliably over a phone line.

This module maps a fingerprint (or any hex digest) onto a short sequence
of memorable words drawn from a fixed 256-word list, one word per byte.
Reading six words aloud is easy; comparing them catches a wrong edition
immediately. Because the mapping is a pure function of the digest, both
sides derive the identical phrase from the identical fingerprint without
exchanging the digest itself.

Design
------
* The word list has exactly 256 entries, so each byte of the digest
  indexes one word directly -- no modulo bias, no collisions.
* The words are real, phonetically distinct, and easy to say over a noisy
  channel, which is the whole point of a mnemonic.
* By default only the first N bytes are rendered (6 gives ~48 bits of
  discrimination, plenty to catch a different edition).
* A checksum word derived from the rendered bytes is appended so a
  listener who mishears one word is very likely to notice.
"""

from __future__ import annotations

from .core import BookCipherError

__all__ = [
    "MNEMONIC_WORDS",
    "MnemonicError",
    "hex_to_mnemonic",
    "mnemonic_to_hex",
    "fingerprint_mnemonic",
    "verify_mnemonic",
]

#: 256 phonetically distinct real words, index 0..255. One word per byte.
MNEMONIC_WORDS: tuple = (
    "acorn", "anchor", "anvil", "apple", "arrow", "atlas", "autumn", "badger",
    "banner", "basket", "beacon", "beetle", "birch", "bison", "blanket", "blossom",
    "bonfire", "bottle", "boulder", "branch", "breeze", "bridge", "brook", "bucket",
    "buffalo", "bullet", "bundle", "butterfly", "cabin", "cactus", "camel", "candle",
    "canyon", "carpet", "castle", "cedar", "cherry", "chestnut", "chimney", "cipher",
    "circle", "cliff", "clover", "cobalt", "comet", "compass", "copper", "coral",
    "cottage", "cotton", "cougar", "coyote", "crane", "crater", "cricket", "crimson",
    "crystal", "current", "dagger", "daisy", "dawn", "delta", "desert", "diamond",
    "dolphin", "domino", "donkey", "dragon", "drift", "drum", "dune", "eagle",
    "echo", "ember", "engine", "falcon", "feather", "fern", "ferry", "fiddle",
    "firefly", "fjord", "flame", "flint", "forest", "fossil", "fountain", "foxglove",
    "frost", "galaxy", "garden", "garnet", "glacier", "glen", "gopher", "granite",
    "grape", "gravel", "grove", "guitar", "gull", "harbor", "hawk", "hazel",
    "heron", "hollow", "honey", "horizon", "hurricane", "ibis", "iceberg", "indigo",
    "island", "ivy", "jaguar", "jasmine", "jetty", "jungle", "juniper", "kayak",
    "kestrel", "kettle", "kingfisher", "kite", "kitten", "koala", "lagoon", "lantern",
    "lark", "lattice", "laurel", "lava", "lemon", "leopard", "lighthouse", "lilac",
    "lily", "lizard", "lobster", "lodge", "lotus", "lynx", "mackerel", "magnet",
    "maple", "marble", "marsh", "meadow", "meteor", "minnow", "mirror", "mistletoe",
    "monarch", "mongoose", "moonbeam", "moose", "mosaic", "mountain", "mulberry", "mustang",
    "narwhal", "nebula", "nectar", "nightjar", "nimbus", "nutmeg", "oasis", "ocelot",
    "octopus", "olive", "onyx", "opal", "orchid", "osprey", "otter", "owl",
    "oxbow", "oyster", "paddle", "palm", "panther", "parrot", "pebble", "pelican",
    "penguin", "pepper", "peregrine", "petal", "phoenix", "pigeon", "pine", "pirate",
    "planet", "plateau", "plum", "polar", "poppy", "prism", "puma", "pyramid",
    "quartz", "quill", "rabbit", "raccoon", "radar", "rainbow", "raven", "reef",
    "reindeer", "ridge", "river", "robin", "rocket", "rosemary", "ruby", "saddle",
    "salmon", "sapphire", "scarlet", "sequoia", "shadow", "sierra", "silver", "skylark",
    "slate", "sloth", "snowflake", "sonar", "sparrow", "sphinx", "spiral", "spruce",
    "stallion", "starling", "steel", "summit", "sunset", "swallow", "swift", "sycamore",
    "talon", "tangerine", "tempest", "thistle", "thunder", "tiger", "timber", "topaz",
    "tornado", "tortoise", "trail", "tulip", "tundra", "turbine", "turtle", "twilight",
)

_WORD_INDEX = {w: i for i, w in enumerate(MNEMONIC_WORDS)}

#: Marker word introducing the trailing checksum.
CHECK_WORD = "check"


class MnemonicError(BookCipherError):
    """Raised when a mnemonic cannot be built or parsed."""


def _checksum_word(data: bytes) -> str:
    """A checksum word derived from the rendered bytes."""
    total = sum(data) % len(MNEMONIC_WORDS)
    return MNEMONIC_WORDS[total]


def hex_to_mnemonic(hex_digest: str, words: int = 6,
                    with_checksum: bool = True) -> str:
    """Render a hex digest as a memorable word phrase.

    Args:
        hex_digest: The digest as a lowercase or uppercase hex string.
        words: How many leading bytes to render (1..len(bytes)).
        with_checksum: Append a trailing "check <word>" pair.

    Returns:
        Space-separated lowercase words.

    Raises:
        MnemonicError: On non-hex input or an out-of-range word count.
    """
    cleaned = hex_digest.strip().lower()
    try:
        data = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise MnemonicError(f"not a hex digest: {hex_digest!r}") from exc
    if not data:
        raise MnemonicError("empty digest")
    if not 1 <= words <= len(data):
        raise MnemonicError(
            f"word count {words} out of range for {len(data)} bytes")
    chosen = data[:words]
    phrase = [MNEMONIC_WORDS[b] for b in chosen]
    if with_checksum:
        phrase.append(CHECK_WORD)
        phrase.append(_checksum_word(chosen))
    return " ".join(phrase)


def mnemonic_to_hex(phrase: str, verify_checksum: bool = True) -> str:
    """Convert a word phrase back to the hex bytes it encodes.

    Args:
        phrase: The phrase from hex_to_mnemonic; case- and spacing-tolerant.
        verify_checksum: When True, a present trailing checksum must match.

    Returns:
        The hex string of the encoded bytes.

    Raises:
        MnemonicError: On an unknown word, a truncated checksum, or a
            checksum mismatch.
    """
    tokens = [t for t in phrase.lower().split() if t]
    if not tokens:
        raise MnemonicError("empty phrase")
    checksum = None
    if len(tokens) >= 2 and tokens[-2] == CHECK_WORD:
        data_tokens = tokens[:-2]
        checksum = tokens[-1]
        if checksum not in _WORD_INDEX:
            raise MnemonicError(f"bad checksum word: {checksum!r}")
    elif CHECK_WORD in tokens:
        raise MnemonicError("check marker without a checksum word")
    else:
        data_tokens = tokens
    if not data_tokens:
        raise MnemonicError("phrase carries no data words")
    data = bytearray()
    for tok in data_tokens:
        if tok not in _WORD_INDEX:
            raise MnemonicError(f"unknown word: {tok!r}")
        data.append(_WORD_INDEX[tok])
    if verify_checksum and checksum is not None:
        expected = _checksum_word(bytes(data))
        if expected != checksum:
            raise MnemonicError(
                f"checksum mismatch: heard {checksum}, computed {expected}")
    return bytes(data).hex()


def fingerprint_mnemonic(fingerprint_hex: str, words: int = 6) -> str:
    """Convenience: render a book fingerprint as a phrase."""
    return hex_to_mnemonic(fingerprint_hex, words=words)


def verify_mnemonic(phrase: str, expected_hex: str, words: int = 6) -> bool:
    """Check that a spoken phrase matches an expected digest prefix.

    Returns False (rather than raising) on any mismatch or parse problem,
    so it can gate an interactive comparison.
    """
    try:
        recovered = mnemonic_to_hex(phrase, verify_checksum=True)
    except MnemonicError:
        return False
    return expected_hex.strip().lower().startswith(recovered)
