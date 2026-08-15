"""Book Cipher Kit -- the cipher that needs no key, only a shared book.

Each character of a message is encoded as a position inside a word of a
book: (line, word, character). Without the same edition of the same book,
the positions are meaningless. The classic unbreakable-ish cipher, as a
complete workbench:

* core      -- encode/decode, coverage, edition fingerprints
* index     -- reusable BookIndex with cached serialization
* corpus    -- embedded public-domain books + deterministic prose generator
* formats   -- text/JSON/CSV/hex/base64 position formats with sniffing
* crypto    -- passphrase-encrypted position payloads (PBKDF2 + HMAC)
* stego     -- hide positions as prose, acrostics, and null ciphers
* analysis  -- security analysis of position lists
* doctor    -- diagnose failing decode sessions

Pure standard library.
"""

from __future__ import annotations

from .core import (
    SEPARATOR,
    BookCipherError,
    CharacterNotFoundError,
    PositionOutOfRangeError,
    book_from_text,
    char_histogram,
    coverage,
    decode,
    diff_books,
    encode,
    find_char,
    fingerprint,
    load_book,
    normalize_line,
    positions_to_text,
    text_to_positions,
    validate_positions,
    word_count,
)
from .index import BookIndex

__version__ = "0.2.0"

__all__ = [
    "SEPARATOR",
    "BookCipherError", "CharacterNotFoundError", "PositionOutOfRangeError",
    "book_from_text", "char_histogram", "coverage", "decode", "diff_books",
    "encode", "find_char", "fingerprint", "load_book", "normalize_line",
    "positions_to_text", "text_to_positions", "validate_positions",
    "word_count", "BookIndex", "__version__",
]
