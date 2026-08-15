"""Verbal transmission of position triples: the word map.

Book ciphers live and die by humans reading positions aloud -- over a
phone line, a radio, or across a table. Digits are notoriously fragile in
noisy channels ("fifteen" vs "fifty"). This module maps every position
triple to a fixed, phonetically distinct vocabulary so a listener can
write positions down without ambiguity, and convert back.

Design
------
* Each of the three coordinates is rendered as one word from a 64-word
  list chosen for consonant distinctness (no rhyming pairs, no words
  that differ only by a vowel). The list is a fixed constant, so both
  ends of the channel share it without negotiation.
* The space marker (-1, -1) gets its own single word, "PAUSE".
* A checksum word is appended: the sum of all coordinate values (spaces
  counted as zero) modulo 64, rendered from the same list. A listener
  who mishears one word will, with probability 63/64, catch it.

The wire format is uppercase words separated by single spaces, e.g.::

    BRAVO ECHO KILO PAUSE DELTA FOXTROT LIMA CHECK

where the final word is the checksum. Groups of four words are kept
together to aid chunking when read aloud.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

from .core import SPACE_MARKER, BookCipherError

__all__ = [
    "WORDMAP",
    "WORD_INDEX",
    "PAUSE_WORD",
    "WordMapError",
    "positions_to_words",
    "words_to_positions",
    "checksum_word",
    "format_for_voice",
    "parse_voice",
]

#: 64 phonetically distinct words, index 0..63. Deliberately no rhymes
#: and no near-homophones; every word starts with a different consonant
#: cluster where possible.
WORDMAP: Tuple[str, ...] = (
    "ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO", "FOXTROT", "GOLF",
    "HOTEL", "INDIA", "JULIET", "KILO", "LIMA", "MIKE", "NOVEMBER",
    "OSCAR", "PAPA", "QUEBEC", "ROMEO", "SIERRA", "TANGO", "UNIFORM",
    "VICTOR", "WHISKEY", "XRAY", "YANKEE", "ZULU", "AMBER", "BIRCH",
    "CEDAR", "DUNE", "EMBER", "FERN", "GRANITE", "HARBOR", "IVY",
    "JASPER", "KELP", "LANTERN", "MAPLE", "NORDIC", "ONYX", "PIPER",
    "QUARTZ", "RIDGE", "SABLE", "TIMBER", "UMBER", "VELVET", "WALNUT",
    "YONDER", "ZENITH", "ANCHOR", "BEACON", "CINDER", "DRIFT", "FALCON",
    "GROVE", "HEARTH", "INGOT", "JUNCTION", "KESTREL", "LODGE", "MARROW",
    "NIMBUS",
)

WORD_INDEX = {w: i for i, w in enumerate(WORDMAP)}

#: The single word representing the space marker.
PAUSE_WORD = "PAUSE"

#: Marker word introducing the checksum at the end of a voice string.
CHECK_MARKER = "CHECK"


class WordMapError(BookCipherError):
    """Raised when a voice string cannot be decoded."""


def _coord_word(value: int) -> str:
    """Map one non-negative coordinate to its word."""
    if value < 0:
        raise WordMapError(f"negative coordinate {value} outside space marker")
    if value >= len(WORDMAP):
        raise WordMapError(
            f"coordinate {value} exceeds word map size {len(WORDMAP)}; "
            "use dotted text for large books")
    return WORDMAP[value]


def checksum_word(positions: Sequence[Tuple[int, int, int]]) -> str:
    """The checksum word for a position list.

    Spaces contribute zero. The checksum is the coordinate sum modulo the
    word-map size, rendered as a word.
    """
    total = 0
    for a, b, c in positions:
        if b == SPACE_MARKER[1]:  # space marker: word == -1
            continue
        total += a + b + c
    return WORDMAP[total % len(WORDMAP)]


def positions_to_words(positions: Sequence[Tuple[int, int, int]]) -> List[str]:
    """Convert position triples to a flat list of words (no checksum).

    Each real triple becomes three words; a space marker becomes the
    single word PAUSE.
    """
    words: List[str] = []
    for a, b, c in positions:
        if b == SPACE_MARKER[1]:  # space marker: word == -1
            words.append(PAUSE_WORD)
        else:
            words.append(_coord_word(a))
            words.append(_coord_word(b))
            words.append(_coord_word(c))
    return words


def words_to_positions(words: Sequence[str]) -> List[Tuple[int, int, int]]:
    """Convert a flat word list back to position triples.

    The list is consumed greedily: PAUSE yields a space marker, any other
    word starts a triple and consumes the next two words.

    Raises:
        WordMapError: On an unknown word or a truncated trailing triple.
    """
    positions: List[Tuple[int, int, int]] = []
    i = 0
    n = len(words)
    while i < n:
        w = words[i].strip().upper()
        if w == PAUSE_WORD:
            # decode() keys on word == -1; line 0 is a harmless placeholder.
            positions.append((0, SPACE_MARKER[0], SPACE_MARKER[1]))
            i += 1
            continue
        if w == CHECK_MARKER:
            break  # checksum handled by parse_voice
        if w not in WORD_INDEX:
            raise WordMapError(f"unknown word: {w!r}")
        if i + 2 >= n:
            raise WordMapError("truncated triple at end of voice string")
        try:
            b = WORD_INDEX[words[i + 1].strip().upper()]
            c = WORD_INDEX[words[i + 2].strip().upper()]
        except KeyError as exc:
            raise WordMapError(f"unknown word in triple near {w!r}") from exc
        positions.append((WORD_INDEX[w], b, c))
        i += 3
    return positions


def format_for_voice(positions: Sequence[Tuple[int, int, int]],
                     group_size: int = 4) -> str:
    """Render positions as a checksummed voice string.

    Args:
        positions: The triples to render.
        group_size: Words per spoken group; groups are separated by a
            double space to cue the listener. Use 1 to disable grouping.

    Returns:
        Uppercase words; the final group is CHECK plus the checksum word.
    """
    if group_size < 1:
        raise WordMapError("group_size must be >= 1")
    words = positions_to_words(positions)
    words.append(CHECK_MARKER)
    words.append(checksum_word(positions))
    if group_size == 1:
        return " ".join(words)
    groups = [" ".join(words[i:i + group_size])
              for i in range(0, len(words), group_size)]
    return "  ".join(groups)


def parse_voice(text: str, verify_checksum: bool = True
                ) -> List[Tuple[int, int, int]]:
    """Parse a voice string produced by format_for_voice.

    Args:
        text: The spoken/typed word string; case- and spacing-insensitive.
        verify_checksum: When True (default), a present CHECK word must
            match or WordMapError is raised.

    Returns:
        The decoded position triples.

    Raises:
        WordMapError: On unknown words, truncation, or checksum mismatch.
    """
    words = [w for w in text.upper().split() if w]
    if not words:
        raise WordMapError("empty voice string")
    check_value = None
    if CHECK_MARKER in words:
        idx = words.index(CHECK_MARKER)
        if idx + 1 >= len(words):
            raise WordMapError("CHECK marker without checksum word")
        checksum = words[idx + 1]
        if checksum not in WORD_INDEX:
            raise WordMapError(f"bad checksum word: {checksum!r}")
        check_value = WORD_INDEX[checksum]
        words = words[:idx]
    positions = words_to_positions(words)
    if verify_checksum and check_value is not None:
        expected = checksum_word(positions)
        if WORD_INDEX[expected] != check_value:
            raise WordMapError(
                f"checksum mismatch: heard {WORDMAP[check_value]}, "
                f"computed {expected}")
    return positions
