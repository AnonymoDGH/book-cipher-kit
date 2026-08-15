"""Tests for book_cipher_kit.formats -- position serialization formats."""

from __future__ import annotations

import pytest

from book_cipher_kit import BookCipherError
from book_cipher_kit.formats import (
    FORMATS,
    MAGIC_B64,
    MAGIC_HEX,
    MAGIC_JSON,
    deserialize,
    from_base64,
    from_csv,
    from_hex,
    from_json,
    from_text,
    serialize,
    sniff,
    to_base64,
    to_csv,
    to_hex,
    to_json,
    to_text,
)

POSITIONS = [(0, 4, 2), (0, 0, 2), (12, -1, -1), (87, 12, 5), (3, 1, 0)]


class TestText:
    def test_roundtrip(self):
        assert from_text(to_text(POSITIONS)) == POSITIONS

    def test_shape(self):
        assert to_text([(1, 2, 3)]) == "1.2.3\n"

    def test_empty(self):
        assert from_text("") == []
        assert from_text("\n\n") == []

    def test_malformed(self):
        with pytest.raises(BookCipherError):
            from_text("1.2\n")
        with pytest.raises(BookCipherError):
            from_text("x.y.z\n")


class TestJson:
    def test_roundtrip(self):
        assert from_json(to_json(POSITIONS)) == POSITIONS

    def test_marker_present(self):
        assert MAGIC_JSON in to_json(POSITIONS)

    def test_count_field(self):
        import json
        data = json.loads(to_json(POSITIONS))
        assert data["count"] == len(POSITIONS)

    def test_missing_marker(self):
        with pytest.raises(BookCipherError):
            from_json('{"positions": [[1,2,3]]}')

    def test_bad_json(self):
        with pytest.raises(BookCipherError):
            from_json("not json at all")

    def test_count_mismatch(self):
        text = to_json(POSITIONS).replace('"count": 5', '"count": 4')
        with pytest.raises(BookCipherError):
            from_json(text)

    def test_bad_entry(self):
        text = to_json(POSITIONS).replace("[0, 4, 2]", "[0, 4]")
        with pytest.raises(BookCipherError):
            from_json(text)

    def test_indent_option(self):
        assert "\n" in to_json(POSITIONS, indent=2)


class TestCsv:
    def test_roundtrip(self):
        assert from_csv(to_csv(POSITIONS)) == POSITIONS

    def test_header(self):
        assert to_csv(POSITIONS).startswith("line,word,char\n")

    def test_missing_header(self):
        with pytest.raises(BookCipherError):
            from_csv("0,4,2\n")

    def test_bad_row_width(self):
        with pytest.raises(BookCipherError):
            from_csv("line,word,char\n1,2\n")

    def test_non_numeric_row(self):
        with pytest.raises(BookCipherError):
            from_csv("line,word,char\na,b,c\n")

    def test_blank_rows_skipped(self):
        assert from_csv("line,word,char\n1,2,3\n\n4,5,6\n") == [(1, 2, 3), (4, 5, 6)]


class TestHex:
    def test_roundtrip(self):
        assert from_hex(to_hex(POSITIONS)) == POSITIONS

    def test_magic(self):
        assert to_hex(POSITIONS).startswith(MAGIC_HEX)

    def test_single_line(self):
        assert to_hex(POSITIONS).count("\n") == 1  # trailing only

    def test_missing_magic(self):
        with pytest.raises(BookCipherError):
            from_hex("000000000000")

    def test_bad_hex(self):
        with pytest.raises(BookCipherError):
            from_hex(MAGIC_HEX + "zzzz")

    def test_negative_marker(self):
        # Space markers use -1; signed packing must survive.
        assert from_hex(to_hex([(5, -1, -1)])) == [(5, -1, -1)]


class TestBase64:
    def test_roundtrip(self):
        assert from_base64(to_base64(POSITIONS)) == POSITIONS

    def test_magic_line(self):
        assert to_base64(POSITIONS).startswith(MAGIC_B64)

    def test_wrapped(self):
        text = to_base64(list(range(0, 1)) and POSITIONS * 20, line_width=16)
        body = [ln for ln in text.splitlines()[1:] if ln]
        assert all(len(ln) <= 16 for ln in body)

    def test_missing_magic(self):
        with pytest.raises(BookCipherError):
            from_base64("aGVsbG8=")

    def test_bad_base64(self):
        with pytest.raises(BookCipherError):
            from_base64(MAGIC_B64 + "\n!!!not-base64!!!")


class TestSniff:
    def test_sniff_each_format(self):
        assert sniff(to_text(POSITIONS)) == "text"
        assert sniff(to_json(POSITIONS)) == "json"
        assert sniff(to_csv(POSITIONS)) == "csv"
        assert sniff(to_hex(POSITIONS)) == "hex"
        assert sniff(to_base64(POSITIONS)) == "base64"

    def test_sniff_empty_is_text(self):
        assert sniff("") == "text"

    def test_sniff_with_surrounding_whitespace(self):
        assert sniff("  " + to_hex(POSITIONS) + "  ") == "hex"


class TestUnified:
    @pytest.mark.parametrize("fmt", sorted(FORMATS))
    def test_serialize_deserialize_roundtrip(self, fmt):
        text = serialize(POSITIONS, fmt)
        assert deserialize(text, fmt) == POSITIONS

    def test_deserialize_autodetect(self):
        for fmt in FORMATS:
            text = serialize(POSITIONS, fmt)
            assert deserialize(text) == POSITIONS, fmt

    def test_unknown_format(self):
        with pytest.raises(BookCipherError):
            serialize(POSITIONS, "yaml")
        with pytest.raises(BookCipherError):
            deserialize("x", "yaml")

    def test_large_payload(self):
        big = [(i, i % 50, i % 12) for i in range(2000)]
        for fmt in FORMATS:
            assert deserialize(serialize(big, fmt), fmt) == big, fmt
