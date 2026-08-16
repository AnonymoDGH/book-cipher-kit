"""Tests for book_cipher_kit.cli -- end-to-end command behavior."""

from __future__ import annotations

import pytest

from book_cipher_kit.cli import main

BOOK = (
    "The quick brown fox jumps over the lazy dog again and again.\n"
    "Pack my box with five dozen liquor jugs. Six big devils from Japan\n"
    "quickly forgot how to waltz. Amazingly few discotheques provide\n"
    "jukeboxes. The five boxing wizards jump quickly.\n"
)


@pytest.fixture
def book_file(tmp_path):
    p = tmp_path / "book.txt"
    p.write_text(BOOK, encoding="utf-8")
    return str(p)


class TestEncodeDecode:
    def test_encode_to_file(self, book_file, tmp_path, capsys):
        out = tmp_path / "coords.txt"
        rc = main(["encode", "--book", book_file, "--message", "meet at dawn",
                   "--out", str(out), "--seed", "1"])
        assert rc == 0
        assert out.exists()
        assert "Encoded" in capsys.readouterr().out

    def test_encode_stdout(self, book_file, capsys):
        rc = main(["encode", "--book", book_file, "--message", "hello", "--seed", "1"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "." in out  # triples

    def test_decode_inline(self, book_file, capsys):
        # Encode to stdout, capture, then decode.
        main(["encode", "--book", book_file, "--message", "meet at dawn", "--seed", "3"])
        positions_text = capsys.readouterr().out
        rc = main(["decode", "--book", book_file, "--positions", positions_text])
        assert rc == 0
        assert capsys.readouterr().out.strip() == "meet at dawn"

    def test_decode_from_file(self, book_file, tmp_path, capsys):
        out = tmp_path / "coords.txt"
        main(["encode", "--book", book_file, "--message", "the package is loose",
              "--out", str(out), "--seed", "2"])
        capsys.readouterr()
        rc = main(["decode", "--book", book_file, "--input", str(out)])
        assert rc == 0
        assert capsys.readouterr().out.strip() == "the package is loose"

    def test_encode_formats(self, book_file, tmp_path):
        for fmt in ("text", "json", "csv", "hex", "base64"):
            out = tmp_path / f"coords.{fmt}"
            rc = main(["encode", "--book", book_file, "--message", "format check",
                       "--out", str(out), "--format", fmt, "--seed", "1"])
            assert rc == 0, fmt
            assert out.read_text(encoding="utf-8").strip(), fmt

    def test_encode_stego_format(self, book_file, tmp_path, capsys):
        out = tmp_path / "cover.txt"
        rc = main(["encode", "--book", book_file, "--message", "stego works",
                   "--out", str(out), "--format", "stego", "--seed", "1"])
        assert rc == 0
        text = out.read_text(encoding="utf-8")
        assert "!" in text  # prose with run terminators

    def test_decode_stego_cover(self, book_file, tmp_path, capsys):
        out = tmp_path / "cover.txt"
        main(["encode", "--book", book_file, "--message", "hidden in prose",
              "--out", str(out), "--format", "stego", "--seed", "1"])
        capsys.readouterr()
        rc = main(["decode", "--book", book_file, "--cover", str(out)])
        assert rc == 0
        assert capsys.readouterr().out.strip() == "hidden in prose"

    def test_avoid_lines_flag(self, book_file, capsys):
        rc = main(["encode", "--book", book_file, "--message", "avoid test",
                   "--avoid-lines", "0,1", "--seed", "1"])
        assert rc == 0

    def test_missing_char_returns_error(self, book_file, capsys):
        rc = main(["encode", "--book", book_file, "--message", "viva 2026"])
        assert rc == 1
        assert "does not appear" in capsys.readouterr().err


class TestStats:
    def test_stats(self, book_file, capsys):
        rc = main(["stats", "--book", book_file])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Alphabet coverage" in out
        assert "Fingerprint" in out

    def test_stats_histogram(self, book_file, capsys):
        rc = main(["stats", "--book", book_file, "--histogram"])
        assert rc == 0
        assert "Top characters" in capsys.readouterr().out


class TestCorpus:
    def test_corpus_list(self, capsys):
        rc = main(["corpus", "--list"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "sun_tzu" in out and "aesop" in out

    def test_corpus_emit(self, tmp_path, capsys):
        out = tmp_path / "book.txt"
        rc = main(["corpus", "--name", "gettysburg", "--out", str(out)])
        assert rc == 0
        assert "score" in out.read_text(encoding="utf-8").lower()

    def test_corpus_generate(self, tmp_path, capsys):
        out = tmp_path / "gen.txt"
        rc = main(["corpus", "--generate", "--paragraphs", "2", "--seed", "5",
                   "--out", str(out)])
        assert rc == 0
        assert out.read_text(encoding="utf-8").strip()

    def test_corpus_pad(self, tmp_path, capsys):
        out = tmp_path / "padded.txt"
        rc = main(["corpus", "--name", "aesop", "--pad", "2", "--seed", "1",
                   "--out", str(out)])
        assert rc == 0


class TestConvert:
    def test_convert_text_to_json(self, book_file, tmp_path, capsys):
        coords = tmp_path / "coords.txt"
        main(["encode", "--book", book_file, "--message", "convert me",
              "--out", str(coords), "--seed", "1"])
        capsys.readouterr()
        out = tmp_path / "coords.json"
        rc = main(["convert", "--input", str(coords), "--to", "json", "--out", str(out)])
        assert rc == 0
        assert "bookcipher-positions" in out.read_text(encoding="utf-8")

    def test_convert_autodetect(self, book_file, tmp_path, capsys):
        coords = tmp_path / "coords.hex"
        main(["encode", "--book", book_file, "--message", "detect me",
              "--out", str(coords), "--format", "hex", "--seed", "1"])
        capsys.readouterr()
        out = tmp_path / "coords.txt"
        rc = main(["convert", "--input", str(coords), "--to", "text", "--out", str(out)])
        assert rc == 0


class TestFingerprintDiff:
    def test_fingerprint(self, book_file, capsys):
        rc = main(["fingerprint", "--book", book_file])
        assert rc == 0
        fp = capsys.readouterr().out.strip()
        assert len(fp) == 64

    def test_diff_same(self, book_file, capsys):
        rc = main(["diff", "--book-a", book_file, "--book-b", book_file])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Same word stream: yes" in out

    def test_diff_different(self, book_file, tmp_path, capsys):
        other = tmp_path / "other.txt"
        other.write_text("completely different words\n", encoding="utf-8")
        rc = main(["diff", "--book-a", book_file, "--book-b", str(other)])
        assert rc == 0
        assert "Same word stream: NO" in capsys.readouterr().out


class TestEncryptDecrypt:
    def test_encrypt_decrypt_roundtrip(self, book_file, tmp_path, capsys):
        coords = tmp_path / "coords.txt"
        main(["encode", "--book", book_file, "--message", "secret cargo",
              "--out", str(coords), "--seed", "1"])
        capsys.readouterr()
        enc = tmp_path / "coords.enc"
        rc = main(["encrypt", "--input", str(coords), "--passphrase", "pw123",
                   "--kdf-iterations", "1000", "--out", str(enc)])
        assert rc == 0
        capsys.readouterr()
        rc = main(["decrypt", "--input", str(enc), "--passphrase", "pw123",
                   "--kdf-iterations", "1000", "--book", book_file])
        assert rc == 0
        assert capsys.readouterr().out.strip() == "secret cargo"

    def test_decrypt_wrong_passphrase(self, book_file, tmp_path, capsys):
        coords = tmp_path / "coords.txt"
        main(["encode", "--book", book_file, "--message", "secret",
              "--out", str(coords), "--seed", "1"])
        enc = tmp_path / "coords.enc"
        main(["encrypt", "--input", str(coords), "--passphrase", "right",
              "--kdf-iterations", "1000", "--out", str(enc)])
        capsys.readouterr()
        rc = main(["decrypt", "--input", str(enc), "--passphrase", "wrong",
                   "--kdf-iterations", "1000"])
        assert rc == 1
        assert "Authentication failed" in capsys.readouterr().err

    def test_bind_book(self, book_file, tmp_path, capsys):
        coords = tmp_path / "coords.txt"
        main(["encode", "--book", book_file, "--message", "bound",
              "--out", str(coords), "--seed", "1"])
        enc = tmp_path / "coords.enc"
        main(["encrypt", "--input", str(coords), "--passphrase", "pw",
              "--bind-book", book_file, "--kdf-iterations", "1000",
              "--out", str(enc)])
        capsys.readouterr()
        rc = main(["decrypt", "--input", str(enc), "--passphrase", "pw",
                   "--bind-book", book_file, "--kdf-iterations", "1000",
                   "--book", book_file])
        assert rc == 0
        assert capsys.readouterr().out.strip() == "bound"

    def test_passprint(self, capsys):
        rc = main(["passprint", "--passphrase", "shared secret",
                   "--kdf-iterations", "1000"])
        assert rc == 0
        assert len(capsys.readouterr().out.strip()) == 16


class TestStegoCommands:
    def test_stego_hide_reveal(self, book_file, tmp_path, capsys):
        coords = tmp_path / "coords.txt"
        main(["encode", "--book", book_file, "--message", "hide this well",
              "--out", str(coords), "--seed", "1"])
        capsys.readouterr()
        cover = tmp_path / "cover.txt"
        rc = main(["stego-hide", "--input", str(coords), "--seed", "2",
                   "--out", str(cover)])
        assert rc == 0
        capsys.readouterr()
        rc = main(["stego-reveal", "--input", str(cover), "--book", book_file])
        assert rc == 0
        assert capsys.readouterr().out.strip() == "hide this well"

    def test_acrostic_command(self, tmp_path, capsys):
        out = tmp_path / "acrostic.txt"
        rc = main(["acrostic", "--message", "meet at dawn", "--seed", "1",
                   "--out", str(out)])
        assert rc == 0
        capsys.readouterr()
        rc = main(["acrostic", "--decode", "--input", str(out)])
        assert rc == 0
        assert capsys.readouterr().out.strip() == "meet at dawn"

    def test_null_command(self, tmp_path, capsys):
        out = tmp_path / "null.txt"
        rc = main(["null", "--message", "meet at dawn", "--stride", "5",
                   "--seed", "1", "--out", str(out)])
        assert rc == 0
        capsys.readouterr()
        rc = main(["null", "--decode", "--input", str(out), "--stride", "5"])
        assert rc == 0
        assert capsys.readouterr().out.strip() == "meet at dawn"


class TestAnalyzeDoctor:
    def test_analyze(self, book_file, tmp_path, capsys):
        coords = tmp_path / "coords.txt"
        main(["encode", "--book", book_file, "--message", "analyze this message",
              "--out", str(coords), "--seed", "1"])
        capsys.readouterr()
        rc = main(["analyze", "--input", str(coords), "--book", book_file])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Verdict" in out

    def test_analyze_json(self, book_file, tmp_path, capsys):
        import json
        coords = tmp_path / "coords.txt"
        main(["encode", "--book", book_file, "--message", "json report",
              "--out", str(coords), "--seed", "1"])
        capsys.readouterr()
        rc = main(["analyze", "--input", str(coords), "--json"])
        assert rc == 0
        report = json.loads(capsys.readouterr().out)
        assert "verdict" in report

    def test_doctor_healthy(self, book_file, tmp_path, capsys):
        coords = tmp_path / "coords.txt"
        main(["encode", "--book", book_file, "--message", "doctor check",
              "--out", str(coords), "--seed", "1"])
        capsys.readouterr()
        rc = main(["doctor", "--book", book_file, "--input", str(coords)])
        assert rc == 0
        assert "[+]" in capsys.readouterr().out

    def test_doctor_unhealthy_exits_nonzero(self, book_file, tmp_path, capsys):
        bad = tmp_path / "bad.txt"
        bad.write_text("9999.0.0\n", encoding="utf-8")
        rc = main(["doctor", "--book", book_file, "--input", str(bad)])
        assert rc == 1
        assert "[-]" in capsys.readouterr().out

    def test_doctor_book_only(self, book_file, capsys):
        rc = main(["doctor", "--book", book_file])
        assert rc == 0
