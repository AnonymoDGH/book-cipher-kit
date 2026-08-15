"""CLI tests for grid-* and verify-* subcommands."""

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


@pytest.fixture
def book_copy(tmp_path):
    p = tmp_path / "book_copy.txt"
    p.write_text(BOOK, encoding="utf-8")
    return str(p)


class TestGridCli:
    def test_show(self, book_file, capsys):
        rc = main(["grid-show", "--book", book_file])
        assert rc == 0
        assert "top:" in capsys.readouterr().out

    def test_encode_decode_roundtrip(self, book_file, tmp_path, capsys):
        out = tmp_path / "digits.txt"
        rc = main(["grid-encode", "--book", book_file,
                   "--message", "meet at dawn", "--out", str(out)])
        assert rc == 0
        digits = out.read_text(encoding="utf-8").strip()
        assert digits.isdigit()

        rc = main(["grid-decode", "--book", book_file, "--digits", digits])
        assert rc == 0
        assert "meet at dawn" in capsys.readouterr().out


class TestVerifyCli:
    def test_full_ceremony_passes(self, book_file, book_copy, tmp_path, capsys):
        probes = tmp_path / "probes.txt"
        answers = tmp_path / "answers.txt"

        rc = main(["verify-challenge", "--book", book_file, "--count", "6",
                   "--salt", "s1", "--seed", "4", "--out", str(probes)])
        assert rc == 0
        assert len(probes.read_text().split()) == 6

        rc = main(["verify-answer", "--book", book_copy,
                   "--probes", str(probes), "--salt", "s1",
                   "--out", str(answers)])
        assert rc == 0

        rc = main(["verify-check", "--book", book_file,
                   "--probes", str(probes), "--answers", str(answers),
                   "--salt", "s1"])
        assert rc == 0
        assert "verified" in capsys.readouterr().out

    def test_ceremony_fails_wrong_salt(self, book_file, book_copy, tmp_path, capsys):
        probes = tmp_path / "probes.txt"
        answers = tmp_path / "answers.txt"
        main(["verify-challenge", "--book", book_file, "--count", "4",
              "--salt", "s1", "--seed", "8", "--out", str(probes)])
        main(["verify-answer", "--book", book_copy, "--probes", str(probes),
              "--salt", "s1", "--out", str(answers)])
        rc = main(["verify-check", "--book", book_file,
                   "--probes", str(probes), "--answers", str(answers),
                   "--salt", "WRONG"])
        assert rc == 1
        assert "MISMATCH" in capsys.readouterr().out

    def test_ceremony_fails_wrong_edition(self, book_file, tmp_path, capsys):
        wrong = tmp_path / "wrong.txt"
        wrong.write_text(
            "A quick red fox leaps over a sleepy hound once more and more.\n"
            "Pack my box with five dozen liquor jugs. Six big devils from Japan\n"
            "quickly forgot how to waltz. Amazingly few discotheques provide\n"
            "jukeboxes. The five boxing wizards jump quickly.\n",
            encoding="utf-8")
        probes = tmp_path / "probes.txt"
        answers = tmp_path / "answers.txt"
        # Probe line 0 heavily so the differing first line is hit.
        main(["verify-challenge", "--book", book_file, "--count", "8",
              "--salt", "s2", "--seed", "2", "--out", str(probes)])
        main(["verify-answer", "--book", str(wrong), "--probes", str(probes),
              "--salt", "s2", "--out", str(answers)])
        rc = main(["verify-check", "--book", book_file,
                   "--probes", str(probes), "--answers", str(answers),
                   "--salt", "s2"])
        assert rc == 1
        assert "MISMATCH" in capsys.readouterr().out
