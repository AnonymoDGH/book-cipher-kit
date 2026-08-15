"""CLI tests for share-split/combine, voice-hide/reveal, audit-log/verify."""

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
def positions_file(tmp_path, book_file):
    p = tmp_path / "pos.txt"
    rc = main(["encode", "--book", book_file, "--message", "meet at dawn",
               "--seed", "3", "--out", str(p)])
    assert rc == 0
    return str(p)


class TestShareCli:
    def test_split_and_combine(self, tmp_path, capsys):
        outdir = tmp_path / "shares"
        rc = main(["share-split", "--secret", "buried treasure map",
                   "--k", "2", "--n", "3", "--seed", "11",
                   "--out-dir", str(outdir)])
        assert rc == 0
        files = sorted(outdir.glob("share-*.txt"))
        assert len(files) == 3

        rc = main(["share-combine",
                   "--share", str(files[0]), "--share", str(files[2])])
        assert rc == 0
        assert "buried treasure map" in capsys.readouterr().out

    def test_combine_too_few_shares(self, tmp_path, capsys):
        outdir = tmp_path / "shares"
        main(["share-split", "--secret", "secret", "--k", "3", "--n", "4",
              "--seed", "5", "--out-dir", str(outdir)])
        files = sorted(outdir.glob("share-*.txt"))
        rc = main(["share-combine", "--share", str(files[0]),
                   "--share", str(files[1])])
        assert rc == 1
        assert "Need 3 shares" in capsys.readouterr().out

    def test_combine_to_file(self, tmp_path, capsys):
        outdir = tmp_path / "shares"
        main(["share-split", "--secret", "binary-safe", "--k", "2", "--n", "2",
              "--seed", "9", "--out-dir", str(outdir)])
        files = sorted(outdir.glob("share-*.txt"))
        out = tmp_path / "recovered.txt"
        rc = main(["share-combine", "--share", str(files[0]),
                   "--share", str(files[1]), "--out", str(out)])
        assert rc == 0
        assert out.read_text(encoding="utf-8") == "binary-safe"


class TestVoiceCli:
    def test_hide_and_reveal(self, tmp_path, positions_file, book_file, capsys):
        voice = tmp_path / "voice.txt"
        rc = main(["voice-hide", "--input", positions_file,
                   "--out", str(voice)])
        assert rc == 0
        text = voice.read_text(encoding="utf-8")
        assert "CHECK" in text

        rc = main(["voice-reveal", "--input", str(voice), "--book", book_file])
        assert rc == 0
        assert "meet at dawn" in capsys.readouterr().out

    def test_reveal_inline_text(self, tmp_path, positions_file, capsys):
        voice = tmp_path / "voice.txt"
        main(["voice-hide", "--input", positions_file, "--out", str(voice)])
        text = voice.read_text(encoding="utf-8").strip()
        rc = main(["voice-reveal", "--text", text])
        assert rc == 0
        out = capsys.readouterr().out
        assert "." in out  # dotted positions

    def test_reveal_no_input_fails(self, capsys):
        rc = main(["voice-reveal"])
        assert rc == 1


class TestAuditCli:
    def test_log_and_verify(self, tmp_path, book_file, capsys):
        log = tmp_path / "audit.log"
        rc = main(["audit-log", "--log", str(log), "--op", "open-book",
                   "--detail", "gettysburg", "--book", book_file])
        assert rc == 0
        rc = main(["audit-log", "--log", str(log), "--op", "encode",
                   "--detail", "meet at dawn"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "seq=2" in out

        rc = main(["audit-verify", "--log", str(log)])
        assert rc == 0
        assert "intact" in capsys.readouterr().out

    def test_verify_detects_tamper(self, tmp_path, capsys):
        log = tmp_path / "audit.log"
        main(["audit-log", "--log", str(log), "--op", "encode"])
        # Tamper with the record detail.
        text = log.read_text(encoding="utf-8")
        tampered = text.replace('"op": "encode"', '"op": "evil"')
        assert tampered != text
        log.write_text(tampered, encoding="utf-8")
        rc = main(["audit-verify", "--log", str(log)])
        assert rc == 1
        assert "BROKEN" in capsys.readouterr().out
