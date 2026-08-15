"""Tests for the extended CLI: session, attack, otp, disguise commands."""

from __future__ import annotations

import pytest

from book_cipher_kit.cli import main

BOOK = (
    "The quick brown fox jumps over the lazy dog again and again.\n"
    "Pack my box with five dozen liquor jugs. Six big devils from Japan\n"
    "quickly forgot how to waltz. Amazingly few discotheques provide\n"
    "jukeboxes. The five boxing wizards jump quickly.\n"
    "How vexingly quick daft zebras jump! Sphinx of black quartz,\n"
    "judge my vow. Jackdaws love my big sphinx of quartz.\n"
)


@pytest.fixture
def book_file(tmp_path):
    p = tmp_path / "book.txt"
    p.write_text(BOOK, encoding="utf-8")
    return str(p)


class TestSessionCommands:
    def test_full_session_flow(self, book_file, tmp_path, capsys):
        sf = tmp_path / "session.json"
        assert main(["session-new", "--book", book_file, "--name", "ops",
                     "--out", str(sf)]) == 0
        capsys.readouterr()

        assert main(["session-add", "--book", book_file, "--session", str(sf),
                     "--message", "first contact", "--seed", "1",
                     "--page-start", "0", "--page-end", "3"]) == 0
        assert main(["session-add", "--book", book_file, "--session", str(sf),
                     "--message", "second message", "--seed", "2",
                     "--page-start", "3", "--page-end", "6"]) == 0
        capsys.readouterr()

        assert main(["session-info", "--session", str(sf)]) == 0
        info = capsys.readouterr().out
        assert "Messages: 2" in info

        assert main(["session-read", "--book", book_file, "--session", str(sf),
                     "--id", "msg-001"]) == 0
        assert capsys.readouterr().out.strip() == "first contact"

        assert main(["session-read", "--book", book_file, "--session", str(sf)]) == 0
        out = capsys.readouterr().out
        assert "first contact" in out and "second message" in out

    def test_session_range_reuse_refused(self, book_file, tmp_path, capsys):
        sf = tmp_path / "session.json"
        main(["session-new", "--book", book_file, "--out", str(sf)])
        main(["session-add", "--book", book_file, "--session", str(sf),
              "--message", "x", "--seed", "1", "--page-start", "0", "--page-end", "3"])
        capsys.readouterr()
        rc = main(["session-add", "--book", book_file, "--session", str(sf),
                   "--message", "y", "--seed", "2", "--page-start", "1", "--page-end", "4"])
        assert rc == 1
        assert "overlaps" in capsys.readouterr().err


class TestAttackCommand:
    def test_attack_with_book(self, book_file, tmp_path, capsys):
        coords = tmp_path / "coords.txt"
        main(["encode", "--book", book_file, "--message", "attack this text",
              "--out", str(coords), "--seed", "1"])
        capsys.readouterr()
        rc = main(["attack", "--input", str(coords), "--book", book_file])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Word structure" in out and "English score" in out

    def test_attack_json(self, book_file, tmp_path, capsys):
        import json
        coords = tmp_path / "coords.txt"
        main(["encode", "--book", book_file, "--message", "json attack",
              "--out", str(coords), "--seed", "1"])
        capsys.readouterr()
        rc = main(["attack", "--input", str(coords), "--json"])
        assert rc == 0
        report = json.loads(capsys.readouterr().out)
        assert "position_leakage" in report


class TestOtpCommands:
    def test_otp_roundtrip(self, book_file, tmp_path, capsys):
        enc = tmp_path / "otp.txt"
        rc = main(["otp-encrypt", "--book", book_file, "--message", "one time secret",
                   "--page-start", "0", "--page-end", "3", "--out", str(enc)])
        assert rc == 0
        capsys.readouterr()
        rc = main(["otp-decrypt", "--book", book_file, "--input", str(enc)])
        assert rc == 0
        assert capsys.readouterr().out.strip() == "one time secret"

    def test_otp_ledger_flow(self, book_file, tmp_path, capsys):
        ledger = tmp_path / "ledger.json"
        assert main(["otp-ledger", "--book", book_file, "--out", str(ledger)]) == 0
        capsys.readouterr()
        enc = tmp_path / "otp.txt"
        rc = main(["otp-encrypt", "--book", book_file, "--message", "burned once",
                   "--page-start", "0", "--page-end", "3",
                   "--ledger", str(ledger), "--out", str(enc)])
        assert rc == 0
        capsys.readouterr()
        # Reusing the same pages must fail.
        rc = main(["otp-encrypt", "--book", book_file, "--message", "again",
                   "--page-start", "1", "--page-end", "4",
                   "--ledger", str(ledger), "--out", str(enc)])
        assert rc == 1
        assert "burned" in capsys.readouterr().err


class TestDisguiseCommands:
    def test_disguise_roundtrip_invoice(self, book_file, tmp_path, capsys):
        coords = tmp_path / "coords.txt"
        main(["encode", "--book", book_file, "--message", "disguised cargo",
              "--out", str(coords), "--seed", "1"])
        capsys.readouterr()
        doc = tmp_path / "invoice.txt"
        rc = main(["disguise-hide", "--input", str(coords), "--scheme", "invoice",
                   "--out", str(doc)])
        assert rc == 0
        capsys.readouterr()
        rc = main(["disguise-reveal", "--input", str(doc), "--scheme", "invoice",
                   "--book", book_file])
        assert rc == 0
        assert capsys.readouterr().out.strip() == "disguised cargo"

    @pytest.mark.parametrize("scheme", ["shopping", "log", "invoice", "schedule"])
    def test_all_schemes_positions_roundtrip(self, scheme, tmp_path, capsys):
        # Position-level roundtrip without a book.
        from book_cipher_kit import positions_to_text, text_to_positions
        coords = tmp_path / "coords.txt"
        coords.write_text(positions_to_text([(0, 2, 1), (1, 3, 0), (2, -1, -1)]),
                          encoding="utf-8")
        doc = tmp_path / "doc.txt"
        assert main(["disguise-hide", "--input", str(coords), "--scheme", scheme,
                     "--out", str(doc)]) == 0
        capsys.readouterr()
        assert main(["disguise-reveal", "--input", str(doc), "--scheme", scheme]) == 0
        out = capsys.readouterr().out
        assert text_to_positions(out) == [(0, 2, 1), (1, 3, 0), (2, -1, -1)]
