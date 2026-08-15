"""CLI tests for the send/receive/describe protocol subcommands."""

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


class TestProtocolCli:
    def test_send_receive_plain(self, book_file, tmp_path, capsys):
        env = tmp_path / "env.json"
        rc = main(["send", "--book", book_file, "--message", "meet at dawn",
                   "--out", str(env)])
        assert rc == 0
        rc = main(["receive", "--book", book_file, "--input", str(env)])
        assert rc == 0
        assert "meet at dawn" in capsys.readouterr().out

    def test_send_receive_encrypted(self, book_file, tmp_path, capsys):
        env = tmp_path / "env.json"
        rc = main(["send", "--book", book_file, "--message", "secret plan",
                   "--passphrase", "hunter2", "--kdf-iterations", "1000",
                   "--out", str(env)])
        assert rc == 0
        rc = main(["receive", "--book", book_file, "--input", str(env),
                   "--passphrase", "hunter2"])
        assert rc == 0
        assert "secret plan" in capsys.readouterr().out

    def test_send_receive_disguised(self, book_file, tmp_path, capsys):
        env = tmp_path / "env.json"
        rc = main(["send", "--book", book_file, "--message", "meet at dawn",
                   "--scheme", "invoice", "--out", str(env)])
        assert rc == 0
        rc = main(["receive", "--book", book_file, "--input", str(env)])
        assert rc == 0
        assert "meet at dawn" in capsys.readouterr().out

    def test_describe(self, book_file, tmp_path, capsys):
        env = tmp_path / "env.json"
        main(["send", "--book", book_file, "--message", "hi",
              "--passphrase", "pw", "--kdf-iterations", "1000",
              "--out", str(env)])
        rc = main(["describe", "--input", str(env)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "encrypt" in out and "stages=" in out

    def test_send_with_audit(self, book_file, tmp_path, capsys):
        env = tmp_path / "env.json"
        audit_log = tmp_path / "audit.log"
        rc = main(["send", "--book", book_file, "--message", "audited",
                   "--audit", str(audit_log), "--out", str(env)])
        assert rc == 0
        assert audit_log.exists()
        rc = main(["receive", "--book", book_file, "--input", str(env),
                   "--audit", str(audit_log)])
        assert rc == 0
        # Both encode and decode steps landed in the audit trail.
        text = audit_log.read_text(encoding="utf-8")
        assert "encode" in text and "decode" in text

    def test_conflicting_layers_rejected(self, book_file, tmp_path, capsys):
        rc = main(["send", "--book", book_file, "--message", "x",
                   "--passphrase", "pw", "--scheme", "invoice"])
        assert rc == 1
        assert "mutually exclusive" in capsys.readouterr().err
