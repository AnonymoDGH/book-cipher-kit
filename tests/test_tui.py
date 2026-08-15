"""Tests for book_cipher_kit.tui -- the interactive shell."""

from __future__ import annotations

import io

import pytest

from book_cipher_kit.tui import TuiState, run_command, run_loop

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
def state(book_file):
    s = TuiState()
    s.load(book_file)
    return s


class TestCommands:
    def test_open(self, book_file):
        s = TuiState()
        out = run_command(s, f"open {book_file}")
        assert "Loaded" in out
        assert s.index is not None

    def test_require_book_error(self):
        s = TuiState()
        from book_cipher_kit import BookCipherError
        with pytest.raises(BookCipherError):
            run_command(s, "encode hello")

    def test_info(self, state):
        out = run_command(state, "info")
        assert "coverage" in out and "fingerprint" in out

    def test_encode_decode_roundtrip(self, state):
        triples = run_command(state, "encode meet at dawn")
        assert "." in triples
        decoded = run_command(state, f"decode {triples.replace(chr(10), ' ')}")
        assert decoded == "meet at dawn"

    def test_stats(self, state):
        out = run_command(state, "stats")
        assert "found" in out and "missing" in out

    def test_finger(self, state):
        out = run_command(state, "finger")
        assert len(out) == 64

    def test_help(self, state):
        out = run_command(state, "help")
        assert "open" in out and "quit" in out

    def test_unknown_command(self, state):
        out = run_command(state, "frobnicate")
        assert "Unknown command" in out

    def test_empty_line(self, state):
        assert run_command(state, "   ") == ""

    def test_quit_raises_systemexit(self, state):
        with pytest.raises(SystemExit):
            run_command(state, "quit")


class TestRunLoop:
    def test_loop_drives_commands(self, book_file):
        script = f"open {book_file}\nencode hello world\nquit\n"
        out = io.StringIO()
        rc = run_loop(io.StringIO(script), out)
        assert rc == 0
        text = out.getvalue()
        assert "Book Cipher Kit" in text
        assert "." in text  # encoded triples

    def test_loop_handles_eof(self, book_file):
        out = io.StringIO()
        rc = run_loop(io.StringIO(""), out)
        assert rc == 0

    def test_loop_recovers_from_errors(self, book_file):
        script = "encode before loading\nquit\n"
        out = io.StringIO()
        rc = run_loop(io.StringIO(script), out)
        assert rc == 0
        assert "No book loaded" in out.getvalue()
