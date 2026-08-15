"""tui -- an interactive terminal interface for the Book Cipher Kit.

A curses-free, line-oriented interactive shell for people who want to work
with a book cipher without remembering subcommand flags. It reads commands
from stdin, prints results, and keeps the loaded book in memory between
commands so repeated encodes do not re-read the file.

The TUI is deliberately simple and dependency-free: it works over pipes
and in dumb terminals, which also makes it testable. Every command maps
onto a library function, so the TUI adds no new behavior -- only
ergonomics.

Commands
--------
open <path>          load a book
info                 coverage + fingerprint + word count
encode <text>        encode with the loaded book
decode <triples>     decode inline triples
stats                coverage report
finger               print the edition fingerprint
help                 list commands
quit                 exit
"""

from __future__ import annotations

import shlex
import sys
from typing import TextIO

from .core import (
    BookCipherError,
    coverage,
    decode,
    fingerprint,
    load_book,
    text_to_positions,
    word_count,
)
from .index import BookIndex

BANNER = """Book Cipher Kit -- interactive shell
Type 'help' for commands, 'quit' to exit.
"""

HELP = """Commands:
  open <path>      load a book from a text file
  info             show coverage, word count, and fingerprint
  encode <text>    encode text into positions (uses loaded book)
  decode <a.b.c>   decode space-separated triples
  stats            full alphabet coverage report
  finger           print the edition fingerprint
  help             show this help
  quit             exit the shell
"""


class TuiState:
    """Holds the loaded book and its index across commands."""

    def __init__(self) -> None:
        self.lines: list[str] | None = None
        self.index: BookIndex | None = None
        self.path: str | None = None

    def require_book(self) -> BookIndex:
        if self.index is None:
            raise BookCipherError("No book loaded. Use: open <path>")
        return self.index

    def load(self, path: str) -> str:
        self.lines = load_book(path)
        self.index = BookIndex(self.lines)
        self.path = path
        return f"Loaded {path}: {word_count(self.lines)} words"


def run_command(state: TuiState, line: str) -> str:
    """Execute one TUI command and return the text to print.

    Raises BookCipherError for user-facing errors; the caller renders
    them. Unknown commands return a hint rather than raising, so a typo
    does not kill the session.
    """
    line = line.strip()
    if not line:
        return ""
    try:
        # posix=False keeps Windows backslash paths intact.
        parts = shlex.split(line, posix=False)
    except ValueError:
        parts = line.split()
    cmd, rest = parts[0].lower(), parts[1:]

    if cmd in ("quit", "exit", "q"):
        raise SystemExit(0)
    if cmd == "help":
        return HELP.strip()
    if cmd == "open":
        if not rest:
            return "usage: open <path>"
        return state.load(rest[0])
    if cmd == "info":
        index = state.require_book()
        cov = index.coverage_report()
        return (
            f"book: {state.path}\n"
            f"words: {cov['words']}  coverage: {cov['percent']}%\n"
            f"fingerprint: {cov['fingerprint'][:16]}..."
        )
    if cmd == "encode":
        if not rest:
            return "usage: encode <text>"
        index = state.require_book()
        positions = index.encode(" ".join(rest))
        return "\n".join(f"{li}.{wi}.{ci}" for li, wi, ci in positions)
    if cmd == "decode":
        if not rest:
            return "usage: decode <a.b.c ...>"
        index = state.require_book()
        # Triples may arrive space- or newline-separated.
        positions = text_to_positions("\n".join(rest))
        return decode(positions, index.lines)
    if cmd == "stats":
        index = state.require_book()
        cov = index.coverage_report()
        return (
            f"coverage: {cov['percent']}%\n"
            f"found:   {''.join(cov['found'])}\n"
            f"missing: {''.join(cov['missing']) or 'none'}\n"
            f"extras:  {''.join(cov['extras']) or 'none'}"
        )
    if cmd == "finger":
        index = state.require_book()
        return index.fingerprint
    return f"Unknown command: {cmd}. Type 'help'."


def run_loop(in_stream: TextIO = None, out_stream: TextIO = None) -> int:
    """Run the interactive loop until EOF or 'quit'.

    Reads from in_stream (default stdin) and writes to out_stream (default
    stdout), so tests can drive it with StringIO.
    """
    in_stream = in_stream or sys.stdin
    out_stream = out_stream or sys.stdout
    state = TuiState()
    out_stream.write(BANNER)
    while True:
        out_stream.write("bookcipher> ")
        out_stream.flush()
        line = in_stream.readline()
        if not line:  # EOF
            out_stream.write("\n")
            return 0
        try:
            result = run_command(state, line)
        except SystemExit:
            return 0
        except BookCipherError as exc:
            out_stream.write(f"[!] {exc}\n")
            continue
        if result:
            out_stream.write(result + "\n")


__all__ = ["BANNER", "HELP", "TuiState", "run_command", "run_loop"]
