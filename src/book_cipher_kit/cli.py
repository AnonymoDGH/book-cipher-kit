"""Command-line interface for the Book Cipher Kit."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import (
    coverage, decode, encode, load_book,
    positions_to_text, text_to_positions,
)


def cmd_encode(args: argparse.Namespace) -> None:
    lines = load_book(args.book)
    positions = encode(args.message, lines, seed=args.seed)
    if args.out:
        Path(args.out).write_text(positions_to_text(positions), encoding="utf-8")
        print(f"[+] Encoded {len(args.message)} chars -> {args.out}")
    else:
        sys.stdout.write(positions_to_text(positions))


def cmd_decode(args: argparse.Namespace) -> None:
    lines = load_book(args.book)
    if args.positions:
        positions = text_to_positions(args.positions)
    elif args.input:
        positions = text_to_positions(Path(args.input).read_text(encoding="utf-8"))
    else:
        print("[!] Give --positions or --input.")
        sys.exit(1)
    print(decode(positions, lines))


def cmd_stats(args: argparse.Namespace) -> None:
    lines = load_book(args.book)
    c = coverage(lines)
    print(f"[*] Alphabet coverage: {c['percent']}%")
    print(f"[+] Found:   {''.join(c['found'])}")
    print(f"[-] Missing: {''.join(c['missing']) or 'none'}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="bookcipher",
        description="Encode and decode messages using a shared book.",
        epilog="Example: bookcipher encode --book novel.txt --message 'meet at dawn' --out coords.txt",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encode", help="turn a message into positions")
    p_enc.add_argument("--book", required=True, help="path to the shared book (text)")
    p_enc.add_argument("--message", required=True, help="the message to encode")
    p_enc.add_argument("--out", default=None, help="write positions to a file")
    p_enc.add_argument("--seed", type=int, default=None, help="deterministic output")
    p_enc.set_defaults(fn=cmd_encode)

    p_dec = sub.add_parser("decode", help="turn positions back into a message")
    p_dec.add_argument("--book", required=True)
    p_dec.add_argument("--positions", default=None, help='inline, e.g. "1.0.2 2.3.0"')
    p_dec.add_argument("--input", default=None, help="file of positions, one triple per line")
    p_dec.set_defaults(fn=cmd_decode)

    p_stats = sub.add_parser("stats", help="check what the book can encode")
    p_stats.add_argument("--book", required=True)
    p_stats.set_defaults(fn=cmd_stats)

    args = p.parse_args(argv)
    args.fn(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
