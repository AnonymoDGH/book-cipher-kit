"""Command-line interface for the Book Cipher Kit.

Subcommands cover the whole workflow: encode/decode, book statistics,
format conversion, encryption, steganography, security analysis, and
diagnostics. Run 'bookcipher <cmd> --help' for per-command options.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import (
    analysis,
    audit,
    corpus,
    cryptanalysis,
    crypto,
    doctor,
    exchange,
    formats,
    grid,
    mnemonic,
    obfuscate,
    otp,
    protocol,
    share,
    wordmap,
)
from .core import (
    BookCipherError,
    coverage,
    decode,
    diff_books,
    encode,
    fingerprint,
    load_book,
    positions_to_text,
    text_to_positions,
)
from .index import BookIndex
from .session import Session
from .stego import (
    acrostic_to_message,
    cover_text_stats,
    cover_text_to_positions,
    message_to_acrostic,
    message_to_null_cipher,
    null_cipher_to_message,
    positions_to_cover_text,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _read_positions(args: argparse.Namespace) -> list[tuple[int, int, int]]:
    """Load positions from --positions (inline) or --input (file, any format)."""
    if getattr(args, "positions", None):
        return text_to_positions(args.positions)
    if getattr(args, "input", None):
        text = Path(args.input).read_text(encoding="utf-8")
        return formats.deserialize(text)
    print("[!] Give --positions or --input.")
    sys.exit(1)


def _write_output(text: str, out: str | None, note: str) -> None:
    if out:
        Path(out).write_text(text, encoding="utf-8")
        print(note)
    else:
        sys.stdout.write(text)


def _get_passphrase(args: argparse.Namespace, confirm: bool) -> str:
    if getattr(args, "passphrase", None):
        return args.passphrase
    pw = getpass.getpass("Passphrase: ")
    if confirm:
        again = getpass.getpass("Confirm:  ")
        if pw != again:
            print("[!] Passphrases do not match.")
            sys.exit(1)
    return pw


# ---------------------------------------------------------------------------
# encode / decode / stats
# ---------------------------------------------------------------------------

def cmd_encode(args: argparse.Namespace) -> None:
    lines = load_book(args.book)
    index = BookIndex(lines)
    avoid = set()
    if args.avoid_lines:
        avoid = {int(x) for x in args.avoid_lines.split(",") if x.strip()}
    positions = index.encode(
        args.message, seed=args.seed,
        avoid_lines=avoid or None, prefer_rare=args.prefer_rare,
    )
    fmt = args.format
    if fmt == "stego":
        text = positions_to_cover_text(positions, seed=args.seed or 0)
    else:
        text = formats.serialize(positions, fmt)
    _write_output(
        text, args.out,
        f"[+] Encoded {len(args.message)} chars -> {args.out} ({fmt})",
    )


def cmd_decode(args: argparse.Namespace) -> None:
    lines = load_book(args.book)
    if getattr(args, "cover", None):
        text = Path(args.cover).read_text(encoding="utf-8")
        positions = cover_text_to_positions(text)
    else:
        positions = _read_positions(args)
    print(decode(positions, lines))


def cmd_stats(args: argparse.Namespace) -> None:
    lines = load_book(args.book)
    c = coverage(lines)
    print(f"[*] Alphabet coverage: {c['percent']}%")
    print(f"[+] Found:   {''.join(c['found'])}")
    print(f"[-] Missing: {''.join(c['missing']) or 'none'}")
    print(f"[*] Extras (digits/punct): {''.join(c['extras']) or 'none'}")
    print(f"[*] Total encodable positions: {c['total_positions']}")
    print(f"[*] Words: {sum(len(ln.split()) for ln in lines)}")
    print(f"[*] Fingerprint: {fingerprint(lines)[:16]}...")
    if args.histogram:
        from .core import char_histogram
        hist = char_histogram(lines)
        top = list(hist.items())[:12]
        print("[*] Top characters: " + ", ".join(f"{ch}:{n}" for ch, n in top))


# ---------------------------------------------------------------------------
# corpus
# ---------------------------------------------------------------------------

def cmd_corpus(args: argparse.Namespace) -> None:
    if args.list:
        for name in corpus.list_embedded():
            lines = corpus.get_embedded(name)
            words = sum(len(ln.split()) for ln in lines)
            print(f"{name:<14} {words:>6} words  {corpus.describe_embedded(name)}")
        return
    if args.generate:
        lines = corpus.generate_prose(
            paragraphs=args.paragraphs, seed=args.seed, wrap=args.wrap,
        )
    else:
        name = args.name or "sun_tzu"
        lines = corpus.get_embedded(name)
        if args.pad:
            lines = lines + [""] + corpus.generate_prose(
                paragraphs=args.pad, seed=args.seed,
            )
    text = "\n".join(lines) + "\n"
    _write_output(text, args.out, f"[+] Wrote {len(lines)} lines -> {args.out}")


# ---------------------------------------------------------------------------
# convert / fingerprint / diff
# ---------------------------------------------------------------------------

def cmd_convert(args: argparse.Namespace) -> None:
    text = Path(args.input).read_text(encoding="utf-8")
    positions = formats.deserialize(text, args.from_format)
    out = formats.serialize(positions, args.to_format)
    _write_output(
        out, args.out,
        f"[+] Converted {len(positions)} positions {args.from_format or 'auto'} -> {args.to_format}",
    )


def cmd_fingerprint(args: argparse.Namespace) -> None:
    lines = load_book(args.book)
    print(fingerprint(lines))


def cmd_diff(args: argparse.Namespace) -> None:
    a = load_book(args.book_a)
    b = load_book(args.book_b)
    d = diff_books(a, b)
    print(f"[*] Lines: {d['lines_a']} vs {d['lines_b']}")
    print(f"[*] Same word stream: {'yes' if d['same_word_stream'] else 'NO'}")
    print(f"[*] Fingerprint A: {d['fingerprint_a'][:16]}...")
    print(f"[*] Fingerprint B: {d['fingerprint_b'][:16]}...")
    if d["first_differing_lines"]:
        shown = ", ".join(str(x) for x in d["first_differing_lines"])
        print(f"[-] First differing lines: {shown}")
    else:
        print("[+] No differing lines.")


# ---------------------------------------------------------------------------
# encrypt / decrypt
# ---------------------------------------------------------------------------

def cmd_encrypt(args: argparse.Namespace) -> None:
    positions = _read_positions(args)
    pw = _get_passphrase(args, confirm=True)
    ad = b""
    if args.bind_book:
        ad = fingerprint(load_book(args.bind_book)).encode()
    armored = crypto.encrypt_to_text(
        positions, pw, associated_data=ad, iterations=args.kdf_iterations,
    )
    _write_output(armored, args.out, f"[+] Encrypted {len(positions)} positions -> {args.out}")


def cmd_decrypt(args: argparse.Namespace) -> None:
    armored = Path(args.input).read_text(encoding="utf-8")
    pw = _get_passphrase(args, confirm=False)
    ad = b""
    if args.bind_book:
        ad = fingerprint(load_book(args.bind_book)).encode()
    positions = crypto.decrypt_from_text(
        armored, pw, associated_data=ad, iterations=args.kdf_iterations,
    )
    if args.book:
        print(decode(positions, load_book(args.book)))
    else:
        sys.stdout.write(positions_to_text(positions))


def cmd_passprint(args: argparse.Namespace) -> None:
    pw = _get_passphrase(args, confirm=False)
    print(crypto.passphrase_fingerprint(pw, iterations=args.kdf_iterations))


# ---------------------------------------------------------------------------
# steganography
# ---------------------------------------------------------------------------

def cmd_stego_hide(args: argparse.Namespace) -> None:
    positions = _read_positions(args)
    text = positions_to_cover_text(positions, seed=args.seed)
    stats = cover_text_stats(text)
    _write_output(text, args.out, f"[+] Hid {len(positions)} positions -> {args.out}")
    print(
        f"[*] cover: {stats['sentences']} sentences, "
        f"avg {stats['avg_sentence_words']} words, "
        f"!-fraction {stats['exclamation_fraction']}",
        file=sys.stderr,
    )


def cmd_stego_reveal(args: argparse.Namespace) -> None:
    text = Path(args.input).read_text(encoding="utf-8")
    positions = cover_text_to_positions(text)
    if args.book:
        print(decode(positions, load_book(args.book)))
    else:
        sys.stdout.write(positions_to_text(positions))


def cmd_acrostic(args: argparse.Namespace) -> None:
    if args.decode:
        text = Path(args.input).read_text(encoding="utf-8")
        print(acrostic_to_message(text))
    else:
        text = message_to_acrostic(args.message, seed=args.seed)
        _write_output(text, args.out, f"[+] Acrostic -> {args.out}")


def cmd_null(args: argparse.Namespace) -> None:
    if args.decode:
        text = Path(args.input).read_text(encoding="utf-8")
        print(null_cipher_to_message(text, n=args.stride))
    else:
        text = message_to_null_cipher(args.message, n=args.stride, seed=args.seed)
        _write_output(text, args.out, f"[+] Null cipher (stride {args.stride}) -> {args.out}")


# ---------------------------------------------------------------------------
# analyze / doctor
# ---------------------------------------------------------------------------

def cmd_analyze(args: argparse.Namespace) -> None:
    positions = _read_positions(args)
    lines = load_book(args.book) if args.book else None
    report = analysis.security_report(positions, lines)
    if args.json:
        print(json.dumps(report, indent=2))
        return
    s = report["spread"]
    r = report["reuse"]
    st = report["structure"]
    print(f"[*] Message: {st['message_length']} chars in {st['word_count']} words")
    if "lines_used" in s:
        print(f"[*] Spread: {s['lines_used']} lines, concentration {s['concentration']}")
    print(f"[*] Reuse: {r['reused_positions']} reused positions ({r['reuse_fraction']})")
    print(f"[*] Entropy model: {report['entropy']['bits']} bits")
    print(f"[*] Book bounds leaked: >= {st['book_bounds']['min_lines']} lines")
    for w in report["warnings"]:
        print(f"[-] {w}")
    print(f"[*] Verdict: {report['verdict']}")


def cmd_doctor(args: argparse.Namespace) -> None:
    if args.input:
        text = Path(args.input).read_text(encoding="utf-8")
        if args.book:
            checks = doctor.diagnose_pair(args.book, text)
        else:
            checks = doctor.diagnose_positions_text(text)
    elif args.book:
        checks = doctor.diagnose_book(args.book)
    else:
        print("[!] Give --book and/or --input.")
        sys.exit(1)
    print(doctor.format_report(checks))
    return 0 if doctor.report_is_healthy(checks) else 1


# ---------------------------------------------------------------------------
# session
# ---------------------------------------------------------------------------

def cmd_session_new(args: argparse.Namespace) -> None:
    lines = load_book(args.book)
    session = Session(fingerprint(lines), name=args.name)
    session.save(args.out)
    print(f"[+] New session '{args.name}' -> {args.out}")


def cmd_session_add(args: argparse.Namespace) -> None:
    lines = load_book(args.book)
    session = Session.load(args.session)
    record = session.add_message(
        args.message, lines, seed=args.seed,
        message_id=args.id, page_start=args.page_start, page_end=args.page_end,
    )
    session.save(args.session)
    print(f"[+] Added {record['id']} ({record['chars']} chars) -> {args.session}")


def cmd_session_read(args: argparse.Namespace) -> None:
    lines = load_book(args.book)
    session = Session.load(args.session)
    if args.id:
        print(session.decode_message(args.id, lines))
    else:
        for m in session.messages:
            print(f"--- {m['id']} ---")
            print(session.decode_message(m["id"], lines))


def cmd_session_info(args: argparse.Namespace) -> None:
    session = Session.load(args.session)
    s = session.summary()
    print(f"[*] Session: {s['name']}")
    print(f"[*] Book fingerprint: {s['book_fingerprint'][:16]}...")
    print(f"[*] Messages: {s['messages']} ({s['total_chars']} chars)")
    for mid in s["ids"]:
        print(f"    - {mid}")


# ---------------------------------------------------------------------------
# attack (cryptanalysis yardstick)
# ---------------------------------------------------------------------------

def cmd_attack(args: argparse.Namespace) -> None:
    positions = _read_positions(args)
    lines = load_book(args.book) if args.book else None
    report = cryptanalysis.attack_report(positions, lines)
    if args.json:
        print(json.dumps(report, indent=2))
        return
    leak = report["position_leakage"]
    words = report["word_structure"]
    print(f"[*] Positions: {leak.get('positions', 0)}")
    if "line_entropy" in leak:
        print(f"[*] Line entropy: {leak['line_entropy']} bits")
        print(f"[*] Char-index IoC: {leak['char_index_ioc']}")
    print(f"[*] Word structure: {words['signature']}")
    if "plaintext" in report:
        pt = report["plaintext"]
        print(f"[*] Plaintext IoC: {pt['iocs']} (English ~0.065)")
        print(f"[*] Chi-squared: {pt['chi_squared']}")
        print(f"[*] English score: {pt['english_score']}")


# ---------------------------------------------------------------------------
# otp (book-derived one-time pad)
# ---------------------------------------------------------------------------

def cmd_otp_encrypt(args: argparse.Namespace) -> None:
    lines = load_book(args.book)
    if args.ledger:
        ledger = otp.PadLedger.load(args.ledger)
        armored = ledger.encrypt(args.message, lines, args.page_start, args.page_end)
        ledger.save(args.ledger)
        print(f"[+] Encrypted and burned pages {args.page_start}-{args.page_end}")
    else:
        armored = otp.pad_encrypt_to_text(
            args.message, lines, args.page_start, args.page_end, args.counter,
        )
    _write_output(armored, args.out, f"[+] OTP ciphertext -> {args.out}")


def cmd_otp_decrypt(args: argparse.Namespace) -> None:
    lines = load_book(args.book)
    armored = Path(args.input).read_text(encoding="utf-8")
    print(otp.pad_decrypt_from_text(armored, lines))


def cmd_otp_ledger(args: argparse.Namespace) -> None:
    lines = load_book(args.book)
    ledger = otp.PadLedger(fingerprint(lines))
    ledger.save(args.out)
    print(f"[+] New pad ledger -> {args.out} ({len(lines)} pages available)")


# ---------------------------------------------------------------------------
# disguise (obfuscation schemes)
# ---------------------------------------------------------------------------

def cmd_disguise_hide(args: argparse.Namespace) -> None:
    positions = _read_positions(args)
    text = obfuscate.hide(positions, args.scheme, seed=args.seed)
    _write_output(text, args.out, f"[+] Disguised as {args.scheme} -> {args.out}")


def cmd_disguise_reveal(args: argparse.Namespace) -> None:
    text = Path(args.input).read_text(encoding="utf-8")
    positions = obfuscate.reveal(text, args.scheme)
    if args.book:
        print(decode(positions, load_book(args.book)))
    else:
        sys.stdout.write(positions_to_text(positions))


# ---------------------------------------------------------------------------
# secret sharing
# ---------------------------------------------------------------------------

def cmd_share_split(args: argparse.Namespace) -> None:
    """Split a passphrase or file into k-of-n Shamir shares."""
    if args.secret is not None:
        secret = args.secret.encode("utf-8")
    elif args.secret_file:
        secret = Path(args.secret_file).read_bytes()
    else:
        secret = getpass.getpass("Secret to split: ").encode("utf-8")
    import random as _random
    rng = _random.Random(args.seed) if args.seed is not None else None
    shares = share.split_secret(secret, args.k, args.n, rng=rng)
    fp = share.secret_fingerprint(secret)
    outdir = Path(args.out_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    for s in shares:
        # Each file carries one share; n=1 describes the file, while k and
        # the fingerprint carry the recovery parameters.
        text = share.serialize_shares([s], args.k, 1, fp)
        path = outdir / f"share-{s.x:02d}.txt"
        path.write_text(text, encoding="utf-8")
        print(f"[+] {path}  fingerprint={share.share_fingerprint(s)}")
    print(f"[+] Secret fingerprint: {fp} (any {args.k} of {args.n} shares recover it)")


def cmd_share_combine(args: argparse.Namespace) -> None:
    """Recover a secret from share files and verify its fingerprint."""
    shares = []
    k = n = 0
    fp = ""
    for path in args.share:
        text = Path(path).read_text(encoding="utf-8")
        parsed, k, n, fp = share.parse_shares(text)
        shares.extend(parsed)
    if len(shares) < k:
        print(f"[!] Need {k} shares, only {len(shares)} given.")
        return 1
    if not share.verify_share_set(shares, k, fp):
        print("[!] Share set does not verify against its fingerprint.")
        return 1
    secret = share.combine_shares(shares[:k])
    if args.out:
        Path(args.out).write_bytes(secret)
        print(f"[+] Recovered {len(secret)} bytes -> {args.out}")
    else:
        try:
            print(secret.decode("utf-8"))
        except UnicodeDecodeError:
            sys.stdout.buffer.write(secret)


# ---------------------------------------------------------------------------
# voice (word map)
# ---------------------------------------------------------------------------

def cmd_voice_hide(args: argparse.Namespace) -> None:
    """Render positions as a checksummed voice string."""
    positions = _read_positions(args)
    text = wordmap.format_for_voice(positions, group_size=args.group)
    _write_output(text + "\n", args.out, f"[+] Voice string -> {args.out}")


def cmd_voice_reveal(args: argparse.Namespace) -> None:
    """Parse a voice string back into positions, verifying the checksum."""
    text = Path(args.input).read_text(encoding="utf-8") if args.input else args.text
    if not text:
        print("[!] Give --text or --input.")
        return 1
    positions = wordmap.parse_voice(text)
    if args.book:
        print(decode(positions, load_book(args.book)))
    else:
        sys.stdout.write(positions_to_text(positions))


# ---------------------------------------------------------------------------
# audit trail
# ---------------------------------------------------------------------------

def cmd_audit_log(args: argparse.Namespace) -> None:
    """Append an operation record to a hash-chained audit log."""
    path = Path(args.log)
    if path.exists():
        log = audit.AuditLog.from_text(path.read_text(encoding="utf-8"))
    else:
        book_fp = fingerprint(load_book(args.book)) if args.book else ""
        log = audit.AuditLog(book_fingerprint=book_fp)
    rec = log.append(args.op, args.detail or "")
    path.write_text(log.to_text(), encoding="utf-8")
    print(f"[+] seq={rec.seq} op={rec.op} hash={rec.hash[:16]}... -> {path}")


def cmd_audit_verify(args: argparse.Namespace) -> int:
    """Verify the integrity of an audit log's hash chain."""
    text = Path(args.log).read_text(encoding="utf-8")
    log = audit.AuditLog.from_text(text)
    ok, problems = log.verify()
    if ok:
        print(f"[+] Audit log intact: {len(log.records)} records, "
              f"head={log.head_hash()[:16]}...")
        return 0
    print(f"[!] Audit log BROKEN: {len(problems)} problem(s)")
    for p in problems:
        print(f"    - {p}")
    return 1


# ---------------------------------------------------------------------------
# mnemonic (fingerprint word rendering)
# ---------------------------------------------------------------------------

def cmd_mnemonic(args: argparse.Namespace) -> None:
    """Render a book's fingerprint as a memorable word phrase."""
    lines = load_book(args.book)
    fp = fingerprint(lines)
    phrase = mnemonic.fingerprint_mnemonic(fp, words=args.words)
    print(f"fingerprint: {fp}")
    print(f"mnemonic:    {phrase}")


# ---------------------------------------------------------------------------
# protocol (end-to-end pipeline)
# ---------------------------------------------------------------------------

def cmd_protocol_send(args: argparse.Namespace) -> None:
    """Run the full send pipeline and emit a self-describing envelope."""
    lines = load_book(args.book)
    config = protocol.PipelineConfig(
        passphrase=args.passphrase,
        scheme=args.scheme,
        seed=args.seed,
        kdf_iterations=args.kdf_iterations,
    )
    log = None
    if args.audit:
        from pathlib import Path as _Path
        ap = _Path(args.audit)
        if ap.exists():
            log = audit.AuditLog.from_text(ap.read_text(encoding="utf-8"))
        else:
            log = audit.AuditLog(book_fingerprint=fingerprint(lines))
    envelope = protocol.send_message(args.message, lines, config=config,
                                     log=log)
    if log is not None and args.audit:
        Path(args.audit).write_text(log.to_text(), encoding="utf-8")
    _write_output(envelope, args.out, f"[+] Envelope -> {args.out}")


def cmd_protocol_receive(args: argparse.Namespace) -> int:
    """Run the full receive pipeline and print the plaintext."""
    lines = load_book(args.book)
    envelope = Path(args.input).read_text(encoding="utf-8")
    log = None
    if args.audit:
        ap = Path(args.audit)
        if ap.exists():
            log = audit.AuditLog.from_text(ap.read_text(encoding="utf-8"))
        else:
            log = audit.AuditLog(book_fingerprint=fingerprint(lines))
    message = protocol.receive_message(envelope, lines,
                                     passphrase=args.passphrase, log=log)
    if log is not None and args.audit:
        Path(args.audit).write_text(log.to_text(), encoding="utf-8")
    print(message)
    return 0


def cmd_protocol_describe(args: argparse.Namespace) -> None:
    """Summarize an envelope without decrypting it."""
    envelope = Path(args.input).read_text(encoding="utf-8")
    print(protocol.describe_envelope(envelope))


# ---------------------------------------------------------------------------
# checkerboard (compact numeric encoding)
# ---------------------------------------------------------------------------

def cmd_grid_show(args: argparse.Namespace) -> None:
    """Print the book-derived straddling checkerboard."""
    lines = load_book(args.book)
    board = grid.build_checkerboard(lines)
    print(board.describe())


def cmd_grid_encode(args: argparse.Namespace) -> None:
    """Encode a message to the compact digit stream."""
    lines = load_book(args.book)
    digits = grid.text_to_digits(args.message, lines)
    _write_output(digits + "\n", args.out, f"[+] Digit stream -> {args.out}")


def cmd_grid_decode(args: argparse.Namespace) -> None:
    """Decode a digit stream back to a message."""
    lines = load_book(args.book)
    digits = args.digits.strip()
    print(grid.digits_to_text(digits, lines))


# ---------------------------------------------------------------------------
# edition verification ceremony
# ---------------------------------------------------------------------------

def cmd_verify_challenge(args: argparse.Namespace) -> None:
    """Issue probes for an edition-verification ceremony."""
    import random as _random
    lines = load_book(args.book)
    rng = _random.Random(args.seed) if args.seed is not None else None
    probes = exchange.make_probes(lines, count=args.count, rng=rng)
    salt = args.salt
    out = "\n".join(f"{p.line}.{p.word}" for p in probes)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
        print(f"[+] {len(probes)} probes -> {args.out} (salt: {salt})")
    else:
        print(f"[+] Probes (salt: {salt}):")
        print(out)


def cmd_verify_answer(args: argparse.Namespace) -> None:
    """Answer ceremony probes with salted word digests."""
    lines = load_book(args.book)
    probes = []
    for token in Path(args.probes).read_text(encoding="utf-8").split():
        line_s, _, word_s = token.partition(".")
        probes.append(exchange.Probe(line=int(line_s), word=int(word_s)))
    answers = exchange.answer_probes(lines, probes, args.salt)
    out = "\n".join(answers)
    _write_output(out + "\n", args.out, f"[+] {len(answers)} answers -> {args.out}")


def cmd_verify_check(args: argparse.Namespace) -> int:
    """Check ceremony answers against your own copy of the book."""
    lines = load_book(args.book)
    probes = []
    for token in Path(args.probes).read_text(encoding="utf-8").split():
        line_s, _, word_s = token.partition(".")
        probes.append(exchange.Probe(line=int(line_s), word=int(word_s)))
    answers = Path(args.answers).read_text(encoding="utf-8").split()
    ok, bad = exchange.verify_answers(lines, probes, answers, args.salt)
    if ok:
        print(f"[+] Edition verified: {len(probes)}/{len(probes)} probes match.")
        return 0
    print(f"[!] Edition MISMATCH: {len(bad)} of {len(probes)} probes disagree "
          f"(indexes: {bad})")
    return 1


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
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
    p_enc.add_argument("--format", default="text",
                       choices=["text", "json", "csv", "hex", "base64", "stego"],
                       help="output format (default: text)")
    p_enc.add_argument("--avoid-lines", default=None,
                       help="comma-separated line numbers to never use")
    p_enc.add_argument("--prefer-rare", action="store_true",
                       help="weight choices toward rarer lines")
    p_enc.set_defaults(fn=cmd_encode)

    p_dec = sub.add_parser("decode", help="turn positions back into a message")
    p_dec.add_argument("--book", required=True)
    p_dec.add_argument("--positions", default=None, help='inline, e.g. "1.0.2 2.3.0"')
    p_dec.add_argument("--input", default=None, help="file of positions (any format)")
    p_dec.add_argument("--cover", default=None, help="file of stego cover prose")
    p_dec.set_defaults(fn=cmd_decode)

    p_stats = sub.add_parser("stats", help="check what the book can encode")
    p_stats.add_argument("--book", required=True)
    p_stats.add_argument("--histogram", action="store_true", help="show top characters")
    p_stats.set_defaults(fn=cmd_stats)

    p_corp = sub.add_parser("corpus", help="list or emit books")
    p_corp.add_argument("--list", action="store_true", help="list embedded books")
    p_corp.add_argument("--name", default=None, help="embedded book name")
    p_corp.add_argument("--generate", action="store_true", help="generate synthetic prose")
    p_corp.add_argument("--paragraphs", type=int, default=5)
    p_corp.add_argument("--pad", type=int, default=0, help="pad embedded book with N prose paragraphs")
    p_corp.add_argument("--seed", type=int, default=0)
    p_corp.add_argument("--wrap", type=int, default=72)
    p_corp.add_argument("--out", default=None)
    p_corp.set_defaults(fn=cmd_corpus)

    p_conv = sub.add_parser("convert", help="convert positions between formats")
    p_conv.add_argument("--input", required=True)
    p_conv.add_argument("--from", dest="from_format", default=None,
                        choices=[None, "text", "json", "csv", "hex", "base64"],
                        help="input format (default: sniff)")
    p_conv.add_argument("--to", dest="to_format", required=True,
                        choices=["text", "json", "csv", "hex", "base64"])
    p_conv.add_argument("--out", default=None)
    p_conv.set_defaults(fn=cmd_convert)

    p_fp = sub.add_parser("fingerprint", help="print the book's edition fingerprint")
    p_fp.add_argument("--book", required=True)
    p_fp.set_defaults(fn=cmd_fingerprint)

    p_diff = sub.add_parser("diff", help="compare two editions of a book")
    p_diff.add_argument("--book-a", required=True)
    p_diff.add_argument("--book-b", required=True)
    p_diff.set_defaults(fn=cmd_diff)

    p_encr = sub.add_parser("encrypt", help="encrypt positions with a passphrase")
    p_encr.add_argument("--positions", default=None)
    p_encr.add_argument("--input", default=None)
    p_encr.add_argument("--passphrase", default=None, help="omit to be prompted")
    p_encr.add_argument("--bind-book", default=None,
                        help="bind the ciphertext to a book's fingerprint")
    p_encr.add_argument("--kdf-iterations", type=int, default=crypto.KDF_ITERATIONS,
                        help="PBKDF2 cost (default: %(default)s)")
    p_encr.add_argument("--out", default=None)
    p_encr.set_defaults(fn=cmd_encrypt)

    p_decr = sub.add_parser("decrypt", help="decrypt an encrypted positions payload")
    p_decr.add_argument("--input", required=True)
    p_decr.add_argument("--passphrase", default=None, help="omit to be prompted")
    p_decr.add_argument("--bind-book", default=None)
    p_decr.add_argument("--kdf-iterations", type=int, default=crypto.KDF_ITERATIONS,
                        help="PBKDF2 cost, must match the encrypt side")
    p_decr.add_argument("--book", default=None, help="also decode against this book")
    p_decr.set_defaults(fn=cmd_decrypt)

    p_pp = sub.add_parser("passprint", help="show a passphrase's safe fingerprint")
    p_pp.add_argument("--passphrase", default=None)
    p_pp.add_argument("--kdf-iterations", type=int, default=crypto.KDF_ITERATIONS)
    p_pp.set_defaults(fn=cmd_passprint)

    p_sh = sub.add_parser("stego-hide", help="hide positions inside generated prose")
    p_sh.add_argument("--positions", default=None)
    p_sh.add_argument("--input", default=None)
    p_sh.add_argument("--seed", type=int, default=0)
    p_sh.add_argument("--out", default=None)
    p_sh.set_defaults(fn=cmd_stego_hide)

    p_sr = sub.add_parser("stego-reveal", help="recover positions from cover prose")
    p_sr.add_argument("--input", required=True)
    p_sr.add_argument("--book", default=None, help="also decode against this book")
    p_sr.set_defaults(fn=cmd_stego_reveal)

    p_ac = sub.add_parser("acrostic", help="hide a message in line-initial letters")
    p_ac.add_argument("--message", default=None)
    p_ac.add_argument("--decode", action="store_true")
    p_ac.add_argument("--input", default=None)
    p_ac.add_argument("--seed", type=int, default=0)
    p_ac.add_argument("--out", default=None)
    p_ac.set_defaults(fn=cmd_acrostic)

    p_nl = sub.add_parser("null", help="hide a message in every Nth word")
    p_nl.add_argument("--message", default=None)
    p_nl.add_argument("--decode", action="store_true")
    p_nl.add_argument("--input", default=None)
    p_nl.add_argument("--stride", type=int, default=5)
    p_nl.add_argument("--seed", type=int, default=0)
    p_nl.add_argument("--out", default=None)
    p_nl.set_defaults(fn=cmd_null)

    p_an = sub.add_parser("analyze", help="security analysis of a positions list")
    p_an.add_argument("--positions", default=None)
    p_an.add_argument("--input", default=None)
    p_an.add_argument("--book", default=None)
    p_an.add_argument("--json", action="store_true")
    p_an.set_defaults(fn=cmd_analyze)

    p_doc = sub.add_parser("doctor", help="diagnose a failing decode session")
    p_doc.add_argument("--book", default=None)
    p_doc.add_argument("--input", default=None)
    p_doc.set_defaults(fn=cmd_doctor)

    # -- session --
    p_sn = sub.add_parser("session-new", help="create a new session file")
    p_sn.add_argument("--book", required=True)
    p_sn.add_argument("--name", default="session")
    p_sn.add_argument("--out", required=True)
    p_sn.set_defaults(fn=cmd_session_new)

    p_sa = sub.add_parser("session-add", help="encode and append a message")
    p_sa.add_argument("--book", required=True)
    p_sa.add_argument("--session", required=True)
    p_sa.add_argument("--message", required=True)
    p_sa.add_argument("--seed", type=int, default=None)
    p_sa.add_argument("--id", default=None)
    p_sa.add_argument("--page-start", type=int, default=0)
    p_sa.add_argument("--page-end", type=int, default=None)
    p_sa.set_defaults(fn=cmd_session_add)

    p_sr2 = sub.add_parser("session-read", help="decode session messages")
    p_sr2.add_argument("--book", required=True)
    p_sr2.add_argument("--session", required=True)
    p_sr2.add_argument("--id", default=None, help="read one message by id")
    p_sr2.set_defaults(fn=cmd_session_read)

    p_si = sub.add_parser("session-info", help="summarize a session")
    p_si.add_argument("--session", required=True)
    p_si.set_defaults(fn=cmd_session_info)

    # -- attack --
    p_at = sub.add_parser("attack", help="run read-only cryptanalysis yardsticks")
    p_at.add_argument("--positions", default=None)
    p_at.add_argument("--input", default=None)
    p_at.add_argument("--book", default=None)
    p_at.add_argument("--json", action="store_true")
    p_at.set_defaults(fn=cmd_attack)

    # -- otp --
    p_oe = sub.add_parser("otp-encrypt", help="encrypt with a book-derived one-time pad")
    p_oe.add_argument("--book", required=True)
    p_oe.add_argument("--message", required=True)
    p_oe.add_argument("--page-start", type=int, required=True)
    p_oe.add_argument("--page-end", type=int, required=True)
    p_oe.add_argument("--counter", type=int, default=0)
    p_oe.add_argument("--ledger", default=None, help="pad ledger to enforce one-time use")
    p_oe.add_argument("--out", default=None)
    p_oe.set_defaults(fn=cmd_otp_encrypt)

    p_od = sub.add_parser("otp-decrypt", help="decrypt a book-OTP payload")
    p_od.add_argument("--book", required=True)
    p_od.add_argument("--input", required=True)
    p_od.set_defaults(fn=cmd_otp_decrypt)

    p_ol = sub.add_parser("otp-ledger", help="create a new pad ledger")
    p_ol.add_argument("--book", required=True)
    p_ol.add_argument("--out", required=True)
    p_ol.set_defaults(fn=cmd_otp_ledger)

    # -- disguise --
    p_dh = sub.add_parser("disguise-hide", help="hide positions as an everyday document")
    p_dh.add_argument("--positions", default=None)
    p_dh.add_argument("--input", default=None)
    p_dh.add_argument("--scheme", required=True, choices=sorted(obfuscate.SCHEMES))
    p_dh.add_argument("--seed", type=int, default=0)
    p_dh.add_argument("--out", default=None)
    p_dh.set_defaults(fn=cmd_disguise_hide)

    p_dr = sub.add_parser("disguise-reveal", help="recover positions from a disguised document")
    p_dr.add_argument("--input", required=True)
    p_dr.add_argument("--scheme", required=True, choices=sorted(obfuscate.SCHEMES))
    p_dr.add_argument("--book", default=None, help="also decode against this book")
    p_dr.set_defaults(fn=cmd_disguise_reveal)

    # -- secret sharing --
    p_ss = sub.add_parser("share-split", help="split a secret into k-of-n shares")
    p_ss.add_argument("--secret", default=None, help="secret text (omit to prompt)")
    p_ss.add_argument("--secret-file", default=None, help="read secret bytes from a file")
    p_ss.add_argument("--k", type=int, required=True, help="reconstruction threshold")
    p_ss.add_argument("--n", type=int, required=True, help="total shares")
    p_ss.add_argument("--seed", type=int, default=None, help="seed for deterministic tests")
    p_ss.add_argument("--out-dir", required=True, help="directory for share files")
    p_ss.set_defaults(fn=cmd_share_split)

    p_sc = sub.add_parser("share-combine", help="recover a secret from share files")
    p_sc.add_argument("--share", action="append", required=True,
                      help="share file (repeatable)")
    p_sc.add_argument("--out", default=None, help="write recovered bytes here")
    p_sc.set_defaults(fn=cmd_share_combine)

    # -- voice --
    p_vh = sub.add_parser("voice-hide", help="render positions as a spoken word string")
    p_vh.add_argument("--positions", default=None)
    p_vh.add_argument("--input", default=None)
    p_vh.add_argument("--group", type=int, default=4, help="words per spoken group")
    p_vh.add_argument("--out", default=None)
    p_vh.set_defaults(fn=cmd_voice_hide)

    p_vr = sub.add_parser("voice-reveal", help="parse a spoken word string to positions")
    p_vr.add_argument("--text", default=None, help="inline voice string")
    p_vr.add_argument("--input", default=None, help="file with the voice string")
    p_vr.add_argument("--book", default=None, help="also decode against this book")
    p_vr.set_defaults(fn=cmd_voice_reveal)

    # -- audit --
    p_al = sub.add_parser("audit-log", help="append an operation to the audit trail")
    p_al.add_argument("--log", required=True, help="audit log file (created if absent)")
    p_al.add_argument("--op", required=True, help="operation name, e.g. encode")
    p_al.add_argument("--detail", default=None)
    p_al.add_argument("--book", default=None, help="book to fingerprint into a new log")
    p_al.set_defaults(fn=cmd_audit_log)

    p_av = sub.add_parser("audit-verify", help="verify an audit log's hash chain")
    p_av.add_argument("--log", required=True)
    p_av.set_defaults(fn=cmd_audit_verify)

    # -- checkerboard --
    p_gs = sub.add_parser("grid-show", help="show the book-derived checkerboard")
    p_gs.add_argument("--book", required=True)
    p_gs.set_defaults(fn=cmd_grid_show)

    p_ge = sub.add_parser("grid-encode", help="encode a message to a digit stream")
    p_ge.add_argument("--book", required=True)
    p_ge.add_argument("--message", required=True)
    p_ge.add_argument("--out", default=None)
    p_ge.set_defaults(fn=cmd_grid_encode)

    p_gd = sub.add_parser("grid-decode", help="decode a digit stream to a message")
    p_gd.add_argument("--book", required=True)
    p_gd.add_argument("--digits", required=True)
    p_gd.set_defaults(fn=cmd_grid_decode)

    # -- edition verification --
    p_vc = sub.add_parser("verify-challenge", help="issue edition-verification probes")
    p_vc.add_argument("--book", required=True)
    p_vc.add_argument("--count", type=int, default=8)
    p_vc.add_argument("--salt", required=True)
    p_vc.add_argument("--seed", type=int, default=None)
    p_vc.add_argument("--out", default=None)
    p_vc.set_defaults(fn=cmd_verify_challenge)

    p_va = sub.add_parser("verify-answer", help="answer edition-verification probes")
    p_va.add_argument("--book", required=True)
    p_va.add_argument("--probes", required=True, help="file of line.word probes")
    p_va.add_argument("--salt", required=True)
    p_va.add_argument("--out", default=None)
    p_va.set_defaults(fn=cmd_verify_answer)

    p_vk = sub.add_parser("verify-check", help="check ceremony answers against your book")
    p_vk.add_argument("--book", required=True)
    p_vk.add_argument("--probes", required=True)
    p_vk.add_argument("--answers", required=True)
    p_vk.add_argument("--salt", required=True)
    p_vk.set_defaults(fn=cmd_verify_check)

    # -- protocol --
    p_ps = sub.add_parser("send", help="run the full send pipeline (encode+encrypt/disguise)")
    p_ps.add_argument("--book", required=True)
    p_ps.add_argument("--message", required=True)
    p_ps.add_argument("--passphrase", default=None, help="encrypt the payload")
    p_ps.add_argument("--scheme", default=None, choices=sorted(obfuscate.SCHEMES),
                      help="disguise the payload (exclusive with --passphrase)")
    p_ps.add_argument("--seed", type=int, default=0)
    p_ps.add_argument("--kdf-iterations", type=int, default=crypto.KDF_ITERATIONS)
    p_ps.add_argument("--audit", default=None, help="audit log file to append to")
    p_ps.add_argument("--out", default=None)
    p_ps.set_defaults(fn=cmd_protocol_send)

    p_pr = sub.add_parser("receive", help="run the full receive pipeline")
    p_pr.add_argument("--book", required=True)
    p_pr.add_argument("--input", required=True, help="envelope file")
    p_pr.add_argument("--passphrase", default=None)
    p_pr.add_argument("--audit", default=None)
    p_pr.set_defaults(fn=cmd_protocol_receive)

    p_pd = sub.add_parser("describe", help="summarize an envelope without decrypting")
    p_pd.add_argument("--input", required=True)
    p_pd.set_defaults(fn=cmd_protocol_describe)

    p_mn = sub.add_parser("mnemonic", help="render a book fingerprint as words")
    p_mn.add_argument("--book", required=True)
    p_mn.add_argument("--words", type=int, default=6)
    p_mn.set_defaults(fn=cmd_mnemonic)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        rc = args.fn(args)
    except BookCipherError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return rc if isinstance(rc, int) else 0


if __name__ == "__main__":
    sys.exit(main())
