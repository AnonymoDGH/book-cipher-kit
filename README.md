<div align="center">

# 📖 Book Cipher Kit

<img src="https://raw.githubusercontent.com/AnonymoDGH/book-cipher-kit/main/logo.svg" alt="Book Cipher Kit" width="180"/>

**The cipher that needs no key — only a shared book.**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-book--cipher--kit-orange.svg)](https://pypi.org/project/book-cipher-kit/)
[![Platform](https://img.shields.io/badge/platform-osx%20%7C%20linux%20%7C%20windows-lightgrey.svg)]()

> *"Anyone who has the book can read it. Anyone who doesn't, never will."*

</div>

---

## What is it?

A **book cipher** encodes each character of a message as a position inside the
words of a book: *(line, word, character)*. Without the same edition of the
same book, the positions are meaningless — and there is no key to steal, no
algorithm to break, no trace to find. It is the cipher of lovers, prisoners,
and people who trust each other with a bookstore.

## Features

**Core**
- 🔡 Encode messages into `line.word.char` position triples
- 📚 Decode them back with the same book
- 🎲 Optional seed for reproducible (or plausibly deniable) output
- 📊 `stats` — tells you what your book can and cannot encode
- 🧾 Positions live in a plain text file — one triple per line, easy to hide

**Formats & protection**
- 📦 Convert positions between text / JSON / CSV / hex / base64 (`convert`)
- 🔒 Passphrase encryption of positions (PBKDF2 + counter-mode SHA-256 + HMAC)
- 🗝️ Book-derived one-time pad with a burn-after-use ledger (`otp-*`)
- 🧩 Shamir secret sharing of passphrases — k-of-n recovery (`share-*`)

**Steganography & disguise**
- 📝 Hide positions inside generated prose (sentence-length codec, `stego-*`)
- 🛒 Disguise positions as a shopping list, server log, invoice, or schedule (`disguise-*`)
- 🔤 Acrostic and null-cipher message hiding

**Analysis & operations**
- 🩺 `doctor` — diagnoses a book, a position file, or a pair
- 🕵️ `attack` — cryptanalysis yardsticks (chi-squared, IoC, entropy, leakage)
- 🧮 `grid-*` — book-derived straddling checkerboard for compact digit streams
- 🗣️ `voice-*` — render positions as phonetically distinct words to read aloud
- 🧠 `mnemonic` — render a book fingerprint as a memorable word phrase
- 🤝 `verify-*` — challenge/response ceremony proving you share the same edition
- 📜 `audit-*` — hash-chained, tamper-evident operations log
- 📬 `send` / `receive` — the whole pipeline (encode → encrypt/disguise → audit) in one envelope
- 📦 Zero dependencies

## Install

```bash
pip install book-cipher-kit
```

From source:

```bash
git clone https://github.com/AnonymoDGH/book-cipher-kit
cd book-cipher-kit
pip install -e .
```

## Quickstart

```bash
# What can your book encode?
bookcipher stats --book novel.txt
# [*] Alphabet coverage: 98%
# [+] Found:   abcdefghijklmnopqrstuvwxyz
# [-] Missing: q

# Encode
bookcipher encode --book novel.txt --message "meet at dawn" --out coords.txt

# The courier carries only this:
cat coords.txt
# 12.4.2
# 3.1.0
# 87.12.5
# ...

# Decode on the other side
bookcipher decode --book novel.txt --input coords.txt
# meet at dawn
```

## CLI reference

| Command | What it does |
|---|---|
| `bookcipher encode --book <f> --message <m> [--out <f>] [--seed <n>]` | Message → positions |
| `bookcipher decode --book <f> --input <f>` | Positions → message |
| `bookcipher decode --book <f> --positions "1.0.2 2.3.0"` | Inline positions |
| `bookcipher stats --book <f>` | Alphabet coverage report |
| `bookcipher convert --input <f> --to hex` | Convert between formats |
| `bookcipher encrypt --input <f> --passphrase <p>` | Encrypt positions |
| `bookcipher decrypt --input <f> --passphrase <p>` | Decrypt positions |
| `bookcipher otp-encrypt --book <f> --message <m> --page-start N --page-end M` | Book one-time pad |
| `bookcipher share-split --secret <s> --k 2 --n 3 --out-dir <d>` | Shamir split |
| `bookcipher share-combine --share <f> --share <f>` | Shamir recover |
| `bookcipher stego-hide --input <f>` | Hide positions in prose |
| `bookcipher disguise-hide --input <f> --scheme invoice` | Disguise as a document |
| `bookcipher doctor --book <f>` | Diagnose a book |
| `bookcipher attack --input <f> --book <f>` | Cryptanalysis yardsticks |
| `bookcipher grid-encode --book <f> --message <m>` | Compact digit stream |
| `bookcipher voice-hide --input <f>` | Positions → spoken words |
| `bookcipher mnemonic --book <f>` | Fingerprint → word phrase |
| `bookcipher verify-challenge --book <f> --salt <s>` | Edition-verification probes |
| `bookcipher audit-log --log <f> --op encode` | Append to audit trail |
| `bookcipher audit-verify --log <f>` | Verify audit chain |
| `bookcipher send --book <f> --message <m> [--passphrase <p> \| --scheme <s>]` | Full send pipeline |
| `bookcipher receive --book <f> --input <env>` | Full receive pipeline |

## How it works

<img src="https://raw.githubusercontent.com/AnonymoDGH/book-cipher-kit/main/assets/architecture.svg" alt="Architecture" width="820"/>

## Tests

```bash
pip install pytest
pytest
```

The suite covers every module — core encode/decode, formats, crypto, the
one-time pad, Shamir sharing, steganography, disguise schemes, the
checkerboard, voice/word maps, the edition-verification ceremony, the audit
chain, and the end-to-end protocol — with deterministic seeds throughout.

## License

[MIT](LICENSE) — a fiction research prop. Share the book, keep the story.
