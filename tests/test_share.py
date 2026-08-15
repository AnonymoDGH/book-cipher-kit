"""Tests for book_cipher_kit.share -- Shamir secret sharing over GF(257)."""

from __future__ import annotations

import random

import pytest

from book_cipher_kit.share import (
    PRIME,
    Share,
    ShareError,
    combine_shares,
    parse_shares,
    secret_fingerprint,
    serialize_shares,
    share_fingerprint,
    split_secret,
    verify_share_set,
)

SECRET = b"the map is buried under the third stone"


@pytest.fixture
def rng():
    return random.Random(42)


class TestSplitCombine:
    def test_roundtrip_all_shares(self, rng):
        shares = split_secret(SECRET, k=3, n=5, rng=rng)
        assert len(shares) == 5
        assert combine_shares(shares) == SECRET

    def test_roundtrip_threshold_subset(self, rng):
        shares = split_secret(SECRET, k=3, n=5, rng=rng)
        # Any 3 shares reconstruct.
        assert combine_shares(shares[:3]) == SECRET
        assert combine_shares(shares[2:]) == SECRET
        assert combine_shares([shares[0], shares[2], shares[4]]) == SECRET

    def test_fewer_than_threshold_differs(self, rng):
        shares = split_secret(SECRET, k=3, n=5, rng=rng)
        # 2 shares interpolate a different polynomial -> wrong secret.
        wrong = combine_shares(shares[:2])
        assert wrong != SECRET

    def test_k_equals_one(self, rng):
        shares = split_secret(SECRET, k=1, n=3, rng=rng)
        for s in shares:
            assert combine_shares([s]) == SECRET

    def test_k_equals_n(self, rng):
        shares = split_secret(SECRET, k=4, n=4, rng=rng)
        assert combine_shares(shares) == SECRET

    def test_empty_secret(self, rng):
        shares = split_secret(b"", k=2, n=3, rng=rng)
        assert all(s.values == () for s in shares)
        assert combine_shares(shares) == b""

    def test_all_byte_values(self, rng):
        data = bytes(range(256))
        shares = split_secret(data, k=2, n=3, rng=rng)
        assert combine_shares(shares[:2]) == data

    def test_deterministic_with_seed(self):
        a = split_secret(SECRET, k=2, n=3, rng=random.Random(7))
        b = split_secret(SECRET, k=2, n=3, rng=random.Random(7))
        assert a == b

    def test_different_seeds_differ(self):
        a = split_secret(SECRET, k=2, n=3, rng=random.Random(7))
        b = split_secret(SECRET, k=2, n=3, rng=random.Random(8))
        assert a != b

    def test_invalid_kn(self, rng):
        with pytest.raises(ShareError):
            split_secret(SECRET, k=0, n=3, rng=rng)
        with pytest.raises(ShareError):
            split_secret(SECRET, k=4, n=3, rng=rng)
        with pytest.raises(ShareError):
            split_secret(SECRET, k=2, n=PRIME, rng=rng)


class TestShareValidation:
    def test_bad_x(self):
        with pytest.raises(ShareError):
            Share(x=0, values=(1, 2))
        with pytest.raises(ShareError):
            Share(x=PRIME, values=(1, 2))

    def test_bad_value(self):
        with pytest.raises(ShareError):
            Share(x=1, values=(PRIME,))

    def test_combine_empty(self):
        with pytest.raises(ShareError):
            combine_shares([])

    def test_combine_length_mismatch(self, rng):
        shares = split_secret(SECRET, k=2, n=3, rng=rng)
        bad = Share(x=9, values=(1,))
        with pytest.raises(ShareError):
            combine_shares([shares[0], bad])

    def test_combine_duplicate_x(self, rng):
        shares = split_secret(SECRET, k=2, n=3, rng=rng)
        with pytest.raises(ShareError):
            combine_shares([shares[0], shares[0]])


class TestSerialization:
    def test_roundtrip(self, rng):
        shares = split_secret(SECRET, k=2, n=3, rng=rng)
        fp = secret_fingerprint(SECRET)
        text = serialize_shares(shares, k=2, n=3, fingerprint=fp)
        parsed, k, n, fp2 = parse_shares(text)
        assert (k, n, fp2) == (2, 3, fp)
        assert parsed == shares
        assert combine_shares(parsed) == SECRET

    def test_bad_magic(self):
        with pytest.raises(ShareError):
            parse_shares("wrong-header\nk=1 n=1 fp=x\nx=1 v=1")

    def test_missing_params(self):
        with pytest.raises(ShareError):
            parse_shares("bookcipher-shares/1\nx=1 v=1")

    def test_count_mismatch(self, rng):
        shares = split_secret(SECRET, k=2, n=3, rng=rng)
        text = serialize_shares(shares, k=2, n=3,
                                fingerprint=secret_fingerprint(SECRET))
        # Drop one share line.
        lines = text.strip().splitlines()
        broken = "\n".join(lines[:-1])
        with pytest.raises(ShareError):
            parse_shares(broken)


class TestFingerprintsAndVerify:
    def test_share_fingerprint_stable(self, rng):
        shares = split_secret(SECRET, k=2, n=3, rng=rng)
        assert share_fingerprint(shares[0]) == share_fingerprint(shares[0])
        assert share_fingerprint(shares[0]) != share_fingerprint(shares[1])

    def test_verify_ok(self, rng):
        shares = split_secret(SECRET, k=2, n=3, rng=rng)
        fp = secret_fingerprint(SECRET)
        assert verify_share_set(shares, k=2, fingerprint=fp)
        assert verify_share_set(shares[:2], k=2, fingerprint=fp)

    def test_verify_too_few(self, rng):
        shares = split_secret(SECRET, k=3, n=5, rng=rng)
        fp = secret_fingerprint(SECRET)
        assert not verify_share_set(shares[:2], k=3, fingerprint=fp)

    def test_verify_wrong_fingerprint(self, rng):
        shares = split_secret(SECRET, k=2, n=3, rng=rng)
        assert not verify_share_set(shares, k=2, fingerprint="0" * 16)
