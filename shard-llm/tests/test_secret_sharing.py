import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secret_sharing import split_secret, reconstruct_secret, _PRIME


def test_reconstruct_with_exact_threshold():
    secret = 123456789
    shares = split_secret(secret, num_shares=5, threshold=3)
    recovered = reconstruct_secret(shares[:3])
    assert recovered == secret


def test_reconstruct_with_more_than_threshold():
    secret = 987654321
    shares = split_secret(secret, num_shares=6, threshold=3)
    recovered = reconstruct_secret(shares[1:5])  # 4 shares, threshold is 3
    assert recovered == secret


def test_different_share_subsets_agree():
    secret = 42
    shares = split_secret(secret, num_shares=5, threshold=3)
    r1 = reconstruct_secret([shares[0], shares[1], shares[2]])
    r2 = reconstruct_secret([shares[2], shares[3], shares[4]])
    assert r1 == secret
    assert r2 == secret


def test_insufficient_shares_do_not_trivially_reveal_secret():
    # With fewer than `threshold` shares, reconstruction mathematically
    # returns *some* value but it will not equal the true secret
    # (info-theoretic security property of Shamir's scheme).
    secret = 555555
    shares = split_secret(secret, num_shares=5, threshold=4)
    wrong_guess = reconstruct_secret(shares[:2])  # only 2 of 4 needed
    assert wrong_guess != secret


def test_secret_within_prime_bounds():
    secret = _PRIME - 1
    shares = split_secret(secret, num_shares=3, threshold=2)
    assert reconstruct_secret(shares) == secret
