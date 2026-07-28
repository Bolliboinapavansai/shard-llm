"""
secret_sharing.py

Implements Shamir's Secret Sharing (SSS) over a prime field GF(p).

Purpose in this project:
    The symmetric key used to encrypt the PII vault (see pii_redactor.py) is
    never stored as a single value. Instead it is split into N shares using
    Shamir's scheme, such that any K of the N shares can reconstruct the key,
    but K-1 shares reveal nothing about it (information-theoretic security).

    This models a realistic secure-cloud-deployment pattern: instead of one
    admin/service holding a master decryption key, the key is distributed
    across K-of-N custodians (e.g., separate services, HSMs, or team members),
    so no single compromised party can decrypt the PII vault alone.

Reference:
    Shamir, A. (1979). "How to Share a Secret". Communications of the ACM.
"""

import random
from typing import List, Tuple

# A large prime > any 256-bit key represented as an integer.
# (2^521 - 1 is a Mersenne prime, comfortably larger than a 256-bit secret.)
_PRIME = (1 << 521) - 1


def _eval_polynomial(coeffs: List[int], x: int, prime: int) -> int:
    """Evaluate a polynomial (given by its coefficients, constant term first) at x, mod prime."""
    result = 0
    for coeff in reversed(coeffs):
        result = (result * x + coeff) % prime
    return result


def split_secret(secret_int: int, num_shares: int, threshold: int,
                  prime: int = _PRIME) -> List[Tuple[int, int]]:
    """
    Split `secret_int` into `num_shares` shares such that any `threshold`
    of them can reconstruct the secret.

    Returns a list of (x, y) points. Each participant gets one point.
    """
    if threshold > num_shares:
        raise ValueError("threshold cannot exceed num_shares")
    if secret_int >= prime:
        raise ValueError("secret is too large for the chosen prime field")

    # Random polynomial of degree (threshold - 1) with the secret as constant term.
    coeffs = [secret_int] + [random.SystemRandom().randrange(1, prime) for _ in range(threshold - 1)]

    shares = []
    for i in range(1, num_shares + 1):
        y = _eval_polynomial(coeffs, i, prime)
        shares.append((i, y))
    return shares


def _lagrange_interpolate(x: int, points: List[Tuple[int, int]], prime: int) -> int:
    """Reconstruct f(x) via Lagrange interpolation from a list of (x_i, y_i) points, mod prime."""
    total = 0
    n = len(points)
    for i in range(n):
        xi, yi = points[i]
        num, den = 1, 1
        for j in range(n):
            if i == j:
                continue
            xj, _ = points[j]
            num = (num * (x - xj)) % prime
            den = (den * (xi - xj)) % prime
        # Modular inverse of den (prime is prime, so Fermat's little theorem applies)
        inv_den = pow(den, prime - 2, prime)
        term = (yi * num * inv_den) % prime
        total = (total + term) % prime
    return total


def reconstruct_secret(shares: List[Tuple[int, int]], prime: int = _PRIME) -> int:
    """Reconstruct the original secret from a list of >= threshold shares."""
    return _lagrange_interpolate(0, shares, prime)


if __name__ == "__main__":
    # Self-test / demo when run directly.
    secret = int.from_bytes(b"a-256-bit-symmetric-key-example!", byteorder="big") % _PRIME
    shares = split_secret(secret, num_shares=5, threshold=3)
    print("Generated shares:", shares)

    # Reconstruct using any 3 of the 5 shares.
    subset = shares[1:4]
    recovered = reconstruct_secret(subset)
    print("Secret recovered correctly:", recovered == secret)
