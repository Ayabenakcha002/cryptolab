"""Number theory needed by RSA: gcd, modular inverse, primality, prime generation."""

from __future__ import annotations

import secrets
from typing import Tuple


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclid: return ``(g, x, y)`` with ``a*x + b*y == g == gcd(a, b)``."""
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_r, old_x, old_y


def modinv(a: int, m: int) -> int:
    """Inverse of ``a`` modulo ``m``; raises ``ValueError`` if it does not exist."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def _small_primes(limit: int):
    sieve = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return [i for i, flag in enumerate(sieve) if flag]


_SMALL_PRIMES = _small_primes(1000)


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin primality test.

    Write n - 1 = 2^s * d with d odd. For a random base a, n is "probably
    prime" if a^d = 1 or a^(d*2^r) = -1 (mod n) for some r < s. A composite
    number survives a random base with probability at most 1/4, so 40 rounds
    leave an error probability below 4^-40 (about 10^-24).
    """
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Random prime of exactly ``bits`` bits.

    The two top bits are forced to 1 so that the product of two such primes
    has exactly ``2 * bits`` bits; the low bit is forced to 1 (odd).
    """
    if bits < 16:
        raise ValueError("prime size must be at least 16 bits")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_probable_prime(candidate):
            return candidate
