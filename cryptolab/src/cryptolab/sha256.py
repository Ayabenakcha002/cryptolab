"""SHA-256 (FIPS 180-4) implemented from scratch.

Educational code: do not use it in production, use ``hashlib``.

Instead of pasting 72 magic constants from the standard, they are *derived*
the same way the standard defines them:

* the 64 round constants K are the first 32 bits of the fractional parts of
  the cube roots of the first 64 primes;
* the 8 initial hash values H0 are the first 32 bits of the fractional parts
  of the square roots of the first 8 primes.

Integer arithmetic is used, so there is no floating-point rounding involved.
"""

from __future__ import annotations

import math
import struct
from typing import List, Sequence, Tuple

_MASK = 0xFFFFFFFF


def _first_primes(count: int) -> List[int]:
    primes: List[int] = []
    candidate = 2
    while len(primes) < count:
        if all(candidate % p for p in primes if p * p <= candidate):
            primes.append(candidate)
        candidate += 1
    return primes


def _icbrt(n: int) -> int:
    """Exact integer cube root: the largest x with x**3 <= n."""
    if n < 2:
        return n
    x = 1 << ((n.bit_length() + 2) // 3)  # always >= the real cube root
    while True:  # Newton iteration, decreasing monotonically
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            break
        x = y
    while x ** 3 > n:
        x -= 1
    while (x + 1) ** 3 <= n:
        x += 1
    return x


_PRIMES = _first_primes(64)
# floor(cbrt(p) * 2**32) mod 2**32  ==  floor(cbrt(p * 2**96)) mod 2**32
_K: Tuple[int, ...] = tuple(_icbrt(p << 96) & _MASK for p in _PRIMES)
# floor(sqrt(p) * 2**32) mod 2**32  ==  floor(sqrt(p * 2**64)) mod 2**32
_H0: Tuple[int, ...] = tuple(math.isqrt(p << 64) & _MASK for p in _PRIMES[:8])


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK


def _compress(state: Sequence[int], block: bytes) -> List[int]:
    """Process one 64-byte block and return the new chaining value."""
    w = list(struct.unpack(">16I", block)) + [0] * 48
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _MASK

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        big_s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        choose = (e & f) ^ ((~e & _MASK) & g)
        t1 = (h + big_s1 + choose + _K[i] + w[i]) & _MASK
        big_s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        majority = (a & b) ^ (a & c) ^ (b & c)
        t2 = (big_s0 + majority) & _MASK
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK, c, b, a, (t1 + t2) & _MASK

    return [(s + v) & _MASK for s, v in zip(state, (a, b, c, d, e, f, g, h))]


class SHA256:
    """Incremental SHA-256, with the same interface as ``hashlib.sha256``."""

    name = "sha256"
    digest_size = 32
    block_size = 64

    def __init__(self, data: bytes = b"") -> None:
        self._state: List[int] = list(_H0)
        self._buffer = b""
        self._length = 0  # total message length in bytes
        if data:
            self.update(data)

    def update(self, data: bytes) -> None:
        data = bytes(data)
        self._length += len(data)
        buf = self._buffer + data
        end = len(buf) - (len(buf) % 64)
        for offset in range(0, end, 64):
            self._state = _compress(self._state, buf[offset:offset + 64])
        self._buffer = buf[end:]

    def digest(self) -> bytes:
        """Return the digest without disturbing the running state."""
        state = list(self._state)
        tail = self._buffer + b"\x80"
        tail += b"\x00" * ((56 - len(tail)) % 64)
        tail += struct.pack(">Q", (self._length * 8) & 0xFFFFFFFFFFFFFFFF)
        for offset in range(0, len(tail), 64):
            state = _compress(state, tail[offset:offset + 64])
        return struct.pack(">8I", *state)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "SHA256":
        clone = SHA256()
        clone._state = list(self._state)
        clone._buffer = self._buffer
        clone._length = self._length
        return clone


def sha256(data: bytes) -> bytes:
    """One-shot SHA-256 of ``data``."""
    return SHA256(data).digest()
