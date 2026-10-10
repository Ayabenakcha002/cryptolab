"""Modes of operation for AES: CBC, CTR and GCM.

Which one to use? **GCM**. A block cipher only encrypts 16 bytes; a mode
turns it into something usable on real messages. CBC and CTR give
confidentiality *only*: an attacker who flips bits in the ciphertext flips
predictable bits in the plaintext and you will never know. GCM adds an
authentication tag, so any modification is detected.
"""

from __future__ import annotations

import secrets
from typing import Tuple

from .aes import AES
from .utils import constant_time_equal, pkcs7_pad, pkcs7_unpad, xor_bytes


class InvalidTag(Exception):
    """Raised when GCM authentication fails (wrong key, AAD or tampering)."""


# --------------------------------------------------------------------- CBC --

def cbc_encrypt(aes: AES, iv: bytes, plaintext: bytes) -> bytes:
    """CBC encryption with PKCS#7 padding. The IV must be random per message.

    WARNING: unauthenticated. Combine with a MAC (encrypt-then-MAC) or use GCM.
    """
    if len(iv) != 16:
        raise ValueError("CBC IV must be 16 bytes")
    padded = pkcs7_pad(plaintext)
    previous, out = iv, []
    for offset in range(0, len(padded), 16):
        block = xor_bytes(padded[offset:offset + 16], previous)
        previous = aes.encrypt_block(block)
        out.append(previous)
    return b"".join(out)


def cbc_decrypt(aes: AES, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("CBC IV must be 16 bytes")
    if not ciphertext or len(ciphertext) % 16 != 0:
        raise ValueError("CBC ciphertext length must be a positive multiple of 16")
    previous, out = iv, []
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16]
        out.append(xor_bytes(aes.decrypt_block(block), previous))
        previous = block
    return pkcs7_unpad(b"".join(out))


# --------------------------------------------------------------------- CTR --

def ctr_crypt(aes: AES, initial_counter_block: bytes, data: bytes) -> bytes:
    """CTR mode (SP 800-38A): XOR the data with the encrypted counter stream.

    Encryption and decryption are the same operation. Never reuse a
    (key, counter block) pair: two messages encrypted with the same keystream
    leak the XOR of their plaintexts.
    """
    if len(initial_counter_block) != 16:
        raise ValueError("CTR counter block must be 16 bytes")
    counter = int.from_bytes(initial_counter_block, "big")
    out = bytearray()
    for offset in range(0, len(data), 16):
        keystream = aes.encrypt_block(counter.to_bytes(16, "big"))
        chunk = data[offset:offset + 16]
        out.extend(a ^ b for a, b in zip(chunk, keystream))
        counter = (counter + 1) % (1 << 128)
    return bytes(out)


# --------------------------------------------------------------------- GCM --

_R = 0xE1 << 120  # the GCM reduction constant, in the spec's reflected bit order


def _gf128_mul(x: int, y: int) -> int:
    """Multiply in GF(2^128) as defined by SP 800-38D (bit 0 = most significant)."""
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ _R if v & 1 else v >> 1
    return z


def _ghash(h: int, aad: bytes, ciphertext: bytes) -> int:
    """Polynomial hash over AAD and ciphertext, keyed with H = E_K(0^128)."""

    def blocks(data: bytes):
        for offset in range(0, len(data), 16):
            yield int.from_bytes(data[offset:offset + 16].ljust(16, b"\x00"), "big")

    y = 0
    for block in blocks(aad):
        y = _gf128_mul(y ^ block, h)
    for block in blocks(ciphertext):
        y = _gf128_mul(y ^ block, h)
    lengths = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    return _gf128_mul(y ^ lengths, h)


def _inc32(block: bytes) -> bytes:
    counter = (int.from_bytes(block[12:], "big") + 1) & 0xFFFFFFFF
    return block[:12] + counter.to_bytes(4, "big")


def _gctr(aes: AES, counter_block: bytes, data: bytes) -> bytes:
    out = bytearray()
    for offset in range(0, len(data), 16):
        keystream = aes.encrypt_block(counter_block)
        chunk = data[offset:offset + 16]
        out.extend(a ^ b for a, b in zip(chunk, keystream))
        counter_block = _inc32(counter_block)
    return bytes(out)


def gcm_encrypt(
    aes: AES, iv: bytes, plaintext: bytes, aad: bytes = b""
) -> Tuple[bytes, bytes]:
    """AES-GCM with a 96-bit IV. Returns ``(ciphertext, 16-byte tag)``.

    ``aad`` is authenticated but not encrypted (headers, metadata...). The IV
    must NEVER repeat under the same key: a repeated IV in GCM reveals the
    authentication key and destroys all security.
    """
    if len(iv) != 12:
        raise ValueError("this implementation supports 96-bit (12-byte) GCM IVs only")
    h = int.from_bytes(aes.encrypt_block(bytes(16)), "big")
    j0 = iv + b"\x00\x00\x00\x01"
    ciphertext = _gctr(aes, _inc32(j0), plaintext)
    s = _ghash(h, aad, ciphertext).to_bytes(16, "big")
    tag = xor_bytes(aes.encrypt_block(j0), s)
    return ciphertext, tag


def gcm_decrypt(
    aes: AES, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""
) -> bytes:
    """Verify the tag first, and only then decrypt. Raises :class:`InvalidTag`."""
    if len(iv) != 12:
        raise ValueError("this implementation supports 96-bit (12-byte) GCM IVs only")
    h = int.from_bytes(aes.encrypt_block(bytes(16)), "big")
    j0 = iv + b"\x00\x00\x00\x01"
    s = _ghash(h, aad, ciphertext).to_bytes(16, "big")
    expected = xor_bytes(aes.encrypt_block(j0), s)
    if len(tag) != 16 or not constant_time_equal(expected, tag):
        raise InvalidTag("authentication failed")
    return _gctr(aes, _inc32(j0), ciphertext)


def random_iv(size: int = 12) -> bytes:
    """A fresh random IV from the operating system's CSPRNG."""
    return secrets.token_bytes(size)
