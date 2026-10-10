"""Small helpers shared by the other modules."""

from __future__ import annotations

import hmac as _stdlib_hmac


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of identical length."""
    if len(a) != len(b):
        raise ValueError("xor_bytes: inputs must have the same length")
    return bytes(x ^ y for x, y in zip(a, b))


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """Compare two byte strings without leaking where they first differ.

    Delegates to the standard library: comparing secrets (MACs, tags) with
    ``==`` stops at the first mismatch and so leaks timing information.
    """
    return _stdlib_hmac.compare_digest(a, b)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Append PKCS#7 padding (always at least one byte)."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Remove PKCS#7 padding, raising ``ValueError`` if it is malformed.

    Reporting *why* padding is wrong to an attacker is what makes padding-oracle
    attacks possible, so every failure raises the same error.
    """
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid padding")
    pad_len = data[-1]
    if not 1 <= pad_len <= block_size:
        raise ValueError("invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding")
    return data[:-pad_len]
