"""HMAC-SHA256 (RFC 2104 / FIPS 198-1) built on our own SHA-256."""

from __future__ import annotations

from .sha256 import sha256

_BLOCK_SIZE = 64


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256(key, message).

    HMAC(K, m) = H((K' xor opad) || H((K' xor ipad) || m)) where K' is the key
    padded with zeros to the hash block size (or hashed first if it is longer).
    The nested construction is what protects against length-extension attacks
    that break the naive ``H(key || message)``.
    """
    key = bytes(key)
    if len(key) > _BLOCK_SIZE:
        key = sha256(key)
    key = key.ljust(_BLOCK_SIZE, b"\x00")
    inner_pad = bytes(b ^ 0x36 for b in key)
    outer_pad = bytes(b ^ 0x5C for b in key)
    return sha256(outer_pad + sha256(inner_pad + bytes(message)))
