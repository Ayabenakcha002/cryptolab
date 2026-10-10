"""RSA key generation, OAEP encryption and PKCS#1 v1.5 signatures.

Educational code (see the README security notice). Highlights:

* keys are generated with a CSPRNG and Miller-Rabin;
* private-key operations use the Chinese Remainder Theorem (about 4x faster),
  RSA blinding (against timing attacks) and a fault check on the result;
* encryption uses **RSAES-OAEP** (RFC 8017) with SHA-256, never "textbook" RSA;
* signature verification re-encodes the expected message and compares it,
  instead of parsing the padding (parsing is what enabled the Bleichenbacher
  signature forgeries).
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass
from typing import Dict, Tuple

from .numtheory import generate_prime, modinv
from .sha256 import sha256
from .utils import constant_time_equal, xor_bytes

_HASH_LEN = 32
MIN_KEY_BITS = 1024
_DECRYPT_ERROR = "decryption error"

# DER prefix of DigestInfo for SHA-256 (RFC 8017, section 9.2, note 1).
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def to_dict(self) -> Dict[str, str]:
        return {"type": "rsa-public", "n": hex(self.n), "e": hex(self.e)}

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "PublicKey":
        if data.get("type") != "rsa-public":
            raise ValueError("not an RSA public key")
        return cls(n=int(data["n"], 16), e=int(data["e"], 16))


@dataclass(frozen=True)
class PrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    @property
    def public(self) -> PublicKey:
        return PublicKey(self.n, self.e)

    def to_dict(self) -> Dict[str, str]:
        return {
            "type": "rsa-private",
            "n": hex(self.n),
            "e": hex(self.e),
            "d": hex(self.d),
            "p": hex(self.p),
            "q": hex(self.q),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "PrivateKey":
        if data.get("type") != "rsa-private":
            raise ValueError("not an RSA private key")
        key = cls(*(int(data[name], 16) for name in ("n", "e", "d", "p", "q")))
        if key.p * key.q != key.n:
            raise ValueError("inconsistent private key (p * q != n)")
        return key


def generate_keypair(bits: int = 2048, e: int = 65537) -> PrivateKey:
    """Generate an RSA key. Use 2048 bits or more for anything real.

    n = p*q, and the private exponent d is the inverse of e modulo
    lambda(n) = lcm(p-1, q-1). Then (m^e)^d = m (mod n).
    """
    if bits < MIN_KEY_BITS or bits % 2:
        raise ValueError(f"key size must be an even number >= {MIN_KEY_BITS} bits")
    half = bits // 2
    while True:
        p, q = generate_prime(half), generate_prime(half)
        if p == q or abs(p - q) < (1 << (half - 100)):
            continue  # p and q too close: n could be factored by Fermat's method
        lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        if math.gcd(e, lam) != 1:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        if p < q:
            p, q = q, p
        return PrivateKey(n=n, e=e, d=modinv(e, lam), p=p, q=q)


# ----------------------------------------------------------- raw operations --

def _public_op(key: PublicKey, m: int) -> int:
    if not 0 <= m < key.n:
        raise ValueError("message representative out of range")
    return pow(m, key.e, key.n)


def _crt_private(key: PrivateKey, c: int) -> int:
    """c^d mod n through the Chinese Remainder Theorem."""
    dp, dq = key.d % (key.p - 1), key.d % (key.q - 1)
    m1, m2 = pow(c, dp, key.p), pow(c, dq, key.q)
    h = (modinv(key.q, key.p) * (m1 - m2)) % key.p
    return m2 + h * key.q


def _private_op(key: PrivateKey, c: int) -> int:
    if not 0 <= c < key.n:
        raise ValueError("ciphertext representative out of range")
    # Blinding: decrypt c * r^e instead of c, then divide by r. The attacker
    # no longer controls the number being exponentiated, which defeats timing
    # attacks that rely on chosen inputs.
    while True:
        r = 2 + secrets.randbelow(key.n - 3)
        if math.gcd(r, key.n) == 1:
            break
    blinded = (c * pow(r, key.e, key.n)) % key.n
    m = (_crt_private(key, blinded) * modinv(r, key.n)) % key.n
    # A single fault during CRT computation lets an attacker factor n, so
    # never release a result that does not re-encrypt to the input.
    if pow(m, key.e, key.n) != c:
        raise RuntimeError("fault detected in RSA private operation")
    return m


# -------------------------------------------------------------------- OAEP --

def _mgf1(seed: bytes, length: int) -> bytes:
    """Mask generation function MGF1 with SHA-256 (RFC 8017, appendix B.2.1)."""
    out = b""
    counter = 0
    while len(out) < length:
        out += sha256(seed + counter.to_bytes(4, "big"))
        counter += 1
    return out[:length]


def max_oaep_message_length(key: PublicKey) -> int:
    return key.size_bytes - 2 * _HASH_LEN - 2


def oaep_encrypt(key: PublicKey, message: bytes, label: bytes = b"") -> bytes:
    """RSAES-OAEP encryption (SHA-256, MGF1-SHA-256)."""
    k = key.size_bytes
    if len(message) > max_oaep_message_length(key):
        raise ValueError(
            f"message too long for this key (max {max_oaep_message_length(key)} bytes)"
        )
    padding_string = b"\x00" * (k - len(message) - 2 * _HASH_LEN - 2)
    data_block = sha256(label) + padding_string + b"\x01" + message
    seed = secrets.token_bytes(_HASH_LEN)
    masked_db = xor_bytes(data_block, _mgf1(seed, k - _HASH_LEN - 1))
    masked_seed = xor_bytes(seed, _mgf1(masked_db, _HASH_LEN))
    encoded = b"\x00" + masked_seed + masked_db
    return _public_op(key, int.from_bytes(encoded, "big")).to_bytes(k, "big")


def oaep_decrypt(key: PrivateKey, ciphertext: bytes, label: bytes = b"") -> bytes:
    """RSAES-OAEP decryption.

    Every kind of failure raises the *same* error, and all checks are
    evaluated before deciding: telling an attacker which check failed enables
    Manger's chosen-ciphertext attack.
    """
    k = key.size_bytes
    if len(ciphertext) != k or k < 2 * _HASH_LEN + 2:
        raise ValueError(_DECRYPT_ERROR)
    try:
        encoded = _private_op(key, int.from_bytes(ciphertext, "big")).to_bytes(k, "big")
    except ValueError:
        raise ValueError(_DECRYPT_ERROR) from None
    first, masked_seed, masked_db = encoded[0], encoded[1:1 + _HASH_LEN], encoded[1 + _HASH_LEN:]
    seed = xor_bytes(masked_seed, _mgf1(masked_db, _HASH_LEN))
    data_block = xor_bytes(masked_db, _mgf1(seed, k - _HASH_LEN - 1))
    label_ok = constant_time_equal(data_block[:_HASH_LEN], sha256(label))
    rest = data_block[_HASH_LEN:]
    separator = -1
    for index, byte in enumerate(rest):  # scan everything, no early exit
        if separator < 0 and byte != 0:
            separator = index
    separator_ok = separator >= 0 and rest[separator] == 1
    # Bitwise & (not "and") so that no check is skipped once one has failed.
    if not ((first == 0) & label_ok & separator_ok):
        raise ValueError(_DECRYPT_ERROR)
    return rest[separator + 1:]


# ------------------------------------------------------ PKCS#1 v1.5 signing --

def _emsa_pkcs1_v15(message: bytes, em_len: int) -> bytes:
    digest_info = _SHA256_DIGEST_INFO + sha256(message)
    if em_len < len(digest_info) + 11:
        raise ValueError("key too small for SHA-256 signatures")
    return b"\x00\x01" + b"\xff" * (em_len - len(digest_info) - 3) + b"\x00" + digest_info


def sign(key: PrivateKey, message: bytes) -> bytes:
    """RSASSA-PKCS1-v1_5 signature with SHA-256 (deterministic)."""
    k = key.size_bytes
    encoded = _emsa_pkcs1_v15(message, k)
    return _private_op(key, int.from_bytes(encoded, "big")).to_bytes(k, "big")


def verify(key: PublicKey, message: bytes, signature: bytes) -> bool:
    """Return True iff ``signature`` is a valid signature of ``message``."""
    k = key.size_bytes
    if len(signature) != k:
        return False
    try:
        recovered = _public_op(key, int.from_bytes(signature, "big")).to_bytes(k, "big")
        expected = _emsa_pkcs1_v15(message, k)
    except ValueError:
        return False
    return constant_time_equal(recovered, expected)
