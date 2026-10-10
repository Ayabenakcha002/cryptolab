import math
import os

import pytest

from cryptolab import rsa
from cryptolab.numtheory import egcd, generate_prime, is_probable_prime, modinv


@pytest.fixture(scope="module")
def key():
    return rsa.generate_keypair(1024)


@pytest.fixture(scope="module")
def other_key():
    return rsa.generate_keypair(1024)


# ------------------------------------------------------------ number theory --

def test_egcd_bezout_identity():
    for a, b in [(240, 46), (17, 3120), (0, 5), (5, 0), (2 ** 64, 3 ** 40)]:
        g, x, y = egcd(a, b)
        assert g == math.gcd(a, b) and a * x + b * y == g


def test_modinv():
    assert modinv(17, 3120) == 2753  # classic textbook RSA example
    for m in (97, 1009, 2 ** 61 - 1):
        for a in (1, 2, 3, m - 1):
            assert a * modinv(a, m) % m == 1
    with pytest.raises(ValueError):
        modinv(6, 9)


@pytest.mark.parametrize("n", [2, 3, 5, 97, 1009, 7919, 2 ** 61 - 1, 2 ** 127 - 1])
def test_primes_are_recognised(n):
    assert is_probable_prime(n)


@pytest.mark.parametrize(
    "n",
    [
        -7, 0, 1, 4, 9, 1001, 7917,
        561, 1105, 1729, 2465, 41041, 825265,  # Carmichael numbers fool the Fermat test
        (2 ** 61 - 1) * (2 ** 31 - 1),
    ],
)
def test_composites_are_rejected(n):
    assert not is_probable_prime(n)


def test_generate_prime_has_exact_size_and_is_prime():
    for bits in (16, 64, 256):
        p = generate_prime(bits)
        assert p.bit_length() == bits and is_probable_prime(p)
        assert p >> (bits - 2) == 0b11  # top two bits are set


# ---------------------------------------------------------------- key setup --

def test_keypair_is_mathematically_consistent(key):
    assert key.p * key.q == key.n and key.p != key.q
    assert key.n.bit_length() == 1024
    lam = (key.p - 1) * (key.q - 1) // math.gcd(key.p - 1, key.q - 1)
    assert key.e * key.d % lam == 1
    m = 0xC0FFEE
    assert pow(pow(m, key.e, key.n), key.d, key.n) == m


@pytest.mark.parametrize("bits", [512, 768, 1023, 0, -1])
def test_weak_or_odd_key_sizes_are_refused(bits):
    with pytest.raises(ValueError):
        rsa.generate_keypair(bits)


def test_key_serialisation_round_trip(key):
    assert rsa.PrivateKey.from_dict(key.to_dict()) == key
    assert rsa.PublicKey.from_dict(key.public.to_dict()) == key.public
    with pytest.raises(ValueError):
        rsa.PrivateKey.from_dict(key.public.to_dict())
    with pytest.raises(ValueError):
        rsa.PublicKey.from_dict(key.to_dict())
    broken = dict(key.to_dict(), p=hex(key.p + 2))
    with pytest.raises(ValueError):
        rsa.PrivateKey.from_dict(broken)


# --------------------------------------------------------------------- OAEP --

@pytest.mark.parametrize("length", [0, 1, 20, 62])
def test_oaep_round_trip(key, length):
    message = os.urandom(length)
    assert rsa.oaep_decrypt(key, rsa.oaep_encrypt(key.public, message)) == message


def test_oaep_is_randomised(key):
    a = rsa.oaep_encrypt(key.public, b"same message")
    b = rsa.oaep_encrypt(key.public, b"same message")
    assert a != b  # textbook RSA would give identical ciphertexts


def test_oaep_message_length_limit(key):
    limit = rsa.max_oaep_message_length(key.public)
    assert limit == 128 - 2 * 32 - 2
    rsa.oaep_encrypt(key.public, bytes(limit))
    with pytest.raises(ValueError):
        rsa.oaep_encrypt(key.public, bytes(limit + 1))


def test_oaep_label_must_match(key):
    ct = rsa.oaep_encrypt(key.public, b"secret", label=b"context-A")
    assert rsa.oaep_decrypt(key, ct, label=b"context-A") == b"secret"
    with pytest.raises(ValueError):
        rsa.oaep_decrypt(key, ct, label=b"context-B")


def test_oaep_failures_are_indistinguishable(key, other_key):
    good = rsa.oaep_encrypt(key.public, b"secret")
    bad_inputs = [
        good[:-1],  # wrong length
        bytes([good[0] ^ 1]) + good[1:],  # tampered
        b"\xff" * len(good),  # representative >= n
        bytes(len(good)),  # zero
        rsa.oaep_encrypt(other_key.public, b"secret"),  # encrypted for someone else
    ]
    messages = set()
    for bad in bad_inputs:
        with pytest.raises(ValueError) as info:
            rsa.oaep_decrypt(key, bad)
        messages.add(str(info.value))
    assert messages == {"decryption error"}


# ---------------------------------------------------------------- signatures --

def test_sign_and_verify(key):
    message = b"transfer 100 EUR to Alice"
    signature = rsa.sign(key, message)
    assert len(signature) == 128
    assert rsa.verify(key.public, message, signature)
    assert rsa.sign(key, message) == signature  # PKCS#1 v1.5 is deterministic


def test_verify_rejects_forgeries(key, other_key):
    message = b"transfer 100 EUR to Alice"
    signature = rsa.sign(key, message)
    assert not rsa.verify(key.public, b"transfer 900 EUR to Mallory", signature)
    assert not rsa.verify(other_key.public, message, signature)
    assert not rsa.verify(key.public, message, bytes([signature[0] ^ 1]) + signature[1:])
    assert not rsa.verify(key.public, message, signature[:-1])
    assert not rsa.verify(key.public, message, b"\xff" * 128)  # representative >= n
    assert not rsa.verify(key.public, message, bytes(128))


def test_signature_with_trailing_garbage_in_padding_is_rejected(key):
    """A parser that ignores bytes after the hash would accept this; we re-encode."""
    k = key.size_bytes
    forged_em = rsa._emsa_pkcs1_v15(b"msg", k)[:-1] + b"\x00"  # corrupt last hash byte
    forged_sig = rsa._private_op(key, int.from_bytes(forged_em, "big")).to_bytes(k, "big")
    assert not rsa.verify(key.public, b"msg", forged_sig)


def test_private_operation_detects_faults(key, monkeypatch):
    monkeypatch.setattr(rsa, "_crt_private", lambda k, c: 12345)
    with pytest.raises(RuntimeError, match="fault"):
        rsa.sign(key, b"x")
