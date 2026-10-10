import hashlib
import hmac as std_hmac
import os

import pytest

from cryptolab.mac import hmac_sha256
from cryptolab.sha256 import SHA256, _H0, _K, _icbrt, sha256


def test_derived_constants_match_the_standard():
    assert _K[0] == 0x428A2F98 and _K[1] == 0x71374491 and _K[63] == 0xC67178F2
    assert _H0[0] == 0x6A09E667 and _H0[7] == 0x5BE0CD19


@pytest.mark.parametrize("n", [0, 1, 7, 8, 26, 27, 28, 10 ** 30, 10 ** 30 - 1, 2 ** 96 * 311])
def test_integer_cube_root(n):
    x = _icbrt(n)
    assert x ** 3 <= n < (x + 1) ** 3


# FIPS 180-4 / NIST example messages.
@pytest.mark.parametrize(
    "message,digest",
    [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ],
)
def test_known_digests(message, digest):
    assert sha256(message).hex() == digest


def test_one_million_a():
    h = SHA256()
    for _ in range(1000):
        h.update(b"a" * 1000)
    assert h.hexdigest() == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"


@pytest.mark.parametrize("length", list(range(0, 140)) + [1000, 4097])
def test_matches_hashlib_for_every_padding_boundary(length):
    data = os.urandom(length)
    assert sha256(data) == hashlib.sha256(data).digest()


def test_incremental_updates_match_one_shot():
    data = os.urandom(1000)
    h = SHA256()
    for i in range(0, len(data), 37):
        h.update(data[i:i + 37])
    assert h.digest() == hashlib.sha256(data).digest()


def test_digest_does_not_consume_state_and_copy_is_independent():
    h = SHA256(b"hello ")
    first = h.digest()
    assert h.digest() == first
    clone = h.copy()
    clone.update(b"world")
    h.update(b"there")
    assert clone.digest() == hashlib.sha256(b"hello world").digest()
    assert h.digest() == hashlib.sha256(b"hello there").digest()


# RFC 4231 test vectors.
def test_hmac_rfc4231_case_1():
    key, data = b"\x0b" * 20, b"Hi There"
    assert hmac_sha256(key, data).hex() == (
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )


def test_hmac_rfc4231_case_2():
    assert hmac_sha256(b"Jefe", b"what do ya want for nothing?").hex() == (
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )


def test_hmac_rfc4231_case_6_key_longer_than_block():
    key = b"\xaa" * 131
    data = b"Test Using Larger Than Block-Size Key - Hash Key First"
    assert hmac_sha256(key, data).hex() == (
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    )


@pytest.mark.parametrize("key_len", [0, 1, 32, 64, 65, 200])
def test_hmac_matches_stdlib(key_len):
    key, data = os.urandom(key_len), os.urandom(123)
    assert hmac_sha256(key, data) == std_hmac.new(key, data, "sha256").digest()
