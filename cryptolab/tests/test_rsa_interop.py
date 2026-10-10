"""RSA cross-checks against the `cryptography` package (OpenSSL)."""

import pytest

from cryptolab import rsa
from cryptolab.numtheory import modinv

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa as crsa  # noqa: E402


@pytest.fixture(scope="module")
def keys():
    ours = rsa.generate_keypair(2048)
    numbers = crsa.RSAPrivateNumbers(
        p=ours.p, q=ours.q, d=ours.d,
        dmp1=ours.d % (ours.p - 1), dmq1=ours.d % (ours.q - 1), iqmp=modinv(ours.q, ours.p),
        public_numbers=crsa.RSAPublicNumbers(ours.e, ours.n),
    )
    # `private_key()` makes OpenSSL validate p, q, d, n: our key is well formed.
    return ours, numbers.private_key()


OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
MESSAGE = b"interoperability check \x00\xff"


def test_openssl_decrypts_our_oaep(keys):
    ours, theirs = keys
    assert theirs.decrypt(rsa.oaep_encrypt(ours.public, MESSAGE), OAEP) == MESSAGE


def test_we_decrypt_openssl_oaep(keys):
    ours, theirs = keys
    assert rsa.oaep_decrypt(ours, theirs.public_key().encrypt(MESSAGE, OAEP)) == MESSAGE


def test_openssl_verifies_our_signature(keys):
    ours, theirs = keys
    signature = rsa.sign(ours, MESSAGE)
    theirs.public_key().verify(signature, MESSAGE, padding.PKCS1v15(), hashes.SHA256())


def test_we_verify_openssl_signature(keys):
    ours, theirs = keys
    signature = theirs.sign(MESSAGE, padding.PKCS1v15(), hashes.SHA256())
    assert rsa.verify(ours.public, MESSAGE, signature)
    assert signature == rsa.sign(ours, MESSAGE)  # deterministic, so byte-identical
