"""Cross-check against the `cryptography` package (OpenSSL). Skipped if absent.

This is the strongest evidence that the from-scratch code is correct: random
inputs, all key sizes, compared byte-for-byte with an independent, audited
implementation.
"""

import os

import pytest

from cryptolab import modes
from cryptolab.aes import AES

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import padding  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms  # noqa: E402
from cryptography.hazmat.primitives.ciphers import modes as cmodes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402


@pytest.mark.parametrize("key_len", [16, 24, 32])
def test_block_cipher_matches_openssl(key_len):
    key = os.urandom(key_len)
    ours = AES(key)
    ref = Cipher(algorithms.AES(key), cmodes.ECB())
    for _ in range(30):
        block = os.urandom(16)
        expected = ref.encryptor().update(block)
        assert ours.encrypt_block(block) == expected
        assert ours.decrypt_block(expected) == block


@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("length", [0, 1, 16, 77])
def test_cbc_and_ctr_match_openssl(key_len, length):
    key, iv, data = os.urandom(key_len), os.urandom(16), os.urandom(length)
    ours = AES(key)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), cmodes.CBC(iv)).encryptor()
    assert modes.cbc_encrypt(ours, iv, data) == enc.update(padded) + enc.finalize()

    enc = Cipher(algorithms.AES(key), cmodes.CTR(iv)).encryptor()
    assert modes.ctr_crypt(ours, iv, data) == enc.update(data) + enc.finalize()


@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("aad_len", [0, 5, 16, 33])
@pytest.mark.parametrize("data_len", [0, 1, 16, 50])
def test_gcm_matches_openssl(key_len, aad_len, data_len):
    key, iv = os.urandom(key_len), os.urandom(12)
    aad, data = os.urandom(aad_len), os.urandom(data_len)
    ct, tag = modes.gcm_encrypt(AES(key), iv, data, aad)
    assert ct + tag == AESGCM(key).encrypt(iv, data, aad)
    assert AESGCM(key).decrypt(iv, ct + tag, aad) == data
