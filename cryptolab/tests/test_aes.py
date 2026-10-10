import os

import pytest

from cryptolab.aes import AES, INV_SBOX, SBOX, gf_inverse, gf_mul
from cryptolab.modes import (
    InvalidTag,
    cbc_decrypt,
    cbc_encrypt,
    ctr_crypt,
    gcm_decrypt,
    gcm_encrypt,
)

H = bytes.fromhex


def test_sbox_known_values_and_bijection():
    assert SBOX[0x00] == 0x63 and SBOX[0x01] == 0x7C and SBOX[0x53] == 0xED
    assert sorted(SBOX) == list(range(256))
    assert all(INV_SBOX[SBOX[a]] == a for a in range(256))


def test_field_arithmetic_from_fips_197():
    assert gf_mul(0x57, 0x83) == 0xC1  # example in FIPS 197, section 4.2
    assert gf_mul(0x57, 0x13) == 0xFE
    assert all(gf_mul(a, gf_inverse(a)) == 1 for a in range(1, 256))


# FIPS 197, appendix C.
@pytest.mark.parametrize(
    "key,ciphertext",
    [
        ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    ],
)
def test_fips_197_appendix_c(key, ciphertext):
    plaintext = H("00112233445566778899aabbccddeeff")
    aes = AES(H(key))
    assert aes.encrypt_block(plaintext) == H(ciphertext)
    assert aes.decrypt_block(H(ciphertext)) == plaintext


def test_fips_197_appendix_b():
    aes = AES(H("2b7e151628aed2a6abf7158809cf4f3c"))
    assert aes.encrypt_block(H("3243f6a8885a308d313198a2e0370734")) == H(
        "3925841d02dc09fbdc118597196a0b32"
    )


@pytest.mark.parametrize("key_len", [16, 24, 32])
def test_decrypt_inverts_encrypt(key_len):
    aes = AES(os.urandom(key_len))
    for _ in range(25):
        block = os.urandom(16)
        assert aes.decrypt_block(aes.encrypt_block(block)) == block


@pytest.mark.parametrize("key_len", [0, 15, 17, 20, 31, 33, 64])
def test_invalid_key_sizes(key_len):
    with pytest.raises(ValueError):
        AES(bytes(key_len))


def test_invalid_block_size():
    aes = AES(bytes(16))
    for bad in (b"", bytes(15), bytes(17)):
        with pytest.raises(ValueError):
            aes.encrypt_block(bad)
        with pytest.raises(ValueError):
            aes.decrypt_block(bad)


# NIST SP 800-38A, appendix F (AES-128).
SP800_KEY = H("2b7e151628aed2a6abf7158809cf4f3c")
SP800_PT = H(
    "6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710"
)


def test_cbc_sp800_38a_f21():
    iv = H("000102030405060708090a0b0c0d0e0f")
    expected = H(
        "7649abac8119b246cee98e9b12e9197d" "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516" "3ff1caa1681fac09120eca307586e1a7"
    )
    out = cbc_encrypt(AES(SP800_KEY), iv, SP800_PT)
    assert out[:64] == expected  # the 5th block is the PKCS#7 padding block
    assert len(out) == 80
    assert cbc_decrypt(AES(SP800_KEY), iv, out) == SP800_PT


def test_ctr_sp800_38a_f51():
    counter = H("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    expected = H(
        "874d6191b620e3261bef6864990db6ce" "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab" "1e031dda2fbe03d1792170a0f3009cee"
    )
    assert ctr_crypt(AES(SP800_KEY), counter, SP800_PT) == expected
    assert ctr_crypt(AES(SP800_KEY), counter, expected) == SP800_PT


def test_ctr_counter_wraps_around_128_bits_and_handles_partial_blocks():
    aes = AES(SP800_KEY)
    data = os.urandom(37)
    out = ctr_crypt(aes, b"\xff" * 16, data)
    assert len(out) == 37
    assert ctr_crypt(aes, b"\xff" * 16, out) == data


@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 100])
def test_cbc_round_trip_all_padding_cases(length):
    aes, iv, data = AES(os.urandom(32)), os.urandom(16), os.urandom(length)
    assert cbc_decrypt(aes, iv, cbc_encrypt(aes, iv, data)) == data


def test_cbc_rejects_bad_input():
    aes, iv = AES(bytes(16)), bytes(16)
    with pytest.raises(ValueError):
        cbc_encrypt(aes, bytes(8), b"x")
    with pytest.raises(ValueError):
        cbc_decrypt(aes, iv, b"")
    with pytest.raises(ValueError):
        cbc_decrypt(aes, iv, bytes(17))
    with pytest.raises(ValueError, match="invalid padding"):
        cbc_decrypt(aes, iv, os.urandom(32))  # random data: padding almost surely wrong


# McGrew & Viega, "The Galois/Counter Mode of Operation", test cases 1, 2 and 4.
def test_gcm_test_case_1_empty_message():
    ct, tag = gcm_encrypt(AES(bytes(16)), bytes(12), b"")
    assert ct == b"" and tag == H("58e2fccefa7e3061367f1d57a4e7455a")


def test_gcm_test_case_2():
    ct, tag = gcm_encrypt(AES(bytes(16)), bytes(12), bytes(16))
    assert ct == H("0388dace60b6a392f328c2b971b2fe78")
    assert tag == H("ab6e47d42cec13bdf53a67b21257bddf")


GCM4 = dict(
    key=H("feffe9928665731c6d6a8f9467308308"),
    iv=H("cafebabefacedbaddecaf888"),
    pt=H(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    ),
    aad=H("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
    ct=H(
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
    ),
    tag=H("5bc94fbc3221a5db94fae95ae7121a47"),
)


def test_gcm_test_case_4_with_aad_and_partial_block():
    aes = AES(GCM4["key"])
    ct, tag = gcm_encrypt(aes, GCM4["iv"], GCM4["pt"], GCM4["aad"])
    assert (ct, tag) == (GCM4["ct"], GCM4["tag"])
    assert gcm_decrypt(aes, GCM4["iv"], ct, tag, GCM4["aad"]) == GCM4["pt"]


def test_gcm_detects_every_kind_of_tampering():
    aes, iv = AES(os.urandom(32)), os.urandom(12)
    ct, tag = gcm_encrypt(aes, iv, b"attack at dawn", b"header")
    assert gcm_decrypt(aes, iv, ct, tag, b"header") == b"attack at dawn"
    flipped = bytes([ct[0] ^ 1]) + ct[1:]
    for args in (
        (iv, flipped, tag, b"header"),  # ciphertext modified
        (iv, ct, bytes([tag[0] ^ 1]) + tag[1:], b"header"),  # tag modified
        (iv, ct, tag, b"HEADER"),  # associated data modified
        (os.urandom(12), ct, tag, b"header"),  # wrong IV
        (iv, ct, tag[:-1], b"header"),  # truncated tag
    ):
        with pytest.raises(InvalidTag):
            gcm_decrypt(aes, *args)
    with pytest.raises(InvalidTag):
        gcm_decrypt(AES(os.urandom(32)), iv, ct, tag, b"header")  # wrong key


def test_gcm_rejects_non_96_bit_iv():
    with pytest.raises(ValueError):
        gcm_encrypt(AES(bytes(16)), bytes(16), b"x")
    with pytest.raises(ValueError):
        gcm_decrypt(AES(bytes(16)), bytes(8), b"x", bytes(16))
