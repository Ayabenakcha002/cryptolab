# cryptolab

[English](README.md) · [Français](README.fr.md)

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-none-brightgreen)
![Purpose](https://img.shields.io/badge/purpose-educational-orange)

**cryptolab** is a from-scratch implementation of the cryptographic building blocks that protect most of the internet, written in readable pure Python, with no runtime dependency:

| Primitive | Standard | What is implemented |
|---|---|---|
| **SHA-256** | FIPS 180-4 | streaming hash; constants *derived* from prime roots, not pasted |
| **HMAC-SHA256** | RFC 2104 | keyed message authentication |
| **AES-128/192/256** | FIPS 197 | block cipher; S-box *computed* from GF(2⁸) arithmetic |
| **CBC, CTR, GCM** | SP 800-38A/D | modes of operation; GCM gives authenticated encryption |
| **RSA** | RFC 8017 | key generation (Miller-Rabin), OAEP encryption, PKCS#1 v1.5 signatures, CRT + blinding + fault check |

The goal is to **understand** cryptography by building it, and to prove the result correct against independent implementations.

> ⚠️ **Security notice.** This is an **educational** library. It is slow, it is not constant-time (pure-Python big integers and table-lookup AES leak timing information), and it has not been audited. **Never use it to protect real secrets.** In real projects use a vetted library such as [`cryptography`](https://cryptography.io) or libsodium.

## Why you can trust that it is correct

Writing crypto is easy; writing *correct* crypto is not. Every primitive is tested three ways:

1. **Official test vectors:** FIPS 197 (appendices B and C), FIPS 180-4 / NIST SHA examples (including the one-million-`a` message), NIST SP 800-38A (CBC, CTR), the McGrew-Viega GCM test cases, RFC 4231 (HMAC).
2. **Differential testing:** random inputs, all key sizes, byte-for-byte comparison with `hashlib`, `hmac` and OpenSSL (through the `cryptography` package): AES block cipher, CBC, CTR, GCM, SHA-256 at every padding boundary, HMAC with every key-length case.
3. **Interoperability:** keys generated here are accepted by OpenSSL; we decrypt OpenSSL's RSA-OAEP ciphertexts and verify its signatures, and the reverse. The `openssl` command-line tool was also used to check a ciphertext and a signature produced by this code.

Plus behavioural tests for the security properties: tamper detection in GCM, indistinguishable OAEP failures, rejection of malformed signatures, fault detection, weak key sizes refused. **321 tests**, run on Python 3.9 to 3.13 by GitHub Actions.

## Installation

```bash
git clone https://github.com/<your-username>/cryptolab.git
cd cryptolab
python -m pip install -e ".[dev]"     # "dev" adds pytest and the reference library used by the tests
```

Python 3.9+. The library itself needs nothing but the standard library.

## Library usage

```python
from cryptolab import AES, gcm_encrypt, gcm_decrypt, InvalidTag, sha256, hmac_sha256
import os

# Hashing and MAC
print(sha256(b"abc").hex())
tag = hmac_sha256(b"secret key", b"message")

# Authenticated encryption: AES-256-GCM
key, nonce = os.urandom(32), os.urandom(12)      # a nonce must NEVER repeat under one key
ciphertext, tag = gcm_encrypt(AES(key), nonce, b"attack at dawn", aad=b"header")
assert gcm_decrypt(AES(key), nonce, ciphertext, tag, aad=b"header") == b"attack at dawn"
try:
    gcm_decrypt(AES(key), nonce, ciphertext[:-1] + b"X", tag, aad=b"header")
except InvalidTag:
    print("tampering detected")
```

```python
from cryptolab import generate_keypair, oaep_encrypt, oaep_decrypt, sign, verify

key = generate_keypair(2048)                      # about a second
secret = oaep_encrypt(key.public, b"hello")       # randomised: different each time
assert oaep_decrypt(key, secret) == b"hello"

signature = sign(key, b"contract v1")
assert verify(key.public, b"contract v1", signature)
assert not verify(key.public, b"contract v2", signature)
```

## Command line

```bash
cryptolab hash file.pdf                                  # like sha256sum
cryptolab encrypt notes.txt -o notes.enc                 # password-based, AES-256-GCM
cryptolab decrypt notes.enc -o notes.txt

cryptolab rsa-keygen -b 2048 -o alice                    # writes alice (private, mode 600) and alice.pub
cryptolab rsa-encrypt -k alice.pub short.txt -o short.rsa
cryptolab rsa-decrypt -k alice short.rsa -o short.txt
cryptolab rsa-sign -k alice contract.pdf -o contract.sig
cryptolab rsa-verify -k alice.pub contract.pdf contract.sig   # exit code 0 = valid
```

The file format of `encrypt` is `magic | salt | nonce | ciphertext | tag`, and the header is authenticated as GCM associated data. The password is turned into a key with the standard library's scrypt: key derivation is not what this project teaches, and a pure-Python password hash would take minutes. The password is read from a hidden prompt (never from the command line, where it would appear in shell history and process lists).

## Design decisions worth knowing

- **Derived constants.** SHA-256's 72 constants come from integer cube/square roots of primes; the AES S-box from the inverse in GF(2⁸) followed by an affine map. Fewer magic numbers, fewer typos, and you can see *why* they are what they are.
- **Authenticated encryption first.** GCM is the recommended mode; the tag is checked **before** any decryption and compared in constant time. CBC and CTR are provided for study and carry a warning.
- **RSA done properly.** OAEP rather than textbook RSA; all OAEP failures raise one identical error (against Manger's attack); signature verification re-encodes and compares instead of parsing padding (against Bleichenbacher-style forgeries); private operations use blinding and a CRT fault check; keys under 1024 bits and primes that are too close together are refused.
- **Honest scope.** Not implemented on purpose: GCM with IVs other than 96 bits, RSA-PSS, elliptic curves, side-channel hardening. See [`docs/THEORY.md`](docs/THEORY.md) for the mathematics behind each primitive.

## Performance

Measured on a cloud VM (so only the orders of magnitude matter). Pure Python is roughly **1000× slower** than OpenSSL, which is why this is a learning tool.

| Operation | cryptolab | Reference |
|---|---|---|
| SHA-256 | about 0.4 MB/s | `hashlib`: hundreds of MB/s |
| AES-256-GCM (encrypt 1 MB) | about 4 s | OpenSSL with AES-NI: milliseconds |
| RSA-2048 key generation | about 1 s | |

## Project layout

```text
src/cryptolab/
├── sha256.py      SHA-256 with derived constants
├── mac.py         HMAC-SHA256
├── aes.py         GF(2^8) arithmetic, S-box, key schedule, block cipher
├── modes.py       CBC, CTR, GCM (GHASH in GF(2^128))
├── numtheory.py   extended Euclid, modular inverse, Miller-Rabin, prime generation
├── rsa.py         keys, OAEP, PKCS#1 v1.5 signatures
├── utils.py       PKCS#7, XOR, constant-time comparison
└── cli.py         the `cryptolab` command
tests/             321 tests: official vectors, differential, interoperability, behaviour
docs/THEORY.md     the mathematics behind every primitive
```

## Tests

```bash
python -m pytest
```

## Further reading

NIST FIPS 197 (AES) · FIPS 180-4 (SHS) · SP 800-38A and 38D (modes, GCM) · RFC 2104 (HMAC) · RFC 8017 (PKCS#1) · *Cryptography Engineering* (Ferguson, Schneier, Kohno) · *Serious Cryptography* (Aumasson).

## License

MIT. See [LICENSE](LICENSE).
