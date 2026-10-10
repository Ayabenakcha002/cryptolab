# The mathematics behind cryptolab

[English](THEORY.md) · [Français](THEORY.fr.md)

This document explains *why* each primitive works, and points to where the idea lives in the code. Notation: ⊕ is XOR, ‖ is concatenation, `a mod n` is the remainder, ≡ is congruence.

---

## 1. SHA-256 (`sha256.py`)

**Goal.** Map a message of any length to 256 bits such that finding two messages with the same output (collision), or a message for a given output (preimage), is infeasible.

**Merkle-Damgård construction.**

1. *Padding:* append a `1` bit, then `0` bits until the length is 448 mod 512, then the original length as a 64-bit integer. The length makes `abc` and `abc\x00` hash differently.
2. Split into 512-bit blocks. Keep a 256-bit chaining value of eight 32-bit words `a…h`, initialised to H0.
3. For each block, expand its 16 words into a **message schedule** of 64 words, mixing earlier words with rotations and shifts (σ0, σ1).
4. Run 64 **rounds**. Each one computes two temporary values from `e`, `f`, `g`, `h`, a round constant and a schedule word, and from `a`, `b`, `c`:

   - `Ch(e,f,g) = (e ∧ f) ⊕ (¬e ∧ g)`: for each bit, "if `e` then `f` else `g`";
   - `Maj(a,b,c)`: the majority vote of three bits;
   - `Σ0`, `Σ1`: XOR of three rotations, which spreads every input bit across the word.

   Then the words shift down one position and two of them are recomputed.
5. Add the result to the chaining value (modulo 2³²). This feed-forward is what makes the compression function one-way.

**Why the constants are not arbitrary.** K[i] is the first 32 bits of the fractional part of ∛pᵢ and H0 that of √pᵢ for the first primes. These are "nothing-up-my-sleeve numbers": anyone can recompute them, so the designers cannot have hidden a weakness in them. `sha256.py` recomputes them with exact integer arithmetic (`isqrt`, and a Newton iteration for the cube root).

**Length extension.** The digest *is* the final chaining value, so an attacker who knows `H(m)` and `len(m)` can continue hashing and compute `H(m ‖ pad ‖ x)` without knowing `m`. That is why `H(key ‖ message)` is a broken MAC, and why HMAC exists.

## 2. HMAC (`mac.py`)

`HMAC(K, m) = H( (K′ ⊕ opad) ‖ H( (K′ ⊕ ipad) ‖ m ) )`

`K′` is the key zero-padded to the 64-byte block size (hashed first if longer); `ipad = 0x36…36`, `opad = 0x5c…5c`. The inner hash is wrapped by an outer one, which hides the internal state and blocks length extension. Security proofs show HMAC is a secure PRF if the compression function is.

## 3. AES (`aes.py`)

AES works on a 4×4 matrix of bytes (the *state*) for 10, 12 or 14 rounds (128-, 192- or 256-bit keys).

### 3.1 The field GF(2⁸)

A byte is a polynomial of degree ≤ 7 with coefficients in {0,1}: `0x57 = x⁶+x⁴+x²+x+1`.

- **Addition** is XOR.
- **Multiplication** is polynomial multiplication, reduced modulo the irreducible polynomial `x⁸+x⁴+x³+x+1` (`0x11B`). Multiplying by `x` is a left shift, XORed with `0x1B` if a bit fell off (`_xtime`).
- Because the modulus is irreducible, every non-zero byte has an inverse.
- The non-zero elements form a cyclic group of order 255 and `0x03` generates it. So every non-zero `a = 3ⁱ`, and `a · b = 3^(i+j mod 255)`: this is how the code multiplies and inverts using log/exp tables. FIPS 197 gives `0x57 · 0x83 = 0xC1`, which the tests check.

### 3.2 SubBytes: the S-box

`S(a) = affine(a⁻¹)`, with `0⁻¹ := 0`. Inversion is the *non-linear* part. It was chosen because it has excellent resistance to linear and differential cryptanalysis. The affine map `b ⊕ rotl(b,1) ⊕ rotl(b,2) ⊕ rotl(b,3) ⊕ rotl(b,4) ⊕ 0x63` removes the fixed points and algebraic structure of pure inversion. The table is *computed* at import time and checked against known values (`S(0x00)=0x63`, `S(0x53)=0xED`).

### 3.3 ShiftRows and MixColumns

- **ShiftRows** rotates row *r* of the state left by *r* bytes, so bytes of one column are spread over four columns.
- **MixColumns** multiplies each column, seen as a vector over GF(2⁸), by the matrix

  ```text
  | 02 03 01 01 |
  | 01 02 03 01 |
  | 01 01 02 03 |
  | 03 01 01 02 |
  ```

  Every output byte depends on four input bytes. Together, ShiftRows and MixColumns give **diffusion**: after two rounds every byte of the state depends on every input byte. The decryption matrix (`0E 0B 0D 09 …`) is the inverse of this one over GF(2⁸).

### 3.4 Key schedule

The key is split into words `w[0…Nk-1]`; each later word is `w[i] = w[i-Nk] ⊕ f(w[i-1])`, where `f` is the identity, or RotWord + SubWord + a round constant (every `Nk` words), or SubWord only (AES-256, every 4th word). Round constants are successive powers of `x` in GF(2⁸): `01, 02, 04, 08, 10, 20, 40, 80, 1B, 36`.

### 3.5 Round structure

`AddRoundKey` → (`SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`) × (Nr−1) → `SubBytes`, `ShiftRows`, `AddRoundKey`. The last round has no MixColumns. Decryption runs the inverse operations in reverse order.

**Side channels.** Indexing a 256-entry table with a secret byte takes a time that depends on the CPU cache state, which has been exploited remotely (Bernstein, 2005). Production AES uses hardware instructions (AES-NI) or bit-sliced code. This implementation does not.

## 4. Modes of operation (`modes.py`)

A block cipher is a permutation of 16-byte blocks. To encrypt a message you need a *mode*.

- **ECB** (encrypt each block independently) is not provided: equal plaintext blocks give equal ciphertext blocks, so patterns survive (the famous "ECB penguin").
- **CBC:** `Cᵢ = E(Pᵢ ⊕ Cᵢ₋₁)`, `C₀ = IV`. The IV must be unpredictable. Needs padding (PKCS#7). Unauthenticated, and padding errors reported to an attacker allow *padding-oracle* attacks that decrypt everything. Hence the single error message in `pkcs7_unpad`.
- **CTR:** `Cᵢ = Pᵢ ⊕ E(nonce ‖ counterᵢ)`. A stream cipher built from a block cipher: no padding, parallelisable. Reusing a counter value reveals `P ⊕ P′` of the two messages. Still unauthenticated: flipping a ciphertext bit flips the same plaintext bit.
- **GCM** = CTR + a polynomial MAC.
  - Let `H = E(0¹²⁸)`. **GHASH** treats 128-bit blocks as elements of GF(2¹²⁸) (modulus `x¹²⁸+x⁷+x²+x+1`, with the standard's reflected bit order) and computes `Y = (… ((A₁·H ⊕ A₂)·H ⊕ …) · H` over the associated data, the ciphertext and a final block holding their lengths. This is polynomial evaluation at the secret point `H`.
  - The **tag** is `E(J₀) ⊕ GHASH`, where `J₀ = IV ‖ 0³¹1`. Encryption uses CTR starting at `J₀ + 1`.
  - Two valid tags on messages under the same IV leak `H` (the "forbidden attack"), after which anyone can forge tags. **Never repeat a (key, IV) pair.** That is why the CLI draws 96 fresh random bits per file and derives a new key from a fresh salt anyway.
  - Decryption verifies the tag first (constant-time comparison) and refuses to decrypt on mismatch.

## 5. RSA (`numtheory.py`, `rsa.py`)

### 5.1 Why it works

Pick two large primes `p`, `q`; `n = pq`. Let `λ = lcm(p−1, q−1)`. Pick `e` with `gcd(e, λ) = 1` (65537 here) and compute `d = e⁻¹ mod λ` with the extended Euclidean algorithm. The public key is `(n, e)`, the private key `d`.

Encryption is `c = mᵉ mod n`; decryption is `m = cᵈ mod n`. **Why that returns `m`:** `ed = 1 + kλ`, so `mᵉᵈ = m · (m^λ)ᵏ`. By Fermat's little theorem `m^(p−1) ≡ 1 (mod p)` when `p ∤ m`, and `λ` is a multiple of `p−1`, so `mᵉᵈ ≡ m (mod p)`. (If `p | m` both sides are 0.) The same holds modulo `q`. Since `p` and `q` are coprime, the **Chinese Remainder Theorem** gives `mᵉᵈ ≡ m (mod n)`.

**Security** rests on the difficulty of factoring `n` (computing `d` from `(n, e)` is as hard as factoring). The largest factored RSA modulus has 829 bits (RSA-250, 2020), hence 2048 bits as a minimum today; a large quantum computer would break RSA with Shor's algorithm.

### 5.2 Primes: Miller-Rabin (`numtheory.py`)

Fermat's test (`aⁿ⁻¹ ≡ 1`) is fooled by Carmichael numbers like 561. Miller-Rabin writes `n − 1 = 2ˢd` and checks the sequence `aᵈ, a²ᵈ, …, a^(2^(s−1) d)`: for a prime it either starts at 1 or hits −1 (because the only square roots of 1 modulo a prime are ±1). A composite passes for at most 1/4 of the bases, so 40 random rounds give an error below 4⁻⁴⁰. Candidates are first sieved with the primes below 1000. Both top bits are forced to 1 so `pq` has exactly the requested size; `p` and `q` are rejected if too close together (Fermat factoring).

### 5.3 Speed: the CRT (`_crt_private`)

Computing `cᵈ mod n` directly costs one exponentiation with a 2048-bit modulus. Instead compute it modulo `p` and `q` (half-size numbers, and with exponents reduced mod `p−1`, `q−1`), then recombine: `m = m₂ + q · (q⁻¹(m₁ − m₂) mod p)`. Multiplication cost grows roughly quadratically, so this is about 4× faster.

### 5.4 Textbook RSA is broken

`c = mᵉ mod n` alone is:

- **deterministic:** the same message always gives the same ciphertext, so guesses can be confirmed;
- **malleable:** `(m₁m₂)ᵉ = m₁ᵉ·m₂ᵉ`, so an attacker can transform a ciphertext into the encryption of `2m` without the key;
- **weak for small `m`:** if `mᵉ < n` there is no modular reduction and `m` is just an integer `e`-th root.

### 5.5 OAEP (`oaep_encrypt`)

A two-round Feistel-like network with a random seed, using the hash function as mask generator (MGF1):

```text
DB = H(label) ‖ 00…00 ‖ 01 ‖ M
maskedDB   = DB   ⊕ MGF1(seed)
maskedSeed = seed ⊕ MGF1(maskedDB)
EM = 00 ‖ maskedSeed ‖ maskedDB          then   c = EMᵉ mod n
```

The random seed makes encryption probabilistic; the redundancy (`H(label)`, zeros, `01`) lets the decryptor detect any tampering. The decryptor must not reveal *which* check failed: Manger (2001) showed that distinguishing "first byte ≠ 0" from other errors allows decrypting a ciphertext with about 1000 queries. All failures therefore raise the same exception.

### 5.6 Signatures (`sign`, `verify`)

A signature is a *private-key* operation on a hash: `s = EM^d mod n`, where `EM = 00 01 FF…FF 00 ‖ DigestInfo ‖ SHA-256(m)`. To verify, compute `sᵉ mod n` and compare with the `EM` we rebuild ourselves, **not** by parsing the padding. Lenient parsers that stop after the hash (and ignore trailing bytes) allowed Bleichenbacher's 2006 forgery against small `e`. RSA-PSS is the modern, randomised scheme with a security proof; PKCS#1 v1.5 is implemented here because it is deterministic, widely deployed, and easy to cross-check with OpenSSL.

### 5.7 Defences in the private operation (`_private_op`)

- **Blinding:** decrypt `c · rᵉ` for a random `r`, then multiply by `r⁻¹`. The exponentiation never sees attacker-chosen data, which defeats timing attacks (Kocher, 1996).
- **Fault check:** a single bit-flip during the CRT computation gives a result that is correct modulo `p` but not modulo `q`; the faulty output then reveals `gcd(s′ᵉ − m, n) = p` (Boneh-DeMillo-Lipton, 1997). We re-encrypt the result and refuse to release it if it does not match.

## 6. What this project deliberately does not do

Constant-time arithmetic, hardware acceleration, AES-GCM with arbitrary IV lengths, RSA-PSS, ECC and password hashing from scratch. Each of them is a good next project.

## References

- NIST FIPS 197, *Advanced Encryption Standard*; FIPS 180-4, *Secure Hash Standard*.
- NIST SP 800-38A (CBC, CTR) and SP 800-38D (GCM).
- RFC 2104 (HMAC), RFC 4231 (HMAC-SHA-2 test vectors), RFC 8017 (PKCS#1 v2.2).
- J. Daemen, V. Rijmen, *The Design of Rijndael*.
- D. Bleichenbacher, "Chosen ciphertext attacks against protocols based on RSA Encryption Standard PKCS #1" (1998); J. Manger, "A chosen ciphertext attack on RSA OAEP" (2001).
