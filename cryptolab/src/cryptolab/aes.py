"""AES (FIPS 197) block cipher implemented from scratch.

Educational code. It is table-driven pure Python: it is slow and, like every
table-lookup AES, it is *not* resistant to cache-timing attacks. For real
systems use a vetted library backed by AES-NI.

As with SHA-256, nothing is copy-pasted from the standard. The S-box is
*computed* from its mathematical definition:

1. take the multiplicative inverse of the byte in GF(2^8) (0 maps to 0);
2. apply a fixed affine transformation over GF(2) and add 0x63.

GF(2^8) here is the field of polynomials modulo x^8 + x^4 + x^3 + x + 1 (0x11B).
"""

from __future__ import annotations

from typing import List, Sequence

_REDUCTION = 0x11B


def _xtime(a: int) -> int:
    """Multiply a field element by x (i.e. by 2)."""
    a <<= 1
    if a & 0x100:
        a ^= _REDUCTION
    return a


# 3 is a generator of the multiplicative group of GF(2^8), so every non-zero
# element is 3^i for a unique i in 0..254. That gives us log/exp tables and
# therefore fast multiplication and inversion.
_EXP: List[int] = [0] * 255
_LOG: List[int] = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x ^= _xtime(_x)  # x * 3 = x*2 xor x
del _x, _i


def gf_mul(a: int, b: int) -> int:
    """Multiply two elements of GF(2^8)."""
    if a == 0 or b == 0:
        return 0
    return _EXP[(_LOG[a] + _LOG[b]) % 255]


def gf_inverse(a: int) -> int:
    """Multiplicative inverse in GF(2^8); by convention 0 maps to 0."""
    if a == 0:
        return 0
    return _EXP[(255 - _LOG[a]) % 255]


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox() -> List[int]:
    sbox = []
    for a in range(256):
        inv = gf_inverse(a)
        sbox.append(
            inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63
        )
    return sbox


SBOX: List[int] = _build_sbox()
INV_SBOX: List[int] = [0] * 256
for _a, _s in enumerate(SBOX):
    INV_SBOX[_s] = _a
del _a, _s

# Precomputed multiplication tables used by (Inv)MixColumns.
_MUL = {k: [gf_mul(k, a) for a in range(256)] for k in (2, 3, 9, 11, 13, 14)}

# The state is a flat list of 16 bytes in column-major order (byte i sits in
# row i % 4, column i // 4), which is exactly the order of the input block.
# ShiftRows rotates row r left by r positions.
_SHIFT = tuple(r + 4 * ((c + r) % 4) for c in range(4) for r in range(4))
_INV_SHIFT = [0] * 16
for _i, _j in enumerate(_SHIFT):
    _INV_SHIFT[_j] = _i
del _i, _j


def _expand_key(key: bytes) -> List[List[int]]:
    """Key schedule: turn the cipher key into Nr + 1 round keys of 16 bytes."""
    nk = len(key) // 4  # key length in 32-bit words
    nr = nk + 6  # number of rounds
    words: List[List[int]] = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]  # RotWord
            temp = [SBOX[b] for b in temp]  # SubWord
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:  # extra SubWord step for AES-256 only
            temp = [SBOX[b] for b in temp]
        words.append([a ^ b for a, b in zip(words[i - nk], temp)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(nr + 1)]


def _mix_columns(s: Sequence[int]) -> List[int]:
    m2, m3 = _MUL[2], _MUL[3]
    out = [0] * 16
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
        out[c] = m2[a0] ^ m3[a1] ^ a2 ^ a3
        out[c + 1] = a0 ^ m2[a1] ^ m3[a2] ^ a3
        out[c + 2] = a0 ^ a1 ^ m2[a2] ^ m3[a3]
        out[c + 3] = m3[a0] ^ a1 ^ a2 ^ m2[a3]
    return out


def _inv_mix_columns(s: Sequence[int]) -> List[int]:
    m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
    out = [0] * 16
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
        out[c] = m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3]
        out[c + 1] = m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3]
        out[c + 2] = m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3]
        out[c + 3] = m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]
    return out


class AES:
    """AES-128, AES-192 or AES-256 on single 16-byte blocks.

    This is a raw block cipher: it is *not* an encryption scheme on its own.
    Use it through the modes in :mod:`cryptolab.modes` (GCM is the one to pick).
    """

    block_size = 16

    def __init__(self, key: bytes) -> None:
        key = bytes(key)
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes long")
        self._round_keys = _expand_key(key)
        self._rounds = len(key) // 4 + 6

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES operates on 16-byte blocks")
        rk = self._round_keys
        state = [b ^ k for b, k in zip(block, rk[0])]
        for r in range(1, self._rounds):
            state = [SBOX[b] for b in state]  # SubBytes
            state = [state[i] for i in _SHIFT]  # ShiftRows
            state = _mix_columns(state)  # MixColumns
            state = [b ^ k for b, k in zip(state, rk[r])]  # AddRoundKey
        state = [SBOX[b] for b in state]
        state = [state[i] for i in _SHIFT]
        return bytes(b ^ k for b, k in zip(state, rk[self._rounds]))

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES operates on 16-byte blocks")
        rk = self._round_keys
        state = [b ^ k for b, k in zip(block, rk[self._rounds])]
        for r in range(self._rounds - 1, 0, -1):
            state = [state[i] for i in _INV_SHIFT]  # InvShiftRows
            state = [INV_SBOX[b] for b in state]  # InvSubBytes
            state = [b ^ k for b, k in zip(state, rk[r])]  # AddRoundKey
            state = _inv_mix_columns(state)  # InvMixColumns
        state = [state[i] for i in _INV_SHIFT]
        state = [INV_SBOX[b] for b in state]
        return bytes(b ^ k for b, k in zip(state, rk[0]))
