"""cryptolab - cryptographic primitives implemented from scratch for learning.

EDUCATIONAL USE ONLY. For real systems use a vetted library.
"""

__version__ = "0.1.0"

from .aes import AES
from .mac import hmac_sha256
from .modes import (
    InvalidTag,
    cbc_decrypt,
    cbc_encrypt,
    ctr_crypt,
    gcm_decrypt,
    gcm_encrypt,
)
from .rsa import (
    PrivateKey,
    PublicKey,
    generate_keypair,
    oaep_decrypt,
    oaep_encrypt,
    sign,
    verify,
)
from .sha256 import SHA256, sha256

__all__ = [
    "AES", "InvalidTag", "PrivateKey", "PublicKey", "SHA256",
    "cbc_decrypt", "cbc_encrypt", "ctr_crypt", "gcm_decrypt", "gcm_encrypt",
    "generate_keypair", "hmac_sha256", "oaep_decrypt", "oaep_encrypt",
    "sha256", "sign", "verify",
]
