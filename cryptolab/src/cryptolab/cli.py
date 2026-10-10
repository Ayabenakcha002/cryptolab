"""Command-line interface: hashing, password-based file encryption, RSA."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__, rsa
from .aes import AES
from .modes import InvalidTag, gcm_decrypt, gcm_encrypt, random_iv
from .sha256 import SHA256

NOTICE = "cryptolab is an EDUCATIONAL library. Do not use it to protect real secrets."
MAGIC = b"CLAB1"
SALT_LEN, NONCE_LEN, TAG_LEN = 16, 12, 16
PASSWORD_ENV = "CRYPTOLAB_PASSWORD"


class CliError(Exception):
    """A user-facing error (printed without a traceback)."""


def _derive_key(password: str, salt: bytes) -> bytes:
    # Key derivation is not what this project teaches, and a pure-Python
    # password hash would take minutes: use the standard library's scrypt.
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1,
                          maxmem=64 * 1024 * 1024, dklen=32)


def _get_password(confirm: bool) -> str:
    env = os.environ.get(PASSWORD_ENV)
    if env:
        return env
    password = getpass.getpass("Password: ")
    if confirm and getpass.getpass("Repeat password: ") != password:
        raise CliError("passwords do not match")
    if not password:
        raise CliError("empty password")
    return password


def _read(path: str) -> bytes:
    try:
        return sys.stdin.buffer.read() if path == "-" else Path(path).read_bytes()
    except OSError as exc:
        raise CliError(f"cannot read {path}: {exc.strerror}") from None


def _write(path: str, data: bytes, force: bool, private: bool = False) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    try:
        fd = os.open(path, flags, 0o600 if private else 0o644)
    except FileExistsError:
        raise CliError(f"{path} already exists (use --force to overwrite)") from None
    except OSError as exc:
        raise CliError(f"cannot write {path}: {exc.strerror}") from None
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _load_key(path: str, private: bool):
    try:
        data = json.loads(_read(path))
        return rsa.PrivateKey.from_dict(data) if private else (
            rsa.PublicKey.from_dict(data) if data.get("type") == "rsa-public"
            else rsa.PrivateKey.from_dict(data).public
        )
    except (ValueError, KeyError, AttributeError, TypeError):
        raise CliError(f"{path} is not a valid RSA key file") from None


# ---------------------------------------------------------------- commands --

def cmd_hash(args: argparse.Namespace) -> int:
    for path in args.files:
        digest = SHA256()
        try:
            if path == "-":
                for chunk in iter(lambda: sys.stdin.buffer.read(65536), b""):
                    digest.update(chunk)
            else:
                with open(path, "rb") as handle:
                    for chunk in iter(lambda: handle.read(65536), b""):
                        digest.update(chunk)
        except OSError as exc:
            raise CliError(f"cannot read {path}: {exc.strerror}") from None
        print(f"{digest.hexdigest()}  {path}")
    return 0


def cmd_encrypt(args: argparse.Namespace) -> int:
    plaintext = _read(args.input)
    salt, nonce = os.urandom(SALT_LEN), random_iv()
    header = MAGIC + salt + nonce
    aes = AES(_derive_key(_get_password(confirm=True), salt))
    ciphertext, tag = gcm_encrypt(aes, nonce, plaintext, aad=header)
    _write(args.output, header + ciphertext + tag, args.force)
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    blob = _read(args.input)
    header_len = len(MAGIC) + SALT_LEN + NONCE_LEN
    if len(blob) < header_len + TAG_LEN or not blob.startswith(MAGIC):
        raise CliError("not a cryptolab encrypted file")
    header = blob[:header_len]
    salt = header[len(MAGIC):len(MAGIC) + SALT_LEN]
    nonce = header[len(MAGIC) + SALT_LEN:]
    aes = AES(_derive_key(_get_password(confirm=False), salt))
    try:
        plaintext = gcm_decrypt(aes, nonce, blob[header_len:-TAG_LEN], blob[-TAG_LEN:], aad=header)
    except InvalidTag:
        raise CliError("wrong password or corrupted file") from None
    _write(args.output, plaintext, args.force)
    return 0


def cmd_rsa_keygen(args: argparse.Namespace) -> int:
    print(f"Generating a {args.bits}-bit RSA key (pure Python, can take a while)...",
          file=sys.stderr)
    key = rsa.generate_keypair(args.bits)
    private_path = args.out
    public_path = args.out + ".pub"
    _write(private_path, json.dumps(key.to_dict(), indent=2).encode(), args.force, private=True)
    _write(public_path, json.dumps(key.public.to_dict(), indent=2).encode(), args.force)
    print(f"Private key: {private_path}\nPublic key:  {public_path}", file=sys.stderr)
    return 0


def cmd_rsa_encrypt(args: argparse.Namespace) -> int:
    key = _load_key(args.key, private=False)
    message = _read(args.input)
    try:
        ciphertext = rsa.oaep_encrypt(key, message)
    except ValueError as exc:
        raise CliError(f"{exc}. RSA encrypts short messages only: use 'encrypt' for files.") from None
    _write(args.output, ciphertext, args.force)
    return 0


def cmd_rsa_decrypt(args: argparse.Namespace) -> int:
    key = _load_key(args.key, private=True)
    try:
        message = rsa.oaep_decrypt(key, _read(args.input))
    except ValueError:
        raise CliError("decryption failed") from None
    _write(args.output, message, args.force)
    return 0


def cmd_rsa_sign(args: argparse.Namespace) -> int:
    key = _load_key(args.key, private=True)
    _write(args.output, rsa.sign(key, _read(args.input)), args.force)
    return 0


def cmd_rsa_verify(args: argparse.Namespace) -> int:
    key = _load_key(args.key, private=False)
    if rsa.verify(key, _read(args.input), _read(args.signature)):
        print("Signature OK")
        return 0
    print("Signature INVALID", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptolab", description=NOTICE)
    parser.add_argument("--version", action="version", version=f"cryptolab {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, func, help_text: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text, description=help_text)
        p.set_defaults(func=func)
        return p

    p = add("hash", cmd_hash, "print SHA-256 digests (use '-' for stdin)")
    p.add_argument("files", nargs="+", metavar="FILE")

    for name, func, text in (
        ("encrypt", cmd_encrypt, "encrypt a file with a password (AES-256-GCM)"),
        ("decrypt", cmd_decrypt, "decrypt a file produced by 'encrypt'"),
        ("rsa-encrypt", cmd_rsa_encrypt, "encrypt a SHORT message with an RSA public key (OAEP)"),
        ("rsa-decrypt", cmd_rsa_decrypt, "decrypt with an RSA private key"),
        ("rsa-sign", cmd_rsa_sign, "sign a file (RSASSA-PKCS1-v1_5, SHA-256)"),
    ):
        p = add(name, func, text)
        if name.startswith("rsa-"):
            p.add_argument("-k", "--key", required=True, help="RSA key file")
        p.add_argument("input", metavar="INPUT")
        p.add_argument("-o", "--output", required=True)
        p.add_argument("--force", action="store_true", help="overwrite the output file")

    p = add("rsa-verify", cmd_rsa_verify, "verify a signature (exit code 0 = valid)")
    p.add_argument("-k", "--key", required=True, help="RSA public (or private) key file")
    p.add_argument("input", metavar="FILE")
    p.add_argument("signature", metavar="SIGNATURE")

    p = add("rsa-keygen", cmd_rsa_keygen, "generate an RSA key pair (OUT and OUT.pub)")
    p.add_argument("-b", "--bits", type=int, default=2048, help="key size (default 2048)")
    p.add_argument("-o", "--out", required=True, help="private key file; public key gets '.pub'")
    p.add_argument("--force", action="store_true", help="overwrite existing key files")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CliError as exc:
        print(f"cryptolab: error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"cryptolab: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
