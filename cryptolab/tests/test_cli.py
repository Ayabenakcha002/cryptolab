import hashlib
import json

import pytest

from cryptolab.cli import PASSWORD_ENV, main


@pytest.fixture(autouse=True)
def password(monkeypatch):
    monkeypatch.setenv(PASSWORD_ENV, "correct horse battery staple")


def test_hash_matches_sha256sum_format(tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_bytes(b"abc")
    assert main(["hash", str(f)]) == 0
    assert capsys.readouterr().out == f"{hashlib.sha256(b'abc').hexdigest()}  {f}\n"


def test_hash_missing_file(capsys):
    assert main(["hash", "/no/such/file"]) == 1
    assert "cannot read" in capsys.readouterr().err


def test_password_encryption_round_trip(tmp_path):
    plain, enc, dec = tmp_path / "p", tmp_path / "p.enc", tmp_path / "p.out"
    plain.write_bytes(b"top secret " * 100)
    assert main(["encrypt", str(plain), "-o", str(enc)]) == 0
    blob = enc.read_bytes()
    assert b"top secret" not in blob and blob.startswith(b"CLAB1")
    assert main(["decrypt", str(enc), "-o", str(dec)]) == 0
    assert dec.read_bytes() == plain.read_bytes()


def test_encryption_is_randomised(tmp_path):
    plain = tmp_path / "p"
    plain.write_bytes(b"same")
    main(["encrypt", str(plain), "-o", str(tmp_path / "1")])
    main(["encrypt", str(plain), "-o", str(tmp_path / "2")])
    assert (tmp_path / "1").read_bytes() != (tmp_path / "2").read_bytes()


def test_wrong_password_and_tampering_are_detected(tmp_path, monkeypatch, capsys):
    plain, enc = tmp_path / "p", tmp_path / "p.enc"
    plain.write_bytes(b"data")
    main(["encrypt", str(plain), "-o", str(enc)])

    monkeypatch.setenv(PASSWORD_ENV, "wrong")
    assert main(["decrypt", str(enc), "-o", str(tmp_path / "x")]) == 1
    assert "wrong password or corrupted" in capsys.readouterr().err
    assert not (tmp_path / "x").exists()  # nothing is written on failure

    monkeypatch.setenv(PASSWORD_ENV, "correct horse battery staple")
    blob = bytearray(enc.read_bytes())
    blob[len(blob) // 2] ^= 1
    enc.write_bytes(bytes(blob))
    assert main(["decrypt", str(enc), "-o", str(tmp_path / "y")]) == 1


def test_decrypt_rejects_foreign_files(tmp_path, capsys):
    f = tmp_path / "junk"
    f.write_bytes(b"not an encrypted file at all, just text" * 3)
    assert main(["decrypt", str(f), "-o", str(tmp_path / "o")]) == 1
    assert "not a cryptolab" in capsys.readouterr().err


def test_refuses_to_overwrite_without_force(tmp_path, capsys):
    plain, out = tmp_path / "p", tmp_path / "out"
    plain.write_bytes(b"x")
    out.write_bytes(b"precious")
    assert main(["encrypt", str(plain), "-o", str(out)]) == 1
    assert out.read_bytes() == b"precious"
    assert main(["encrypt", str(plain), "-o", str(out), "--force"]) == 0
    assert out.read_bytes() != b"precious"


def test_rsa_workflow(tmp_path, capsys):
    key = tmp_path / "key"
    assert main(["rsa-keygen", "-b", "1024", "-o", str(key)]) == 0
    pub = str(key) + ".pub"
    assert json.loads((tmp_path / "key.pub").read_text())["type"] == "rsa-public"
    assert (key.stat().st_mode & 0o077) == 0 or __import__("os").name == "nt"  # private: 600

    msg, ct, out = tmp_path / "m", tmp_path / "ct", tmp_path / "out"
    msg.write_bytes(b"short secret")
    assert main(["rsa-encrypt", "-k", pub, str(msg), "-o", str(ct)]) == 0
    assert main(["rsa-decrypt", "-k", str(key), str(ct), "-o", str(out)]) == 0
    assert out.read_bytes() == b"short secret"

    sig = tmp_path / "sig"
    assert main(["rsa-sign", "-k", str(key), str(msg), "-o", str(sig)]) == 0
    assert main(["rsa-verify", "-k", pub, str(msg), str(sig)]) == 0
    assert "Signature OK" in capsys.readouterr().out
    msg.write_bytes(b"tampered")
    assert main(["rsa-verify", "-k", pub, str(msg), str(sig)]) == 1


def test_rsa_cli_errors(tmp_path, capsys):
    key = tmp_path / "key"
    main(["rsa-keygen", "-b", "1024", "-o", str(key)])
    big = tmp_path / "big"
    big.write_bytes(b"x" * 500)
    assert main(["rsa-encrypt", "-k", str(key) + ".pub", str(big), "-o", str(tmp_path / "o")]) == 1
    assert "too long" in capsys.readouterr().err
    # a public key cannot be used where a private key is required
    assert main(["rsa-decrypt", "-k", str(key) + ".pub", str(big), "-o", str(tmp_path / "o2")]) == 1
    assert main(["rsa-keygen", "-b", "512", "-o", str(tmp_path / "weak")]) == 2
    assert main(["rsa-keygen", "-b", "1024", "-o", str(key)]) == 1  # exists, no --force


def test_no_command_is_an_error():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2
