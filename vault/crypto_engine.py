import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import pad, unpad

CIPHERS = ("aes", "des", "rc4")

TAG_SIZE = 32
DEK_SIZE = 32
RC4_DROP = 3072
_IV_SIZE = {"aes": 16, "des": 8, "rc4": 16}
_HKDF_CONTEXT = b"vault-cipher-keys-v1"


class IntegrityError(Exception):
    pass


@dataclass(frozen=True)
class CipherKeys:
    aes: bytes
    des: bytes
    rc4: bytes
    mac: bytes


def cipher_keys_from_dek(dek: bytes) -> CipherKeys:
    if len(dek) != DEK_SIZE:
        raise ValueError(f"data key must be {DEK_SIZE} bytes, got {len(dek)}")
    m = HKDF(dek, 88, b"", SHA256, context=_HKDF_CONTEXT)
    return CipherKeys(aes=m[0:32], des=m[32:40], rc4=m[40:56], mac=m[56:88])


def keyed_digest(keys: CipherKeys, plaintext: bytes, aad: bytes = b"") -> bytes:
    mac = hmac.new(keys.mac, digestmod=hashlib.sha256)
    mac.update(b"plaintext-digest|" + struct.pack(">Q", len(aad)) + aad + plaintext)
    return mac.digest()


def _tag(keys, name, aad, iv, ct):
    mac = hmac.new(keys.mac, digestmod=hashlib.sha256)
    mac.update(name.encode() + b"|" + struct.pack(">Q", len(aad)) + aad + iv + ct)
    return mac.digest()


def _rc4_session_key(keys, nonce):
    return hmac.new(keys.rc4, nonce, hashlib.sha256).digest()[:16]


def _encrypt_core(name, keys, iv, plaintext):
    if name == "aes":
        return AES.new(keys.aes, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
    if name == "des":
        return DES.new(keys.des, DES.MODE_CBC, iv).encrypt(pad(plaintext, 8))
    return ARC4.new(_rc4_session_key(keys, iv), drop=RC4_DROP).encrypt(plaintext)


def _decrypt_core(name, keys, iv, ct):
    if name == "aes":
        return unpad(AES.new(keys.aes, AES.MODE_CBC, iv).decrypt(ct), 16)
    if name == "des":
        return unpad(DES.new(keys.des, DES.MODE_CBC, iv).decrypt(ct), 8)
    return ARC4.new(_rc4_session_key(keys, iv), drop=RC4_DROP).decrypt(ct)


def _check_name(name):
    if name not in CIPHERS:
        raise ValueError(f"unknown cipher {name!r}, expected one of {CIPHERS}")


def encrypt(name: str, plaintext: bytes, keys: CipherKeys, aad: bytes = b"") -> bytes:
    _check_name(name)
    iv = os.urandom(_IV_SIZE[name])
    ct = _encrypt_core(name, keys, iv, plaintext)
    return iv + _tag(keys, name, aad, iv, ct) + ct


def decrypt(name: str, blob: bytes, keys: CipherKeys, aad: bytes = b"") -> bytes:
    _check_name(name)
    n = _IV_SIZE[name]
    if len(blob) < n + TAG_SIZE:
        raise IntegrityError("blob too short")
    iv, tag, ct = blob[:n], blob[n : n + TAG_SIZE], blob[n + TAG_SIZE :]
    if not hmac.compare_digest(tag, _tag(keys, name, aad, iv, ct)):
        raise IntegrityError("authentication tag mismatch")
    try:
        return _decrypt_core(name, keys, iv, ct)
    except ValueError as exc:
        raise IntegrityError("corrupted ciphertext") from exc


@dataclass(frozen=True)
class EncryptResult:
    cipher: str
    blob: bytes
    encrypt_ns: int
    size: int


def encrypt_all(plaintext: bytes, keys: CipherKeys, aad: bytes = b""):
    out = {}
    for name in CIPHERS:
        t0 = time.perf_counter_ns()
        blob = encrypt(name, plaintext, keys, aad)
        out[name] = EncryptResult(name, blob, time.perf_counter_ns() - t0, len(blob))
    return keyed_digest(keys, plaintext, aad), out


def decrypt_and_verify(name, blob, keys, expected_digest: bytes, aad: bytes = b"") -> bytes:
    plain = decrypt(name, blob, keys, aad)
    if not hmac.compare_digest(keyed_digest(keys, plain, aad), expected_digest):
        raise IntegrityError("plaintext digest mismatch")
    return plain
