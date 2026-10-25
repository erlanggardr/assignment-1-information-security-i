import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Util.Padding import pad, unpad

CIPHERS = ("aes", "des", "rc4")

PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
TAG_SIZE = 32
RC4_DROP = 3072
_IV_SIZE = {"aes": 16, "des": 8, "rc4": 16}


class IntegrityError(Exception):
    pass


@dataclass(frozen=True)
class UserKeys:
    aes: bytes
    des: bytes
    rc4: bytes
    mac: bytes


def new_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def derive_user_keys(password: str, salt: bytes) -> UserKeys:
    m = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=88)
    return UserKeys(aes=m[0:32], des=m[32:40], rc4=m[40:56], mac=m[56:88])


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def encrypt(name: str, plaintext: bytes, keys: UserKeys, aad: bytes = b"") -> bytes:
    _check_name(name)
    iv = os.urandom(_IV_SIZE[name])
    ct = _encrypt_core(name, keys, iv, plaintext)
    return iv + _tag(keys, name, aad, iv, ct) + ct


def decrypt(name: str, blob: bytes, keys: UserKeys, aad: bytes = b"") -> bytes:
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


def encrypt_all(plaintext: bytes, keys: UserKeys, aad: bytes = b""):
    out = {}
    for name in CIPHERS:
        t0 = time.perf_counter_ns()
        blob = encrypt(name, plaintext, keys, aad)
        out[name] = EncryptResult(name, blob, time.perf_counter_ns() - t0, len(blob))
    return sha256_hex(plaintext), out


def decrypt_and_verify(name, blob, keys, expected_sha256, aad=b""):
    plain = decrypt(name, blob, keys, aad)
    if not hmac.compare_digest(sha256_hex(plain), expected_sha256):
        raise IntegrityError("plaintext SHA-256 mismatch")
    return plain
