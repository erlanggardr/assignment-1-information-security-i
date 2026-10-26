import hashlib
import os

from Crypto.Cipher import AES

from .crypto_engine import DEK_SIZE, IntegrityError

SALT_SIZE = 16
KEK_ITERATIONS = 200_000
MUK_SIZE = 32
_NONCE_SIZE = 12
_TAG_SIZE = 16


def new_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def derive_kek(password: str, salt: bytes, iterations: int = KEK_ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)


def _wrap(key: bytes, secret: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(_NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(secret)
    return nonce + tag + ct


def _unwrap(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < _NONCE_SIZE + _TAG_SIZE:
        raise IntegrityError("wrapped key too short")
    nonce = blob[:_NONCE_SIZE]
    tag = blob[_NONCE_SIZE : _NONCE_SIZE + _TAG_SIZE]
    ct = blob[_NONCE_SIZE + _TAG_SIZE :]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(ct, tag)
    except ValueError as exc:
        raise IntegrityError("wrapped key did not verify") from exc


def muk_aad(user_id) -> bytes:
    return b"vault-muk-v1|" + str(user_id).encode()


def record_aad(user_id, record_id, category: str = "") -> bytes:
    return "|".join(["vault-record-v1", str(user_id), str(record_id), category]).encode()


def new_user_key_material(password: str, user_id):
    salt = new_salt()
    muk = os.urandom(MUK_SIZE)
    wrapped = _wrap(derive_kek(password, salt), muk, muk_aad(user_id))
    return salt, wrapped, muk


def unlock_muk(password: str, kdf_salt: bytes, wrapped_muk: bytes, user_id, iterations: int = KEK_ITERATIONS) -> bytes:
    return _unwrap(derive_kek(password, kdf_salt, iterations), wrapped_muk, muk_aad(user_id))


def rewrap_muk(muk: bytes, new_password: str, user_id):
    salt = new_salt()
    return salt, _wrap(derive_kek(new_password, salt), muk, muk_aad(user_id))


def new_dek() -> bytes:
    return os.urandom(DEK_SIZE)


def wrap_dek(muk: bytes, dek: bytes, aad: bytes) -> bytes:
    return _wrap(muk, dek, aad)


def unwrap_dek(muk: bytes, wrapped_dek: bytes, aad: bytes) -> bytes:
    return _unwrap(muk, wrapped_dek, aad)
