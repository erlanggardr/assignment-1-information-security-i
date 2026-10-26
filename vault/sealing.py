import hmac
import json
import time
from dataclasses import dataclass

from . import crypto_engine as ce
from . import keys


@dataclass(frozen=True)
class SealedObject:
    wrapped_dek: bytes
    digest: bytes
    blobs: dict
    plaintext_size: int
    encrypt_ns: dict


@dataclass(frozen=True)
class OpenResult:
    plaintext: bytes
    unwrap_ns: int
    decrypt_ns: int
    verify_ns: int

    @property
    def crypto_ns(self) -> int:
        return self.unwrap_ns + self.decrypt_ns + self.verify_ns


def seal(plaintext: bytes, muk: bytes, aad: bytes) -> SealedObject:
    dek = keys.new_dek()
    cipher_keys = ce.cipher_keys_from_dek(dek)
    digest, results = ce.encrypt_all(plaintext, cipher_keys, aad)
    return SealedObject(
        wrapped_dek=keys.wrap_dek(muk, dek, aad),
        digest=digest,
        blobs={name: res.blob for name, res in results.items()},
        plaintext_size=len(plaintext),
        encrypt_ns={name: res.encrypt_ns for name, res in results.items()},
    )


def open_one(cipher: str, blob: bytes, wrapped_dek: bytes, digest: bytes, muk: bytes, aad: bytes) -> OpenResult:
    t0 = time.perf_counter_ns()
    cipher_keys = ce.cipher_keys_from_dek(keys.unwrap_dek(muk, wrapped_dek, aad))
    t1 = time.perf_counter_ns()
    plaintext = ce.decrypt(cipher, blob, cipher_keys, aad)
    t2 = time.perf_counter_ns()
    if not hmac.compare_digest(ce.keyed_digest(cipher_keys, plaintext, aad), digest):
        raise ce.IntegrityError("plaintext digest mismatch")
    t3 = time.perf_counter_ns()
    return OpenResult(plaintext, t1 - t0, t2 - t1, t3 - t2)


def open_sealed(sealed: SealedObject, cipher: str, muk: bytes, aad: bytes) -> OpenResult:
    return open_one(cipher, sealed.blobs[cipher], sealed.wrapped_dek, sealed.digest, muk, aad)


def dump_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def seal_json(data: dict, muk: bytes, aad: bytes) -> SealedObject:
    return seal(dump_json(data), muk, aad)


def load_json(result: OpenResult) -> dict:
    return json.loads(result.plaintext.decode("utf-8"))
