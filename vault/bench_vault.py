import math
import operator
import os
import statistics
from collections import Counter

from . import crypto_engine as ce
from . import storage

SAMPLES = {
    "repeated text": (b'{"name":"Budi Santoso","nik":"3174010101900001","income":8500000}\n' * 4000),
    "random bytes": os.urandom(256 * 1024),
}


def entropy(data: bytes) -> float:
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def run_item_downloads(user, muk, downloads=10):
    med = statistics.median
    rows = []
    for entry in storage.list_entries(user, muk):
        for cipher in ce.CIPHERS:
            storage.load_object(user, muk, entry["id"], cipher)
            runs = [storage.load_object(user, muk, entry["id"], cipher) for _ in range(downloads)]
            totals = [r.total_ns for r in runs]
            total_ms = med(totals) / 1e6
            rows.append(
                {
                    "item": entry["label"],
                    "bytes": entry["size"],
                    "kb": entry["size"] / 1024,
                    "cipher": cipher,
                    "downloads": downloads,
                    "io_ms": med(r.io_ns for r in runs) / 1e6,
                    "key_ms": med(r.unwrap_ns for r in runs) / 1e6,
                    "decrypt_ms": med(r.decrypt_ns for r in runs) / 1e6,
                    "verify_ms": med(r.verify_ns for r in runs) / 1e6,
                    "total_ms": total_ms,
                    "total_sd_ms": (statistics.stdev(totals) if downloads > 1 else 0.0) / 1e6,
                    "mb_s": entry["size"] / 1024**2 / (total_ms / 1e3),
                }
            )
    return rows


def compare_ciphertexts(samples=None):
    keys = ce.cipher_keys_from_dek(os.urandom(ce.DEK_SIZE))
    rows = []
    for label, data in (samples or SAMPLES).items():
        for cipher in ce.CIPHERS:
            first = ce.encrypt(cipher, data, keys)
            second = ce.encrypt(cipher, data, keys)
            rows.append(
                {
                    "sample": label,
                    "cipher": cipher,
                    "plain_bytes": len(data),
                    "cipher_bytes": len(first),
                    "overhead": len(first) - len(data),
                    "plain_entropy": entropy(data),
                    "cipher_entropy": entropy(first),
                    "same_output": first == second,
                    "equal_pct": 100 * sum(map(operator.eq, first, second)) / len(first),
                }
            )
    return rows
