import csv
import os
import platform
import statistics
import sys
import time

from . import crypto_engine as ce

DEFAULT_SIZES = {"1 KB": 1024, "1 MB": 1024**2, "5 MB": 5 * 1024**2, "20 MB": 20 * 1024**2}


def _median_ns(fn, runs):
    fn()
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        fn()
        samples.append(time.perf_counter_ns() - t0)
    return statistics.median(samples), (statistics.stdev(samples) if runs > 1 else 0.0)


def run_benchmark(sizes=None, runs=10):
    sizes = sizes or DEFAULT_SIZES
    keys = ce.derive_user_keys("benchmark-password", os.urandom(ce.SALT_SIZE))
    rows = []
    for label, n in sizes.items():
        data = os.urandom(n)
        for name in ce.CIPHERS:
            blob = ce.encrypt(name, data, keys)
            enc, enc_sd = _median_ns(lambda: ce.encrypt(name, data, keys), runs)
            dec, dec_sd = _median_ns(lambda: ce.decrypt(name, blob, keys), runs)
            mb = n / 1024**2
            rows.append(
                {
                    "size": label,
                    "bytes": n,
                    "cipher": name,
                    "enc_ms": enc / 1e6,
                    "enc_sd_ms": enc_sd / 1e6,
                    "dec_ms": dec / 1e6,
                    "dec_sd_ms": dec_sd / 1e6,
                    "enc_mb_s": mb / (enc / 1e9),
                    "dec_mb_s": mb / (dec / 1e9),
                    "cipher_bytes": len(blob),
                    "expansion": len(blob) / n,
                }
            )
    return rows


def environment():
    from Crypto import __version__ as pcd

    return f"Python {platform.python_version()}, pycryptodome {pcd}, {platform.machine()}, {os.cpu_count()} CPUs"


if __name__ == "__main__":
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    rows = run_benchmark(runs=runs)
    print(environment(), f"| median of {runs} runs")
    print(f"{'size':>6} {'cipher':>6} {'enc ms':>9} {'dec ms':>9} {'enc MB/s':>9} {'dec MB/s':>9} {'cipher B':>10}")
    for r in rows:
        print(f"{r['size']:>6} {r['cipher']:>6} {r['enc_ms']:9.3f} {r['dec_ms']:9.3f} "
              f"{r['enc_mb_s']:9.1f} {r['dec_mb_s']:9.1f} {r['cipher_bytes']:10d}")
    with open("bench_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
