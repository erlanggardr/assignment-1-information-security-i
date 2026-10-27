from unittest import TestCase

from vault import bench
from vault import crypto_engine as ce


class DownloadBenchmarkTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.rows = bench.run_download_benchmark({"1 KB": 1024, "64 KB": 64 * 1024}, downloads=3)

    def test_one_row_per_cipher_and_size(self):
        self.assertEqual(len(self.rows), 2 * len(ce.CIPHERS))
        self.assertEqual({r["cipher"] for r in self.rows}, set(ce.CIPHERS))
        self.assertTrue(all(r["downloads"] == 3 for r in self.rows))

    def test_times_are_positive_and_consistent(self):
        for r in self.rows:
            with self.subTest(cipher=r["cipher"], size=r["size"]):
                self.assertGreater(r["decrypt_ms"], 0)
                self.assertGreater(r["total_ms"], 0)
                self.assertAlmostEqual(r["crypto_ms"], r["key_ms"] + r["decrypt_ms"] + r["verify_ms"], delta=r["crypto_ms"])
                self.assertLessEqual(r["crypto_ms"], r["total_ms"] * 1.05)
                self.assertGreater(r["crypto_mb_s"], 0)

    def test_single_download_has_zero_spread(self):
        row = bench.run_download_benchmark({"1 KB": 1024}, downloads=1)[0]
        self.assertEqual(row["total_sd_ms"], 0.0)


class CipherBenchmarkTests(TestCase):
    def test_rows_cover_every_cipher_with_expected_expansion(self):
        rows = bench.run_benchmark({"4 KB": 4096}, runs=2)
        self.assertEqual({r["cipher"] for r in rows}, set(ce.CIPHERS))
        by = {r["cipher"]: r for r in rows}
        self.assertEqual(by["aes"]["cipher_bytes"], 4096 + 16 + 32 + 16)
        self.assertEqual(by["des"]["cipher_bytes"], 4096 + 8 + 32 + 8)
        self.assertEqual(by["rc4"]["cipher_bytes"], 4096 + 16 + 32)
