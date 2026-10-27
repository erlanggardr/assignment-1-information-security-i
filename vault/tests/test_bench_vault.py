import os
import shutil
import tempfile
from io import StringIO

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse

from vault import bench_vault, keys, storage
from vault import crypto_engine as ce
from vault.keyring import keyring
from vault.tests.support import new_client, no_manifest, signup

PNG = b"\x89PNG\r\n\x1a\n" + os.urandom(20000)


class MediaCase(TestCase):
    def setUp(self):
        self.media = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.media, ignore_errors=True)
        override = override_settings(MEDIA_ROOT=self.media)
        override.enable()
        self.addCleanup(override.disable)


class ItemDownloadTests(MediaCase):
    def setUp(self):
        super().setUp()
        self.user = get_user_model().objects.create_user("alice", password="x")
        self.muk = os.urandom(keys.MUK_SIZE)
        storage.store_file(self.user, self.muk, storage.ID_CARD, "ktp.png", PNG)
        storage.store_profile(self.user, self.muk, {"full_name": "Budi"})

    def test_one_row_per_item_and_cipher(self):
        rows = bench_vault.run_item_downloads(self.user, self.muk, downloads=3)
        self.assertEqual(len(rows), 2 * len(ce.CIPHERS))
        self.assertEqual({r["cipher"] for r in rows}, set(ce.CIPHERS))
        self.assertTrue(all(r["downloads"] == 3 for r in rows))

    def test_stage_times_add_up_to_the_total(self):
        for r in bench_vault.run_item_downloads(self.user, self.muk, downloads=3):
            parts = r["io_ms"] + r["key_ms"] + r["decrypt_ms"] + r["verify_ms"]
            self.assertAlmostEqual(parts, r["total_ms"], delta=r["total_ms"] * 0.5)
            self.assertGreater(r["mb_s"], 0)

    def test_nothing_to_measure_for_a_user_without_items(self):
        other = get_user_model().objects.create_user("bob", password="x")
        self.assertEqual(bench_vault.run_item_downloads(other, self.muk, downloads=2), [])

    def test_single_download_has_no_spread(self):
        rows = bench_vault.run_item_downloads(self.user, self.muk, downloads=1)
        self.assertTrue(all(r["total_sd_ms"] == 0 for r in rows))


class CiphertextTests(TestCase):
    def test_same_plaintext_never_gives_the_same_ciphertext(self):
        rows = bench_vault.compare_ciphertexts({"x": b"A" * 5000})
        self.assertEqual(len(rows), len(ce.CIPHERS))
        for r in rows:
            self.assertFalse(r["same_output"], r["cipher"])
            self.assertLess(r["equal_pct"], 5)

    def test_ciphertext_looks_random_even_for_repetitive_plaintext(self):
        for r in bench_vault.compare_ciphertexts({"x": b"AB" * 50000}):
            self.assertLess(r["plain_entropy"], 1.1)
            self.assertGreater(r["cipher_entropy"], 7.99)

    def test_overhead_matches_the_envelope_layout(self):
        expected = {"aes": 64, "des": 48, "rc4": 48}
        for r in bench_vault.compare_ciphertexts({"x": b"\x00" * 4096}):
            self.assertEqual(r["overhead"], expected[r["cipher"]])

    def test_entropy_bounds(self):
        self.assertEqual(bench_vault.entropy(b"aaaa"), 0)
        self.assertAlmostEqual(bench_vault.entropy(bytes(range(256))), 8.0)


@no_manifest
class BenchmarkPageTests(MediaCase):
    def setUp(self):
        super().setUp()
        keyring.clear()
        self.client = new_client()
        signup(self.client, "alice", "Str0ng-pass-123")

    def test_items_benchmark_without_items_says_so(self):
        resp = self.client.post(reverse("vault_benchmark"), {"kind": "items", "downloads": "2"})
        self.assertContains(resp, "nothing stored yet")

    def test_items_benchmark_uses_the_logged_in_users_items(self):
        self.client.post(reverse("vault_upload", args=["id-card"]), {"file": SimpleUploadedFile("ktp.png", PNG)})
        resp = self.client.post(reverse("vault_benchmark"), {"kind": "items", "downloads": "2"})
        html = resp.content.decode()
        self.assertContains(resp, "ID card image")
        for name in ("AES", "DES", "RC4"):
            self.assertIn(name, html)

    def test_other_users_items_are_not_measured(self):
        bob = new_client()
        signup(bob, "bob", "Str0ng-pass-123")
        bob.post(reverse("vault_upload", args=["id-card"]), {"file": SimpleUploadedFile("ktp.png", PNG)})
        resp = self.client.post(reverse("vault_benchmark"), {"kind": "items", "downloads": "2"})
        self.assertNotContains(resp, "ID card image")

    def test_analysis_page(self):
        resp = self.client.post(reverse("vault_benchmark"), {"kind": "analysis"})
        self.assertContains(resp, "Ciphertext comparison")
        self.assertContains(resp, "repeated text")


class CommandTests(TestCase):
    def test_command_writes_csv_and_leaves_nothing_behind(self):
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        buf = StringIO()
        call_command("benchmark_vault", downloads=2, video_mb=1, out=out, stdout=buf)
        self.assertTrue(os.path.exists(os.path.join(out, "downloads.csv")))
        self.assertTrue(os.path.exists(os.path.join(out, "ciphertext.csv")))
        self.assertIn("DES", buf.getvalue().upper())
        self.assertFalse(get_user_model().objects.filter(username="bench_tmp").exists())
