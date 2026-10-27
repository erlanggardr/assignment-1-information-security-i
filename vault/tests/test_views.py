import io
import os

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from vault.keyring import keyring
from vault.tests.support import login, new_client, no_manifest, signup

PASSWORD = "Str0ng-pass-123"


@no_manifest
class VaultViewTests(TestCase):
    def setUp(self):
        keyring.clear()
        self.client = new_client()
        signup(self.client, "borrower1", PASSWORD)

    def test_pages_require_login(self):
        anon = new_client()
        for name in ("vault_demo", "vault_benchmark"):
            resp = anon.get(reverse(name))
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/accounts/login/", resp["Location"])

    def test_pages_load_when_unlocked(self):
        for name in ("vault_demo", "vault_benchmark"):
            self.assertEqual(self.client.get(reverse(name)).status_code, 200)

    def test_locked_session_is_signed_out_and_sent_to_login(self):
        keyring.clear()
        resp = self.client.get(reverse("vault_demo"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/accounts/login/", resp["Location"])
        self.assertNotIn("_auth_user_id", self.client.session)
        login(self.client, "borrower1", PASSWORD)
        self.assertEqual(self.client.get(reverse("vault_demo")).status_code, 200)

    def test_demo_seals_a_file_with_all_three_ciphers(self):
        resp = self.client.post(reverse("vault_demo"), {"file": io.BytesIO(os.urandom(5000))})
        html = resp.content.decode()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(html.count(">intact<"), 3)
        self.assertNotIn("FAILED", html)

    def test_demo_rejects_missing_data(self):
        self.assertEqual(self.client.post(reverse("vault_demo"), {}).status_code, 400)

    def test_benchmark_reports_all_ciphers(self):
        resp = self.client.post(reverse("vault_benchmark"), {"sizes": ["1 KB"], "runs": "2"})
        html = resp.content.decode()
        self.assertEqual(resp.status_code, 200)
        for name in ("AES", "DES", "RC4"):
            self.assertIn(name, html)

    def test_download_benchmark_reports_crypto_and_total_time(self):
        resp = self.client.post(
            reverse("vault_benchmark"), {"kind": "download", "sizes": ["1 KB"], "downloads": "3"}
        )
        html = resp.content.decode()
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Download results", html)
        for name in ("AES", "DES", "RC4"):
            self.assertIn(name, html)
        self.assertIn("Total ms", html)

    def test_benchmark_ignores_garbage_counts(self):
        resp = self.client.post(reverse("vault_benchmark"), {"kind": "download", "sizes": ["1 KB"], "downloads": "lots"})
        self.assertEqual(resp.status_code, 200)
