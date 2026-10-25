import io
import os

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse


# The starter serves static files through a WhiteNoise manifest that only exists
# after `collectstatic`; tests run with DEBUG off, so use plain storage instead.
@override_settings(
    STORAGES={
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }
)
class VaultViewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user("borrower1", password="Str0ng-pass-123")

    def test_pages_require_login(self):
        for name in ("vault_demo", "vault_benchmark"):
            resp = self.client.get(reverse(name))
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/accounts/login/", resp["Location"])

    def test_pages_load_when_logged_in(self):
        self.client.force_login(self.user)
        for name in ("vault_demo", "vault_benchmark"):
            self.assertEqual(self.client.get(reverse(name)).status_code, 200)

    def test_demo_encrypts_a_file_with_all_three_ciphers(self):
        self.client.force_login(self.user)
        resp = self.client.post(
            reverse("vault_demo"),
            {"password": "pw", "file": io.BytesIO(os.urandom(5000))},
        )
        html = resp.content.decode()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(html.count("intact"), 3)
        self.assertNotIn("FAILED", html)

    def test_demo_rejects_missing_password_or_data(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.post(reverse("vault_demo"), {"text": "x"}).status_code, 400)
        self.assertEqual(self.client.post(reverse("vault_demo"), {"password": "pw"}).status_code, 400)

    def test_benchmark_reports_all_ciphers(self):
        self.client.force_login(self.user)
        resp = self.client.post(reverse("vault_benchmark"), {"sizes": ["1 KB"], "runs": "2"})
        html = resp.content.decode()
        self.assertEqual(resp.status_code, 200)
        for name in ("AES", "DES", "RC4"):
            self.assertIn(name, html)
