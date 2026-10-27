import io
import os
import re
import shutil
import tempfile

from django.test import TestCase, override_settings
from django.urls import reverse

from vault import storage
from vault.keyring import keyring
from vault.models import StoredObject
from vault.tests.support import login, new_client, no_manifest, signup

PASSWORD = "Str0ng-pass-123"
PNG = b"\x89PNG\r\n\x1a\n" + os.urandom(4000)
PDF = b"%PDF-1.7\n" + os.urandom(3000)
PROFILE_POST = {
    "full_name": "Budi Santoso",
    "nik": "3174010101900001",
    "mother_maiden_name": "Siti",
    "date_of_birth": "1990-01-01",
    "address": "Jl. Merdeka 1, Jakarta",
    "bank_account": "1234567890",
    "net_worth": "250000000",
}


def upload_file(name, data):
    f = io.BytesIO(data)
    f.name = name
    return f


@no_manifest
class PageBase(TestCase):
    def setUp(self):
        keyring.clear()
        self.media = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.media, ignore_errors=True)
        override = override_settings(MEDIA_ROOT=self.media)
        override.enable()
        self.addCleanup(override.disable)
        self.client = new_client()
        signup(self.client, "alice", PASSWORD)

    def put(self, slug, name, data, client=None):
        return (client or self.client).post(reverse("vault_upload", args=[slug]), {"file": upload_file(name, data)})

    def first_id(self, category):
        return StoredObject.objects.filter(category=category).first().id


class AccessTests(PageBase):
    def test_pages_require_login(self):
        anon = new_client()
        oid = "00000000-0000-0000-0000-000000000001"
        urls = [
            reverse("vault_dashboard"),
            reverse("vault_profile"),
            reverse("vault_upload", args=["id-card"]),
            reverse("vault_download", args=[oid]),
        ]
        for url in urls:
            resp = anon.get(url)
            self.assertEqual(resp.status_code, 302, url)
            self.assertIn("/accounts/login/", resp["Location"])
        self.assertEqual(anon.post(reverse("vault_delete", args=[oid])).status_code, 302)

    def test_locked_session_cannot_download(self):
        self.put("id-card", "ktp.png", PNG)
        oid = self.first_id(storage.ID_CARD)
        keyring.clear()
        resp = self.client.get(reverse("vault_download", args=[oid]))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/accounts/login/", resp["Location"])

    def test_login_lands_on_the_dashboard(self):
        c = new_client()
        resp = login(c, "alice", PASSWORD)
        self.assertEqual(resp["Location"], reverse("vault_dashboard"))

    def test_unknown_upload_slug_is_404(self):
        self.assertEqual(self.client.get(reverse("vault_upload", args=["nope"])).status_code, 404)


class UploadDownloadTests(PageBase):
    def test_id_card_upload_and_download_are_identical_for_every_cipher(self):
        resp = self.put("id-card", "ktp.png", PNG)
        self.assertRedirects(resp, reverse("vault_dashboard"), fetch_redirect_response=False)
        oid = self.first_id(storage.ID_CARD)
        for cipher in ("aes", "des", "rc4"):
            resp = self.client.get(reverse("vault_download", args=[oid]), {"cipher": cipher})
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.content, PNG)
            self.assertEqual(resp["Content-Type"], "image/png")
            self.assertIn("attachment", resp["Content-Disposition"])
            self.assertIn("ktp.png", resp["Content-Disposition"])
            self.assertEqual(resp["X-Content-Type-Options"], "nosniff")
            self.assertIn("decrypt;dur=", resp["Server-Timing"])

    def test_office_document_round_trip(self):
        self.put("office", "slip gaji.pdf", PDF)
        resp = self.client.get(reverse("vault_download", args=[self.first_id(storage.OFFICE)]))
        self.assertEqual(resp.content, PDF)

    def test_video_round_trip_through_disk(self):
        video = b"\x00\x00\x00\x18ftypmp42" + os.urandom(storage.INLINE_LIMIT * 2)
        self.put("video", "live.mp4", video)
        oid = self.first_id(storage.VIDEO)
        for cipher in ("aes", "des", "rc4"):
            self.assertEqual(self.client.get(reverse("vault_download", args=[oid]), {"cipher": cipher}).content, video)

    def test_dashboard_lists_names_decrypted(self):
        self.put("id-card", "ktp.png", PNG)
        html = self.client.get(reverse("vault_dashboard")).content.decode()
        self.assertIn("ktp.png", html)
        for cipher in ("aes", "des", "rc4"):
            self.assertIn(f"cipher={cipher}", html)

    def test_rejected_uploads_show_an_error_and_store_nothing(self):
        for slug, name, data in [
            ("id-card", "ktp.exe", b"MZ\x00\x00"),
            ("id-card", "ktp.png", b"plain text"),
            ("video", "x.mp4", b""),
        ]:
            resp = self.put(slug, name, data)
            self.assertEqual(resp.status_code, 400, (slug, name))
        self.assertEqual(StoredObject.objects.count(), 0)

    def test_missing_file_is_rejected(self):
        resp = self.client.post(reverse("vault_upload", args=["office"]), {})
        self.assertEqual(resp.status_code, 400)

    def test_unknown_cipher_is_a_bad_request(self):
        self.put("id-card", "ktp.png", PNG)
        resp = self.client.get(reverse("vault_download", args=[self.first_id(storage.ID_CARD)]), {"cipher": "rot13"})
        self.assertEqual(resp.status_code, 400)

    def test_corrupted_copy_returns_409_and_other_cipher_still_works(self):
        self.put("id-card", "ktp.png", PNG)
        obj = StoredObject.objects.get()
        blob = bytearray(obj.des_inline)
        blob[-1] ^= 1
        StoredObject.objects.filter(pk=obj.pk).update(des_inline=bytes(blob))
        url = reverse("vault_download", args=[obj.id])
        resp = self.client.get(url, {"cipher": "des"})
        self.assertEqual(resp.status_code, 409)
        self.assertNotIn(PNG[10:40], resp.content)
        self.assertEqual(self.client.get(url, {"cipher": "aes"}).content, PNG)


class PrivacyTests(PageBase):
    def setUp(self):
        super().setUp()
        self.put("id-card", "ktp.png", PNG)
        self.oid = self.first_id(storage.ID_CARD)
        self.bob = new_client()
        signup(self.bob, "bob", PASSWORD)

    def test_other_user_gets_404_on_download_and_delete(self):
        url = reverse("vault_download", args=[self.oid])
        self.assertEqual(self.bob.get(url).status_code, 404)
        self.assertEqual(self.bob.post(reverse("vault_delete", args=[self.oid])).status_code, 404)
        self.assertEqual(self.client.get(url).content, PNG)

    def test_other_user_does_not_see_the_item_in_the_dashboard(self):
        self.assertNotIn("ktp.png", self.bob.get(reverse("vault_dashboard")).content.decode())

    def test_delete_requires_post(self):
        self.assertEqual(self.client.get(reverse("vault_delete", args=[self.oid])).status_code, 405)
        self.assertEqual(StoredObject.objects.count(), 1)

    def test_owner_can_delete(self):
        resp = self.client.post(reverse("vault_delete", args=[self.oid]))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(StoredObject.objects.count(), 0)
        self.assertEqual(self.client.get(reverse("vault_download", args=[self.oid])).status_code, 404)

    def test_data_survives_logout_and_login(self):
        c = new_client()
        login(c, "alice", PASSWORD)
        self.assertEqual(c.get(reverse("vault_download", args=[self.oid])).content, PNG)


class ProfileTests(PageBase):
    def test_form_page_loads_empty(self):
        resp = self.client.get(reverse("vault_profile"))
        self.assertEqual(resp.status_code, 200)

    def test_save_then_reload_shows_decrypted_values(self):
        resp = self.client.post(reverse("vault_profile"), PROFILE_POST)
        self.assertRedirects(resp, reverse("vault_dashboard"), fetch_redirect_response=False)
        html = self.client.get(reverse("vault_profile")).content.decode()
        self.assertIn("Budi Santoso", html)
        self.assertIn("3174010101900001", html)

    def test_invalid_input_is_rejected(self):
        for field, bad in [("nik", "123"), ("nik", "31740101019000ab"), ("net_worth", "-5"), ("bank_account", "abc")]:
            resp = self.client.post(reverse("vault_profile"), {**PROFILE_POST, field: bad})
            self.assertEqual(resp.status_code, 400, (field, bad))
        self.assertEqual(StoredObject.objects.count(), 0)

    def test_profile_is_private_to_its_owner(self):
        self.client.post(reverse("vault_profile"), PROFILE_POST)
        bob = new_client()
        signup(bob, "bob", PASSWORD)
        self.assertNotIn("Budi Santoso", bob.get(reverse("vault_profile")).content.decode())
        self.assertNotIn("Budi", bob.get(reverse("vault_dashboard")).content.decode())

    def test_resaving_keeps_one_profile(self):
        self.client.post(reverse("vault_profile"), PROFILE_POST)
        self.client.post(reverse("vault_profile"), {**PROFILE_POST, "full_name": "Budi Baru"})
        self.assertEqual(StoredObject.objects.filter(category=storage.PROFILE).count(), 1)
        self.assertIn("Budi Baru", self.client.get(reverse("vault_profile")).content.decode())

    def test_password_change_keeps_data_readable(self):
        self.client.post(reverse("vault_profile"), PROFILE_POST)
        self.put("id-card", "ktp.png", PNG)
        new_password = "An0ther-pass-456"
        self.client.post(
            reverse("account_change_password"),
            {"oldpassword": PASSWORD, "password1": new_password, "password2": new_password},
        )
        c = new_client()
        login(c, "alice", new_password)
        self.assertIn("Budi Santoso", c.get(reverse("vault_profile")).content.decode())
        oid = self.first_id(storage.ID_CARD)
        self.assertEqual(c.get(reverse("vault_download", args=[oid])).content, PNG)
