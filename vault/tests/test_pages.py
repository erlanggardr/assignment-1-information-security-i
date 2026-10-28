import importlib.util
import io
import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

from django.test import TestCase, override_settings
from django.urls import reverse

from vault import liveness as live
from vault import storage, views
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


@override_settings(LIVENESS_ENGINE="off")
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


class OnboardingTests(PageBase):
    def html(self):
        return self.client.get(reverse("vault_dashboard")).content.decode()

    def test_new_customer_sees_four_steps_all_pending(self):
        ctx = self.client.get(reverse("vault_dashboard")).context
        self.assertEqual(ctx["done"], 0)
        self.assertEqual(ctx["total"], 4)
        self.assertEqual([s["title"] for s in ctx["steps"]], [
            "Personal details", "ID card (e-KTP)", "Proof of income", "Liveness video",
        ])
        self.assertFalse(any(s["done"] for s in ctx["steps"]))

    def test_progress_follows_what_is_stored(self):
        self.client.post(reverse("vault_profile"), PROFILE_POST)
        self.put("id-card", "ktp.png", PNG)
        ctx = self.client.get(reverse("vault_dashboard")).context
        self.assertEqual((ctx["done"], ctx["percent"], ctx["complete"]), (2, 50, False))

    def test_all_steps_complete(self):
        video = b"\x00\x00\x00\x18ftypmp42" + os.urandom(2000)
        self.client.post(reverse("vault_profile"), PROFILE_POST)
        self.put("id-card", "ktp.png", PNG)
        self.put("office", "slip.pdf", PDF)
        self.put("video", "live.mp4", video)
        ctx = self.client.get(reverse("vault_dashboard")).context
        self.assertEqual((ctx["done"], ctx["percent"], ctx["complete"]), (4, 100, True))

    def test_progress_is_per_customer(self):
        self.put("id-card", "ktp.png", PNG)
        bob = new_client()
        signup(bob, "bob", PASSWORD)
        self.assertEqual(bob.get(reverse("vault_dashboard")).context["done"], 0)

    def test_deleting_an_item_reopens_its_step(self):
        self.put("id-card", "ktp.png", PNG)
        self.client.post(reverse("vault_delete", args=[self.first_id(storage.ID_CARD)]))
        self.assertEqual(self.client.get(reverse("vault_dashboard")).context["done"], 0)

    def test_step_pages_explain_why_and_the_type_of_data(self):
        for slug, text in (("id-card", "Biometric"), ("office", "financial"), ("video", "Biometric")):
            html = self.client.get(reverse("vault_upload", args=[slug])).content.decode()
            self.assertIn("Why we ask", html)
            self.assertIn("Type of data", html)
            self.assertIn(text, html)
        self.assertIn("Why we ask", self.client.get(reverse("vault_profile")).content.decode())

    def test_pages_do_not_cite_regulations(self):
        urls = [reverse("home"), reverse("vault_dashboard"), reverse("vault_profile"), reverse("vault_upload", args=["video"])]
        for url in urls:
            html = self.client.get(url).content.decode()
            for name in ("UU PDP", "GDPR"):
                self.assertNotIn(name, html, url)


class LoanTests(PageBase):
    video = b"\x00\x00\x00\x18ftypmp42" + os.urandom(2000)

    def finish_kyc(self, client=None):
        c = client or self.client
        c.post(reverse("vault_profile"), PROFILE_POST)
        self.put("id-card", "ktp.png", PNG, client=c)
        self.put("office", "slip.pdf", PDF, client=c)
        self.put("video", "live.mp4", self.video, client=c)

    def ask(self, amount="2000000", purpose="daily", client=None):
        return (client or self.client).post(reverse("vault_loan"), {"amount": amount, "purpose": purpose})

    def loans(self):
        return StoredObject.objects.filter(category=storage.LOAN)

    def test_loan_is_locked_until_kyc_is_complete(self):
        self.assertRedirects(self.client.get(reverse("vault_loan")), reverse("vault_dashboard"), fetch_redirect_response=False)
        self.ask()
        self.assertEqual(self.loans().count(), 0)

    def test_each_missing_step_keeps_the_loan_locked(self):
        uploads = [("id-card", "ktp.png", PNG), ("office", "slip.pdf", PDF), ("video", "live.mp4", self.video)]
        for skip in range(4):
            c = new_client()
            signup(c, f"user{skip}", PASSWORD)
            if skip != 0:
                c.post(reverse("vault_profile"), PROFILE_POST)
            for i, (slug, name, data) in enumerate(uploads, start=1):
                if i != skip:
                    self.put(slug, name, data, client=c)
            self.ask(client=c)
        self.assertEqual(self.loans().count(), 0)

    def test_request_after_kyc_is_stored_and_shown(self):
        self.finish_kyc()
        resp = self.ask("3500000", "education")
        self.assertRedirects(resp, reverse("vault_dashboard"), fetch_redirect_response=False)
        html = self.client.get(reverse("vault_dashboard")).content.decode()
        self.assertIn("3,500,000", html)
        self.assertIn("education", html)
        self.assertEqual(self.loans().count(), 1)

    def test_loan_is_encrypted_like_everything_else(self):
        self.finish_kyc()
        self.ask("3500000", "education")
        obj = self.loans().get()
        for cipher in ("aes", "des", "rc4"):
            self.assertNotIn(b"3500000", bytes(getattr(obj, f"{cipher}_inline")))
            resp = self.client.get(reverse("vault_download", args=[obj.id]), {"cipher": cipher})
            self.assertIn(b"3500000", resp.content)

    def test_only_one_request_at_a_time(self):
        self.finish_kyc()
        self.ask()
        self.ask("1000000")
        self.assertEqual(self.loans().count(), 1)

    def test_withdraw_allows_a_new_request(self):
        self.finish_kyc()
        self.ask()
        self.client.post(reverse("vault_delete", args=[self.loans().get().id]))
        self.ask("1000000", "medical")
        self.assertEqual(self.loans().count(), 1)

    def test_amount_limits(self):
        self.finish_kyc()
        for bad in ("0", "499999", "10000001", "-5", "abc", ""):
            self.assertEqual(self.ask(bad).status_code, 400, bad)
        self.assertEqual(self.ask(purpose="gold").status_code, 400)
        self.assertEqual(self.loans().count(), 0)

    def test_dashboard_marks_the_loan_step(self):
        ctx = self.client.get(reverse("vault_dashboard")).context
        self.assertFalse(ctx["complete"])
        self.assertIn("Locked", self.client.get(reverse("vault_dashboard")).content.decode())
        self.finish_kyc()
        self.assertTrue(self.client.get(reverse("vault_dashboard")).context["complete"])

    def test_loan_belongs_to_its_owner(self):
        self.finish_kyc()
        self.ask("3500000")
        bob = new_client()
        signup(bob, "bob", PASSWORD)
        self.assertNotIn("3,500,000", bob.get(reverse("vault_dashboard")).content.decode())
        self.assertEqual(bob.get(reverse("vault_download", args=[self.loans().get().id])).status_code, 404)

    def test_login_required(self):
        self.assertEqual(new_client().get(reverse("vault_loan")).status_code, 302)


class StubEngine:
    def __init__(self, passed):
        self.passed = passed

    def new_challenge(self):
        return "smile", "Please put on a smile expression"

    def check(self, frames, challenge, question):
        return live.Result(self.passed, len(frames), len(frames), "stub")


@override_settings(LIVENESS_ENGINE="ekyc")
class LivenessTests(PageBase):
    video = b"\x00\x00\x00\x18ftypmp42" + os.urandom(2000)

    def run_check(self, passed=True, data=None, name="liveness.mp4"):
        engine = StubEngine(passed)
        patches = [
            mock.patch.object(live, "get_engine", return_value=engine),
            mock.patch.object(live, "extract_frames", return_value=[object()] * 5),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.client.post(reverse("vault_liveness_challenge"))
        return self.client.post(reverse("vault_liveness_submit"), {"video": upload_file(name, data or self.video)})

    def test_passing_check_stores_the_video_encrypted(self):
        resp = self.run_check(True)
        self.assertTrue(resp.json()["passed"])
        oid = self.first_id(storage.VIDEO)
        got = self.client.get(reverse("vault_download", args=[oid]), {"cipher": "des"})
        self.assertEqual(got.content, self.video)

    def test_failing_check_stores_nothing(self):
        resp = self.run_check(False)
        self.assertFalse(resp.json()["passed"])
        self.assertFalse(StoredObject.objects.filter(category=storage.VIDEO).exists())

    def test_challenge_is_single_use(self):
        self.run_check(False)
        resp = self.client.post(reverse("vault_liveness_submit"), {"video": upload_file("l.mp4", self.video)})
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(StoredObject.objects.filter(category=storage.VIDEO).exists())

    def test_submit_without_challenge_is_rejected(self):
        resp = self.client.post(reverse("vault_liveness_submit"), {"video": upload_file("l.mp4", self.video)})
        self.assertEqual(resp.status_code, 400)

    def test_wrong_file_type_is_rejected_before_the_check(self):
        resp = self.run_check(True, data=b"%PDF-1.7\n" + os.urandom(200), name="liveness.mp4")
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(StoredObject.objects.filter(category=storage.VIDEO).exists())

    def test_plain_upload_is_redirected_to_the_check(self):
        resp = self.client.get(reverse("vault_upload", args=["video"]))
        self.assertRedirects(resp, reverse("vault_liveness"), fetch_redirect_response=False)
        resp = self.put("video", "live.mp4", self.video)
        self.assertRedirects(resp, reverse("vault_liveness"), fetch_redirect_response=False)
        self.assertFalse(StoredObject.objects.filter(category=storage.VIDEO).exists())

    def test_attempts_are_limited(self):
        for _ in range(views.LIVENESS_ATTEMPTS):
            self.run_check(False)
        self.assertEqual(self.run_check(True).status_code, 429)

    def test_page_needs_login(self):
        resp = new_client().get(reverse("vault_liveness"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("login", resp["Location"])

    def test_liveness_page_renders(self):
        self.assertContains(self.client.get(reverse("vault_liveness")), "liveness.js")


class LivenessOffTests(PageBase):
    def test_default_is_plain_upload(self):
        resp = self.client.get(reverse("vault_liveness"))
        self.assertRedirects(resp, reverse("vault_upload", args=["video"]), fetch_redirect_response=False)
        self.assertEqual(self.client.post(reverse("vault_liveness_challenge")).status_code, 404)


@unittest.skipUnless(importlib.util.find_spec("cv2"), "opencv not installed")
class FrameExtractionTests(TestCase):
    def test_frames_are_sampled_and_rgb(self):
        import cv2
        import numpy as np

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.avi")
            w = cv2.VideoWriter(path, cv2.VideoWriter_fourcc(*"MJPG"), 15, (320, 240))
            for _ in range(20):
                w.write(np.zeros((240, 320, 3), np.uint8) + np.array([255, 0, 0], np.uint8))  # BGR blue
            w.release()
            data = open(path, "rb").read()
        frames = live.extract_frames(data)
        self.assertEqual(len(frames), 10)
        self.assertGreater(frames[0][0, 0, 2], 200)  # blue ends up in the last RGB channel

    def test_garbage_is_unreadable(self):
        with self.assertRaises(live.VideoUnreadable):
            live.extract_frames(os.urandom(500))
