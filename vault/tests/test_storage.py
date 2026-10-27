import os
import shutil
import tempfile

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase, override_settings

from vault import crypto_engine as ce
from vault import keys, storage
from vault.models import StoredObject

PNG = b"\x89PNG\r\n\x1a\n" + os.urandom(3000)
PDF = b"%PDF-1.7\n" + os.urandom(2000)
MP4 = b"\x00\x00\x00\x18ftypmp42" + os.urandom(storage.INLINE_LIMIT + 5000)
PROFILE = {"full_name": "Budi Santoso", "nik": "3174010101900001", "net_worth": "250000000"}


class StorageBase(TestCase):
    def setUp(self):
        self.media = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.media, ignore_errors=True)
        override = override_settings(MEDIA_ROOT=self.media)
        override.enable()
        self.addCleanup(override.disable)
        User = get_user_model()
        self.alice = User.objects.create_user("alice", password="x")
        self.bob = User.objects.create_user("bob", password="x")
        self.alice_muk = os.urandom(keys.MUK_SIZE)
        self.bob_muk = os.urandom(keys.MUK_SIZE)

    def files_on_disk(self):
        return [f for _, _, names in os.walk(self.media) for f in names]


class RoundTripTests(StorageBase):
    def test_every_category_returns_identical_bytes_for_every_cipher(self):
        cases = [(storage.ID_CARD, "ktp.png", PNG), (storage.OFFICE, "slip.pdf", PDF), (storage.VIDEO, "live.mp4", MP4)]
        for category, name, data in cases:
            obj = storage.store_file(self.alice, self.alice_muk, category, name, data)
            for cipher in ce.CIPHERS:
                loaded = storage.load_object(self.alice, self.alice_muk, obj.id, cipher)
                self.assertEqual(loaded.data, data, (category, cipher))
                self.assertEqual(loaded.filename, name)

    def test_profile_round_trip_in_all_ciphers(self):
        storage.store_profile(self.alice, self.alice_muk, PROFILE)
        for cipher in ce.CIPHERS:
            self.assertEqual(storage.load_profile(self.alice, self.alice_muk, cipher), PROFILE)

    def test_small_blobs_stay_in_database_and_large_ones_go_to_disk(self):
        storage.store_profile(self.alice, self.alice_muk, PROFILE)
        self.assertEqual(self.files_on_disk(), [])
        storage.store_file(self.alice, self.alice_muk, storage.VIDEO, "live.mp4", MP4)
        self.assertEqual(len(self.files_on_disk()), 3)

    def test_disk_names_are_opaque(self):
        storage.store_file(self.alice, self.alice_muk, storage.VIDEO, "budi_selfie.mp4", MP4)
        for name in self.files_on_disk():
            self.assertNotIn("budi", name)
            self.assertNotIn("selfie", name)

    def test_nothing_readable_is_stored_in_the_database(self):
        storage.store_file(self.alice, self.alice_muk, storage.ID_CARD, "budi_ktp.png", PNG)
        storage.store_profile(self.alice, self.alice_muk, PROFILE)
        with connection.cursor() as cur:
            cur.execute("select * from vault_storedobject")
            raw = b"".join(bytes(v) if isinstance(v, (bytes, memoryview)) else str(v).encode() for row in cur.fetchall() for v in row)
        for secret in (b"budi_ktp", b"Budi Santoso", b"3174010101900001", PNG[20:60]):
            self.assertNotIn(secret, raw)

    def test_three_ciphertext_copies_differ(self):
        obj = storage.store_file(self.alice, self.alice_muk, storage.ID_CARD, "ktp.png", PNG)
        blobs = {bytes(getattr(obj, f"{c}_inline")) for c in ce.CIPHERS}
        self.assertEqual(len(blobs), 3)

    def test_load_reports_timings(self):
        obj = storage.store_file(self.alice, self.alice_muk, storage.OFFICE, "slip.pdf", PDF)
        loaded = storage.load_object(self.alice, self.alice_muk, obj.id, "des")
        self.assertGreater(loaded.decrypt_ns, 0)
        self.assertEqual(loaded.total_ns, loaded.io_ns + loaded.unwrap_ns + loaded.decrypt_ns + loaded.verify_ns)


class OwnershipTests(StorageBase):
    def test_other_user_cannot_load_or_delete(self):
        obj = storage.store_file(self.alice, self.alice_muk, storage.ID_CARD, "ktp.png", PNG)
        with self.assertRaises(storage.ObjectNotFound):
            storage.load_object(self.bob, self.bob_muk, obj.id)
        with self.assertRaises(storage.ObjectNotFound):
            storage.delete_object(self.bob, obj.id)
        self.assertEqual(storage.load_object(self.alice, self.alice_muk, obj.id).data, PNG)

    def test_wrong_master_key_does_not_open_the_object(self):
        obj = storage.store_file(self.alice, self.alice_muk, storage.ID_CARD, "ktp.png", PNG)
        with self.assertRaises(ce.IntegrityError):
            storage.load_object(self.alice, self.bob_muk, obj.id)

    def test_listing_only_shows_own_items(self):
        storage.store_file(self.alice, self.alice_muk, storage.ID_CARD, "a.png", PNG)
        storage.store_file(self.bob, self.bob_muk, storage.ID_CARD, "b.png", PNG)
        names = [e["filename"] for e in storage.list_entries(self.alice, self.alice_muk)]
        self.assertEqual(names, ["a.png"])

    def test_copying_a_row_to_another_owner_fails_verification(self):
        obj = storage.store_file(self.alice, self.alice_muk, storage.ID_CARD, "ktp.png", PNG)
        StoredObject.objects.filter(pk=obj.pk).update(owner=self.bob)
        with self.assertRaises(ce.IntegrityError):
            storage.load_object(self.bob, self.alice_muk, obj.id)


class TamperTests(StorageBase):
    def test_flipped_inline_ciphertext_is_rejected_per_cipher(self):
        obj = storage.store_file(self.alice, self.alice_muk, storage.ID_CARD, "ktp.png", PNG)
        for cipher in ce.CIPHERS:
            blob = bytearray(getattr(StoredObject.objects.get(pk=obj.pk), f"{cipher}_inline"))
            blob[-1] ^= 1
            StoredObject.objects.filter(pk=obj.pk).update(**{f"{cipher}_inline": bytes(blob)})
            with self.assertRaises(ce.IntegrityError, msg=cipher):
                storage.load_object(self.alice, self.alice_muk, obj.id, cipher)

    def test_tampered_file_on_disk_is_rejected(self):
        obj = storage.store_file(self.alice, self.alice_muk, storage.VIDEO, "live.mp4", MP4)
        path = os.path.join(self.media, StoredObject.objects.get(pk=obj.pk).aes_file.name)
        with open(path, "r+b") as f:
            f.seek(100)
            f.write(b"\x00\x01\x02")
        with self.assertRaises(ce.IntegrityError):
            storage.load_object(self.alice, self.alice_muk, obj.id, "aes")
        self.assertEqual(storage.load_object(self.alice, self.alice_muk, obj.id, "des").data, MP4)

    def test_missing_file_is_reported_as_integrity_error(self):
        obj = storage.store_file(self.alice, self.alice_muk, storage.VIDEO, "live.mp4", MP4)
        os.remove(os.path.join(self.media, StoredObject.objects.get(pk=obj.pk).rc4_file.name))
        with self.assertRaises(ce.IntegrityError):
            storage.load_object(self.alice, self.alice_muk, obj.id, "rc4")


class ValidationTests(StorageBase):
    def reject(self, category, name, data):
        with self.assertRaises(storage.UploadRejected):
            storage.store_file(self.alice, self.alice_muk, category, name, data)
        self.assertEqual(StoredObject.objects.count(), 0)

    def test_wrong_extension_for_category(self):
        self.reject(storage.ID_CARD, "ktp.pdf", PDF)
        self.reject(storage.VIDEO, "x.png", PNG)
        self.reject(storage.OFFICE, "run.exe", b"MZ" + os.urandom(100))

    def test_content_must_match_extension(self):
        self.reject(storage.ID_CARD, "ktp.png", b"not an image at all")
        self.reject(storage.OFFICE, "slip.pdf", PNG)

    def test_empty_and_oversized(self):
        self.reject(storage.ID_CARD, "ktp.png", b"")
        limit = storage.RULES[storage.ID_CARD]["max"]
        self.reject(storage.ID_CARD, "ktp.png", b"\x89PNG\r\n\x1a\n" + bytes(limit))

    def test_filename_is_sanitised(self):
        obj = storage.store_file(self.alice, self.alice_muk, storage.ID_CARD, "../../etc/pass\r\nwd.png", PNG)
        loaded = storage.load_object(self.alice, self.alice_muk, obj.id)
        self.assertEqual(loaded.filename, "passwd.png")
        self.assertEqual(storage.clean_filename("C:\\dir\\ktp.png"), "ktp.png")
        self.assertEqual(storage.clean_filename(""), "file")

    def test_mime_comes_from_the_server_not_the_client(self):
        obj = storage.store_file(self.alice, self.alice_muk, storage.ID_CARD, "ktp.png", PNG)
        self.assertEqual(storage.load_object(self.alice, self.alice_muk, obj.id).mime, "image/png")


class LifecycleTests(StorageBase):
    def test_saving_a_profile_replaces_the_previous_one(self):
        storage.store_profile(self.alice, self.alice_muk, PROFILE)
        storage.store_profile(self.alice, self.alice_muk, {**PROFILE, "full_name": "Budi Baru"})
        self.assertEqual(StoredObject.objects.filter(owner=self.alice, category=storage.PROFILE).count(), 1)
        self.assertEqual(storage.load_profile(self.alice, self.alice_muk)["full_name"], "Budi Baru")

    def test_profile_is_none_before_it_is_saved(self):
        self.assertIsNone(storage.load_profile(self.alice, self.alice_muk))

    def test_delete_removes_row_and_all_files(self):
        obj = storage.store_file(self.alice, self.alice_muk, storage.VIDEO, "live.mp4", MP4)
        self.assertEqual(len(self.files_on_disk()), 3)
        storage.delete_object(self.alice, obj.id)
        self.assertEqual(self.files_on_disk(), [])
        self.assertEqual(StoredObject.objects.count(), 0)

    def test_deleting_a_user_removes_their_files(self):
        storage.store_file(self.alice, self.alice_muk, storage.VIDEO, "live.mp4", MP4)
        self.alice.delete()
        self.assertEqual(self.files_on_disk(), [])

    def test_failed_save_leaves_no_files_behind(self):
        from unittest import mock

        with mock.patch.object(StoredObject, "save", side_effect=RuntimeError("db down")):
            with self.assertRaises(RuntimeError):
                storage.store_file(self.alice, self.alice_muk, storage.VIDEO, "live.mp4", MP4)
        self.assertEqual(self.files_on_disk(), [])
