import os
from unittest import TestCase

from vault import keys
from vault.crypto_engine import IntegrityError


class UserKeyTests(TestCase):
    def test_unlock_returns_the_same_muk(self):
        salt, wrapped, muk = keys.new_user_key_material("correct horse", 7)
        self.assertEqual(len(muk), keys.MUK_SIZE)
        self.assertEqual(keys.unlock_muk("correct horse", salt, wrapped, 7), muk)

    def test_wrong_password_is_rejected(self):
        salt, wrapped, _ = keys.new_user_key_material("correct horse", 7)
        with self.assertRaises(IntegrityError):
            keys.unlock_muk("wrong horse", salt, wrapped, 7)

    def test_wrapped_muk_does_not_open_for_another_user(self):
        salt, wrapped, _ = keys.new_user_key_material("pw", 7)
        with self.assertRaises(IntegrityError):
            keys.unlock_muk("pw", salt, wrapped, 8)

    def test_tampered_wrapped_muk_is_rejected(self):
        salt, wrapped, _ = keys.new_user_key_material("pw", 7)
        for i in range(len(wrapped)):
            with self.subTest(byte=i):
                bad = bytearray(wrapped)
                bad[i] ^= 1
                with self.assertRaises(IntegrityError):
                    keys.unlock_muk("pw", salt, bytes(bad), 7)

    def test_salts_and_wrappings_are_fresh(self):
        s1, w1, m1 = keys.new_user_key_material("pw", 1)
        s2, w2, m2 = keys.new_user_key_material("pw", 1)
        self.assertNotEqual((s1, w1, m1), (s2, w2, m2))

    def test_rewrap_keeps_muk_and_retires_old_password(self):
        salt, wrapped, muk = keys.new_user_key_material("old password", 7)
        new_salt, new_wrapped = keys.rewrap_muk(muk, "new password", 7)
        self.assertEqual(keys.unlock_muk("new password", new_salt, new_wrapped, 7), muk)
        with self.assertRaises(IntegrityError):
            keys.unlock_muk("old password", new_salt, new_wrapped, 7)
        self.assertNotEqual(new_salt, salt)


class DataKeyTests(TestCase):
    def setUp(self):
        self.muk = os.urandom(keys.MUK_SIZE)
        self.aad = keys.record_aad(7, "rec-1", "ktp")

    def test_dek_round_trip(self):
        dek = keys.new_dek()
        self.assertEqual(keys.unwrap_dek(self.muk, keys.wrap_dek(self.muk, dek, self.aad), self.aad), dek)

    def test_every_dek_is_fresh(self):
        self.assertNotEqual(keys.new_dek(), keys.new_dek())

    def test_dek_is_bound_to_user_and_record(self):
        wrapped = keys.wrap_dek(self.muk, keys.new_dek(), self.aad)
        for other in (keys.record_aad(8, "rec-1", "ktp"), keys.record_aad(7, "rec-2", "ktp"), keys.record_aad(7, "rec-1", "video")):
            with self.subTest(other=other):
                with self.assertRaises(IntegrityError):
                    keys.unwrap_dek(self.muk, wrapped, other)

    def test_dek_does_not_unwrap_under_another_muk(self):
        wrapped = keys.wrap_dek(self.muk, keys.new_dek(), self.aad)
        with self.assertRaises(IntegrityError):
            keys.unwrap_dek(os.urandom(keys.MUK_SIZE), wrapped, self.aad)

    def test_short_wrapped_key_is_rejected(self):
        with self.assertRaises(IntegrityError):
            keys.unwrap_dek(self.muk, b"short", self.aad)
