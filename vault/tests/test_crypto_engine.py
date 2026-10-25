import os
from unittest import TestCase

from vault import crypto_engine as ce

SIZES = [0, 1, 7, 8, 15, 16, 17, 1000, 5 * 1024 * 1024]


class CryptoEngineTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.keys = ce.derive_user_keys("correct horse", ce.new_salt())
        cls.other_keys = ce.derive_user_keys("another password", ce.new_salt())

    def test_round_trip_all_sizes(self):
        for name in ce.CIPHERS:
            for size in SIZES:
                with self.subTest(cipher=name, size=size):
                    data = os.urandom(size)
                    blob = ce.encrypt(name, data, self.keys)
                    self.assertEqual(ce.decrypt(name, blob, self.keys), data)

    def test_same_plaintext_gives_different_ciphertext(self):
        data = b"identical plaintext " * 10
        for name in ce.CIPHERS:
            with self.subTest(cipher=name):
                self.assertNotEqual(ce.encrypt(name, data, self.keys), ce.encrypt(name, data, self.keys))

    def test_flipping_any_byte_is_rejected(self):
        for name in ce.CIPHERS:
            blob = ce.encrypt(name, os.urandom(40), self.keys)
            for i in range(len(blob)):
                with self.subTest(cipher=name, byte=i):
                    bad = bytearray(blob)
                    bad[i] ^= 0x01
                    with self.assertRaises(ce.IntegrityError):
                        ce.decrypt(name, bytes(bad), self.keys)

    def test_wrong_key_is_rejected(self):
        for name in ce.CIPHERS:
            with self.subTest(cipher=name):
                blob = ce.encrypt(name, b"secret", self.keys)
                with self.assertRaises(ce.IntegrityError):
                    ce.decrypt(name, blob, self.other_keys)

    def test_aad_mismatch_is_rejected(self):
        for name in ce.CIPHERS:
            with self.subTest(cipher=name):
                blob = ce.encrypt(name, b"secret", self.keys, aad=b"user1|rec1")
                self.assertEqual(ce.decrypt(name, blob, self.keys, aad=b"user1|rec1"), b"secret")
                with self.assertRaises(ce.IntegrityError):
                    ce.decrypt(name, blob, self.keys, aad=b"user2|rec1")

    def test_truncated_blob_is_rejected(self):
        for name in ce.CIPHERS:
            with self.subTest(cipher=name):
                with self.assertRaises(ce.IntegrityError):
                    ce.decrypt(name, ce.encrypt(name, b"secret", self.keys)[:10], self.keys)

    def test_blob_from_another_cipher_is_rejected(self):
        blob = ce.encrypt("aes", b"secret", self.keys)
        with self.assertRaises(ce.IntegrityError):
            ce.decrypt("des", blob, self.keys)

    def test_key_derivation(self):
        salt = ce.new_salt()
        a = ce.derive_user_keys("pw", salt)
        self.assertEqual(a, ce.derive_user_keys("pw", salt))
        self.assertNotEqual(a, ce.derive_user_keys("pw", ce.new_salt()))
        self.assertEqual((len(a.aes), len(a.des), len(a.rc4), len(a.mac)), (32, 8, 16, 32))
        self.assertEqual(len({a.aes, a.des, a.rc4, a.mac}), 4)

    def test_encrypt_all_and_verify(self):
        data = os.urandom(5000)
        digest, results = ce.encrypt_all(data, self.keys, aad=b"u|r")
        self.assertEqual(set(results), set(ce.CIPHERS))
        for name, res in results.items():
            self.assertEqual(res.size, len(res.blob))
            self.assertGreater(res.encrypt_ns, 0)
            self.assertEqual(ce.decrypt_and_verify(name, res.blob, self.keys, digest, b"u|r"), data)
        with self.assertRaises(ce.IntegrityError):
            ce.decrypt_and_verify("aes", results["aes"].blob, self.keys, "0" * 64, b"u|r")

    def test_unknown_cipher_name(self):
        with self.assertRaises(ValueError):
            ce.encrypt("blowfish", b"x", self.keys)
