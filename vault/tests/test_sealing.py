import hashlib
import os
from unittest import TestCase

from vault import crypto_engine as ce
from vault import keys, sealing


class SealingTests(TestCase):
    def setUp(self):
        self.muk = os.urandom(keys.MUK_SIZE)
        self.aad = keys.record_aad(7, "rec-1", "ktp")

    def test_three_copies_each_open_to_the_original(self):
        for size in (0, 1, 1000, 1024 * 1024):
            data = os.urandom(size)
            sealed = sealing.seal(data, self.muk, self.aad)
            self.assertEqual(set(sealed.blobs), set(ce.CIPHERS))
            self.assertEqual(sealed.plaintext_size, size)
            for name in ce.CIPHERS:
                with self.subTest(size=size, cipher=name):
                    self.assertEqual(sealing.open_sealed(sealed, name, self.muk, self.aad).plaintext, data)

    def test_open_reports_a_timing_breakdown(self):
        sealed = sealing.seal(os.urandom(5000), self.muk, self.aad)
        res = sealing.open_sealed(sealed, "des", self.muk, self.aad)
        self.assertTrue(res.unwrap_ns > 0 and res.decrypt_ns > 0 and res.verify_ns > 0)
        self.assertEqual(res.crypto_ns, res.unwrap_ns + res.decrypt_ns + res.verify_ns)

    def test_each_seal_uses_a_fresh_key(self):
        a = sealing.seal(b"same data", self.muk, self.aad)
        b = sealing.seal(b"same data", self.muk, self.aad)
        self.assertNotEqual(a.wrapped_dek, b.wrapped_dek)
        self.assertNotEqual(a.digest, b.digest)
        for name in ce.CIPHERS:
            self.assertNotEqual(a.blobs[name], b.blobs[name])

    def test_digest_leaks_no_unkeyed_hash_of_the_plaintext(self):
        nik = b"3171234567890001"
        sealed = sealing.seal(nik, self.muk, self.aad)
        self.assertNotEqual(sealed.digest, hashlib.sha256(nik).digest())
        self.assertNotIn(hashlib.sha256(nik).hexdigest(), sealed.digest.hex())

    def test_another_users_key_cannot_open_the_object(self):
        sealed = sealing.seal(b"secret", self.muk, self.aad)
        for name in ce.CIPHERS:
            with self.subTest(cipher=name):
                with self.assertRaises(ce.IntegrityError):
                    sealing.open_sealed(sealed, name, os.urandom(keys.MUK_SIZE), self.aad)

    def test_object_moved_to_another_user_or_record_is_rejected(self):
        sealed = sealing.seal(b"secret", self.muk, self.aad)
        for other in (keys.record_aad(8, "rec-1", "ktp"), keys.record_aad(7, "rec-2", "ktp")):
            for name in ce.CIPHERS:
                with self.subTest(cipher=name, other=other):
                    with self.assertRaises(ce.IntegrityError):
                        sealing.open_sealed(sealed, name, self.muk, other)

    def test_tampered_ciphertext_digest_or_wrapped_key_is_rejected(self):
        sealed = sealing.seal(b"x" * 100, self.muk, self.aad)
        for name in ce.CIPHERS:
            blob = bytearray(sealed.blobs[name])
            blob[-1] ^= 1
            with self.subTest(what="blob", cipher=name):
                with self.assertRaises(ce.IntegrityError):
                    sealing.open_one(name, bytes(blob), sealed.wrapped_dek, sealed.digest, self.muk, self.aad)
        bad_digest = bytes([sealed.digest[0] ^ 1]) + sealed.digest[1:]
        with self.assertRaises(ce.IntegrityError):
            sealing.open_one("aes", sealed.blobs["aes"], sealed.wrapped_dek, bad_digest, self.muk, self.aad)
        bad_dek = bytearray(sealed.wrapped_dek)
        bad_dek[-1] ^= 1
        with self.assertRaises(ce.IntegrityError):
            sealing.open_one("aes", sealed.blobs["aes"], bytes(bad_dek), sealed.digest, self.muk, self.aad)

    def test_copy_swapped_between_objects_is_rejected(self):
        a = sealing.seal(b"object a", self.muk, self.aad)
        b = sealing.seal(b"object b", self.muk, self.aad)
        with self.assertRaises(ce.IntegrityError):
            sealing.open_one("aes", b.blobs["aes"], a.wrapped_dek, a.digest, self.muk, self.aad)

    def test_json_record_round_trip_is_canonical(self):
        record = {"name": "Siti Aisyah", "nik": "3171234567890001", "income": 12500000, "alamat": "Jl. Mawar No. 5"}
        self.assertEqual(sealing.dump_json(record), sealing.dump_json(dict(reversed(list(record.items())))))
        sealed = sealing.seal_json(record, self.muk, self.aad)
        for name in ce.CIPHERS:
            with self.subTest(cipher=name):
                self.assertEqual(sealing.load_json(sealing.open_sealed(sealed, name, self.muk, self.aad)), record)
