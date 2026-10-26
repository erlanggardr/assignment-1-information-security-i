import os
from unittest import TestCase

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Util.Padding import pad

from vault import crypto_engine as ce

SIZES = [0, 1, 7, 8, 15, 16, 17, 1000, 5 * 1024 * 1024]
ZERO_IV_16 = bytes(16)
ZERO_IV_8 = bytes(8)


def new_keys():
    return ce.cipher_keys_from_dek(os.urandom(ce.DEK_SIZE))


class KnownAnswerTests(TestCase):

    def test_aes_256_fips_197(self):
        key = bytes(range(32))
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = AES.new(key, AES.MODE_CBC, ZERO_IV_16).encrypt(pt)
        self.assertEqual(ct.hex(), "8ea2b7ca516745bfeafc49904b496089")

    def test_des_classic_vector(self):
        key = bytes.fromhex("133457799BBCDFF1")
        pt = bytes.fromhex("0123456789ABCDEF")
        ct = DES.new(key, DES.MODE_CBC, ZERO_IV_8).encrypt(pt)
        self.assertEqual(ct.hex().upper(), "85E813540F0AB405")

    def test_rc4_wikipedia_vector(self):
        ct = ARC4.new(b"Key").encrypt(b"Plaintext")
        self.assertEqual(ct.hex().upper(), "BBF316E8D940AF0AD3")


class WrapperUsesTheRightPrimitiveTests(TestCase):

    def setUp(self):
        self.keys = new_keys()
        self.data = os.urandom(1234)

    def test_aes_is_aes_256_cbc_pkcs7(self):
        blob = ce.encrypt("aes", self.data, self.keys)
        iv, ct = blob[:16], blob[48:]
        self.assertEqual(len(self.keys.aes), 32)
        self.assertEqual(AES.new(self.keys.aes, AES.MODE_CBC, iv).encrypt(pad(self.data, 16)), ct)

    def test_des_is_single_des_cbc_pkcs7(self):
        blob = ce.encrypt("des", self.data, self.keys)
        iv, ct = blob[:8], blob[40:]
        self.assertEqual(len(self.keys.des), 8)
        self.assertEqual(DES.new(self.keys.des, DES.MODE_CBC, iv).encrypt(pad(self.data, 8)), ct)

    def test_rc4_is_rc4_with_nonce_mixed_key_and_drop(self):
        blob = ce.encrypt("rc4", self.data, self.keys)
        nonce, ct = blob[:16], blob[48:]
        session_key = ce._rc4_session_key(self.keys, nonce)
        stream = ARC4.new(session_key)
        stream.encrypt(bytes(ce.RC4_DROP))
        self.assertEqual(stream.encrypt(self.data), ct)
        self.assertEqual(len(ct), len(self.data))


class CryptoEngineTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.keys = new_keys()
        cls.other_keys = new_keys()

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

    def test_cipher_keys_are_deterministic_separated_and_sized(self):
        dek = os.urandom(ce.DEK_SIZE)
        a = ce.cipher_keys_from_dek(dek)
        self.assertEqual(a, ce.cipher_keys_from_dek(dek))
        self.assertNotEqual(a, new_keys())
        self.assertEqual((len(a.aes), len(a.des), len(a.rc4), len(a.mac)), (32, 8, 16, 32))
        self.assertEqual(len({a.aes, a.des, a.rc4, a.mac}), 4)
        with self.assertRaises(ValueError):
            ce.cipher_keys_from_dek(b"too short")

    def test_keyed_digest_depends_on_key_data_and_aad(self):
        d = ce.keyed_digest(self.keys, b"3171234567890001", b"u|r")
        self.assertEqual(len(d), 32)
        self.assertEqual(d, ce.keyed_digest(self.keys, b"3171234567890001", b"u|r"))
        self.assertNotEqual(d, ce.keyed_digest(self.other_keys, b"3171234567890001", b"u|r"))
        self.assertNotEqual(d, ce.keyed_digest(self.keys, b"3171234567890002", b"u|r"))
        self.assertNotEqual(d, ce.keyed_digest(self.keys, b"3171234567890001", b"u|x"))

    def test_encrypt_all_and_verify(self):
        data = os.urandom(5000)
        digest, results = ce.encrypt_all(data, self.keys, aad=b"u|r")
        self.assertEqual(set(results), set(ce.CIPHERS))
        for name, res in results.items():
            self.assertEqual(res.size, len(res.blob))
            self.assertGreater(res.encrypt_ns, 0)
            self.assertEqual(ce.decrypt_and_verify(name, res.blob, self.keys, digest, b"u|r"), data)
        with self.assertRaises(ce.IntegrityError):
            ce.decrypt_and_verify("aes", results["aes"].blob, self.keys, bytes(32), b"u|r")

    def test_unknown_cipher_name(self):
        with self.assertRaises(ValueError):
            ce.encrypt("blowfish", b"x", self.keys)
