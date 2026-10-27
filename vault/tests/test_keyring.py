from unittest import TestCase

from vault.keyring import Keyring


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class KeyringTests(TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.ring = Keyring(ttl=60, clock=self.clock)

    def test_put_and_get(self):
        self.ring.put("s1", b"k" * 32)
        self.assertEqual(self.ring.get("s1"), b"k" * 32)

    def test_unknown_or_empty_session_key(self):
        self.assertIsNone(self.ring.get("nope"))
        self.assertIsNone(self.ring.get(None))
        self.assertIsNone(self.ring.get(""))

    def test_keys_are_per_session(self):
        self.ring.put("s1", b"a" * 32)
        self.ring.put("s2", b"b" * 32)
        self.assertEqual(self.ring.get("s1"), b"a" * 32)
        self.assertEqual(self.ring.get("s2"), b"b" * 32)

    def test_expires_after_ttl_without_use(self):
        self.ring.put("s1", b"k" * 32)
        self.clock.now += 61
        self.assertIsNone(self.ring.get("s1"))
        self.assertEqual(len(self.ring), 0)

    def test_use_extends_lifetime(self):
        self.ring.put("s1", b"k" * 32)
        for _ in range(5):
            self.clock.now += 50
            self.assertEqual(self.ring.get("s1"), b"k" * 32)

    def test_drop_and_clear(self):
        self.ring.put("s1", b"a" * 32)
        self.ring.put("s2", b"b" * 32)
        self.ring.drop("s1")
        self.ring.drop("missing")
        self.assertIsNone(self.ring.get("s1"))
        self.assertIsNotNone(self.ring.get("s2"))
        self.ring.clear()
        self.assertEqual(len(self.ring), 0)
