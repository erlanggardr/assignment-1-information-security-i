from django.contrib.auth import get_user_model
from django.test import TestCase

from vault import keys
from vault.keyring import keyring
from vault.models import UserKey
from vault.tests.support import login, new_client, no_manifest, signup

PASSWORD = "Str0ng-pass-123"


@no_manifest
class KeyLifecycleTests(TestCase):
    def setUp(self):
        keyring.clear()

    def unlocked_key(self, client):
        return keyring.get(client.session.session_key)

    def test_signup_creates_a_wrapped_key_and_unlocks_the_session(self):
        c = new_client()
        signup(c, "borrower1", PASSWORD)
        user = get_user_model().objects.get(username="borrower1")
        record = UserKey.objects.get(user=user)
        self.assertGreater(len(bytes(record.wrapped_muk)), keys.MUK_SIZE)
        muk = self.unlocked_key(c)
        self.assertIsNotNone(muk)
        self.assertNotIn(muk, bytes(record.wrapped_muk))

    def test_login_unlocks_the_same_key_in_a_new_session(self):
        c1 = new_client()
        signup(c1, "borrower1", PASSWORD)
        muk = self.unlocked_key(c1)
        c2 = new_client()
        login(c2, "borrower1", PASSWORD)
        self.assertEqual(self.unlocked_key(c2), muk)
        self.assertNotEqual(c1.session.session_key, c2.session.session_key)

    def test_wrong_password_unlocks_nothing(self):
        signup(new_client(), "borrower1", PASSWORD)
        keyring.clear()
        c = new_client()
        login(c, "borrower1", "wrong-password")
        self.assertEqual(len(keyring), 0)
        self.assertNotIn("_auth_user_id", c.session)

    def test_logout_drops_the_key(self):
        c = new_client()
        signup(c, "borrower1", PASSWORD)
        key = c.session.session_key
        self.assertIsNotNone(keyring.get(key))
        c.post("/accounts/logout/")
        self.assertIsNone(keyring.get(key))

    def test_users_have_different_keys(self):
        c1, c2 = new_client(), new_client()
        signup(c1, "borrower1", PASSWORD)
        signup(c2, "borrower2", PASSWORD)
        self.assertNotEqual(self.unlocked_key(c1), self.unlocked_key(c2))

    def test_user_created_without_a_key_gets_one_at_first_login(self):
        get_user_model().objects.create_user("legacy", password=PASSWORD)
        c = new_client()
        login(c, "legacy", PASSWORD)
        self.assertTrue(UserKey.objects.filter(user__username="legacy").exists())
        self.assertIsNotNone(self.unlocked_key(c))

    def test_password_change_rewraps_the_key_without_changing_it(self):
        c = new_client()
        signup(c, "borrower1", PASSWORD)
        muk = self.unlocked_key(c)
        before = bytes(UserKey.objects.get(user__username="borrower1").wrapped_muk)
        new_pw = "An0ther-str0ng-pass"
        resp = c.post("/accounts/password/change/", {"oldpassword": PASSWORD, "password1": new_pw, "password2": new_pw})
        self.assertEqual(resp.status_code, 302)
        after = bytes(UserKey.objects.get(user__username="borrower1").wrapped_muk)
        self.assertNotEqual(before, after)
        keyring.clear()
        c2 = new_client()
        login(c2, "borrower1", new_pw)
        self.assertEqual(self.unlocked_key(c2), muk)
        c3 = new_client()
        login(c3, "borrower1", PASSWORD)
        self.assertNotIn("_auth_user_id", c3.session)

    def test_password_reset_cannot_recover_the_key(self):
        c = new_client()
        signup(c, "borrower1", PASSWORD)
        user = get_user_model().objects.get(username="borrower1")
        user.set_password("Reset-by-email-123")
        user.save()
        keyring.clear()
        c2 = new_client()
        login(c2, "borrower1", "Reset-by-email-123")
        self.assertIn("_auth_user_id", c2.session)
        self.assertEqual(len(keyring), 0)
