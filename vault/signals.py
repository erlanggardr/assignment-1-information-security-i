from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver

from .keyring import keyring


@receiver(user_logged_in)
def store_unlocked_key(sender, request, user, **kwargs):
    muk = getattr(request, "_vault_muk", None)
    if muk is None:
        return
    del request._vault_muk
    if not request.session.session_key:
        request.session.save()
    keyring.put(request.session.session_key, muk)


@receiver(user_logged_out)
def forget_key(sender, request, user, **kwargs):
    if request is not None and request.session.session_key:
        keyring.drop(request.session.session_key)
