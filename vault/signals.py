from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.db.models.signals import post_delete
from django.dispatch import receiver

from .keyring import keyring
from .models import StoredObject


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


@receiver(post_delete, sender=StoredObject)
def remove_blob_files(sender, instance, **kwargs):
    # cascades (deleting a user) skip delete_object, so clean the files here
    for cipher in ("aes", "des", "rc4"):
        field = getattr(instance, f"{cipher}_file")
        if field:
            field.storage.delete(field.name)
