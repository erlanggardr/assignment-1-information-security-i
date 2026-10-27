import logging

from . import keys
from .crypto_engine import IntegrityError
from .keyring import keyring
from .models import UserKey

log = logging.getLogger(__name__)


class VaultLocked(Exception):
    pass


def provision_user_key(user, password: str) -> bytes:
    salt, wrapped, muk = keys.new_user_key_material(password, user.pk)
    UserKey.objects.create(user=user, kdf_salt=salt, wrapped_muk=wrapped)
    return muk


def unlock_user(user, password: str):
    try:
        record = user.vault_key
    except UserKey.DoesNotExist:
        return provision_user_key(user, password)
    try:
        return keys.unlock_muk(
            password, bytes(record.kdf_salt), bytes(record.wrapped_muk), user.pk, record.kdf_iterations
        )
    except IntegrityError:
        log.warning("vault key of user %s does not open with the supplied password", user.pk)
        return None


def change_password(user, old_password: str, new_password: str) -> bool:
    muk = unlock_user(user, old_password)
    if muk is None:
        return False
    salt, wrapped = keys.rewrap_muk(muk, new_password, user.pk)
    UserKey.objects.filter(user=user).update(kdf_salt=salt, wrapped_muk=wrapped, kdf_iterations=keys.KEK_ITERATIONS)
    return True


def get_muk(request):
    return keyring.get(request.session.session_key)


def require_muk(request) -> bytes:
    muk = get_muk(request)
    if muk is None:
        raise VaultLocked()
    return muk
