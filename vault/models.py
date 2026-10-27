from django.conf import settings
from django.db import models

from . import keys


class UserKey(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="vault_key")
    kdf_salt = models.BinaryField(max_length=keys.SALT_SIZE)
    wrapped_muk = models.BinaryField(max_length=64)
    kdf_iterations = models.PositiveIntegerField(default=keys.KEK_ITERATIONS)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"UserKey({self.user_id})"
