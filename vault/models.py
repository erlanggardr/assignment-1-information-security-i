import uuid

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


def blob_path(instance, filename):
    """Opaque on-disk name"""
    cipher = filename.rsplit(".", 1)[-1]
    return f"objects/{uuid.uuid4().hex}.{cipher}"


class StoredObject(models.Model):
    """One sealed item. The three ciphertext copies."""

    PROFILE = "PROFILE"
    ID_CARD = "ID_CARD"
    OFFICE = "OFFICE"
    VIDEO = "VIDEO"
    LOAN = "LOAN"
    CATEGORIES = [
        (PROFILE, "Personal data"),
        (ID_CARD, "ID card image"),
        (OFFICE, "Office document"),
        (VIDEO, "Video"),
        (LOAN, "Loan request"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="vault_objects")
    category = models.CharField(max_length=16, choices=CATEGORIES)
    created_at = models.DateTimeField(auto_now_add=True)
    plain_size = models.PositiveBigIntegerField()
    wrapped_dek = models.BinaryField()
    digest = models.BinaryField(max_length=32)
    meta = models.BinaryField()

    aes_inline = models.BinaryField(null=True, blank=True)
    des_inline = models.BinaryField(null=True, blank=True)
    rc4_inline = models.BinaryField(null=True, blank=True)
    aes_file = models.FileField(upload_to=blob_path, blank=True, max_length=255)
    des_file = models.FileField(upload_to=blob_path, blank=True, max_length=255)
    rc4_file = models.FileField(upload_to=blob_path, blank=True, max_length=255)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["owner", "category"])]

    def __str__(self):
        return f"StoredObject({self.id}, {self.category})"
