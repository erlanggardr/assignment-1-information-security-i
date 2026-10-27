import json
import os
import re
import time
import uuid
from dataclasses import dataclass

from django.core.files.base import ContentFile
from django.db import transaction

from . import crypto_engine as ce
from . import keys, sealing
from .models import StoredObject

PROFILE, ID_CARD, OFFICE, VIDEO, LOAN = (
    StoredObject.PROFILE,
    StoredObject.ID_CARD,
    StoredObject.OFFICE,
    StoredObject.VIDEO,
    StoredObject.LOAN,
)
KYC_CATEGORIES = (PROFILE, ID_CARD, OFFICE, VIDEO)

INLINE_LIMIT = 256 * 1024

MB = 1024 * 1024
# uploads are read fully into memory (plaintext + 3 ciphertexts), so keep the limits low
RULES = {
    ID_CARD: {"exts": {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png"}, "max": 10 * MB},
    OFFICE: {
        "exts": {
            "pdf": "application/pdf",
            "doc": "application/msword",
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xls": "application/vnd.ms-excel",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        },
        "max": 25 * MB,
    },
    VIDEO: {"exts": {"mp4": "video/mp4", "webm": "video/webm", "mov": "video/quicktime"}, "max": 50 * MB},
}
PROFILE_MAX = 16 * 1024
LOAN_MIN, LOAN_MAX = 500_000, 10_000_000

_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_MAGIC = {
    "jpg": lambda d: d.startswith(b"\xff\xd8\xff"),
    "jpeg": lambda d: d.startswith(b"\xff\xd8\xff"),
    "png": lambda d: d.startswith(b"\x89PNG\r\n\x1a\n"),
    "pdf": lambda d: d.startswith(b"%PDF-"),
    "doc": lambda d: d.startswith(_OLE),
    "xls": lambda d: d.startswith(_OLE),
    "docx": lambda d: d.startswith(b"PK\x03\x04"),
    "xlsx": lambda d: d.startswith(b"PK\x03\x04"),
    "mp4": lambda d: d[4:8] == b"ftyp",
    "mov": lambda d: d[4:8] in (b"ftyp", b"moov", b"wide", b"mdat", b"free"),
    "webm": lambda d: d.startswith(b"\x1a\x45\xdf\xa3"),
}


class ObjectNotFound(Exception):
    pass


class UploadRejected(Exception):
    pass


class LoanRejected(Exception):
    pass


@dataclass(frozen=True)
class LoadedObject:
    id: uuid.UUID
    category: str
    filename: str
    mime: str
    data: bytes
    cipher: str
    io_ns: int
    unwrap_ns: int
    decrypt_ns: int
    verify_ns: int

    @property
    def total_ns(self) -> int:
        return self.io_ns + self.unwrap_ns + self.decrypt_ns + self.verify_ns


def clean_filename(name: str) -> str:
    name = os.path.basename((name or "").replace("\\", "/"))
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip().lstrip(".")
    return name[:120] or "file"


def extension(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def validate_file(category: str, filename: str, size: int, data: bytes = None) -> str:
    """Return the MIME type for an allowed upload, or raise UploadRejected."""
    rule = RULES.get(category)
    if rule is None:
        raise UploadRejected("Unknown file category.")
    ext = extension(filename)
    if ext not in rule["exts"]:
        allowed = ", ".join(sorted(rule["exts"]))
        raise UploadRejected(f"File type .{ext or '?'} is not allowed here (allowed: {allowed}).")
    if size <= 0:
        raise UploadRejected("The file is empty.")
    if size > rule["max"]:
        raise UploadRejected(f"File is larger than {rule['max'] // MB} MB.")
    if data is not None and not _MAGIC[ext](data):
        raise UploadRejected(f"The file content does not look like a .{ext} file.")
    return rule["exts"][ext]


def _aad(user, object_id, category, part=""):
    return keys.record_aad(user.pk, object_id, f"{category}:{part}" if part else category)


def _write_blob(obj, cipher, blob):
    if len(blob) <= INLINE_LIMIT:
        setattr(obj, f"{cipher}_inline", blob)
    else:
        getattr(obj, f"{cipher}_file").save(f"x.{cipher}", ContentFile(blob), save=False)


def _read_blob(obj, cipher):
    inline = getattr(obj, f"{cipher}_inline")
    if inline is not None:
        return bytes(inline)
    field = getattr(obj, f"{cipher}_file")
    if not field:
        raise ce.IntegrityError(f"{cipher} ciphertext is missing")
    try:
        with field.open("rb") as f:
            return f.read()
    except FileNotFoundError as exc:
        raise ce.IntegrityError(f"{cipher} ciphertext file is missing") from exc


def _discard_files(obj):
    for cipher in ce.CIPHERS:
        field = getattr(obj, f"{cipher}_file")
        if field:
            field.storage.delete(field.name)


def _seal_into(user, muk, category, filename, mime, data):
    object_id = uuid.uuid4()
    sealed = sealing.seal(data, muk, _aad(user, object_id, category))
    meta = keys.wrap_dek(
        muk, sealing.dump_json({"filename": filename, "mime": mime}), _aad(user, object_id, category, "meta")
    )
    obj = StoredObject(
        id=object_id,
        owner=user,
        category=category,
        plain_size=len(data),
        wrapped_dek=sealed.wrapped_dek,
        digest=sealed.digest,
        meta=meta,
    )
    try:
        for cipher in ce.CIPHERS:
            _write_blob(obj, cipher, sealed.blobs[cipher])
        obj.save(force_insert=True)
    except Exception:
        _discard_files(obj)
        raise
    return obj


def store_file(user, muk, category, filename, data: bytes) -> StoredObject:
    filename = clean_filename(filename)
    mime = validate_file(category, filename, len(data), data)
    return _seal_into(user, muk, category, filename, mime, data)


def store_profile(user, muk, fields: dict) -> StoredObject:
    """One profile per user; saving again replaces it."""
    payload = sealing.dump_json(fields)
    if len(payload) > PROFILE_MAX:
        raise UploadRejected("Profile data is too large.")
    with transaction.atomic():
        old = list(StoredObject.objects.filter(owner=user, category=PROFILE))
        obj = _seal_into(user, muk, PROFILE, "profile.json", "application/json", payload)
        for item in old:
            _delete(item)
    return obj


def _delete(obj):
    _discard_files(obj)
    obj.delete()


def _get(user, object_id) -> StoredObject:
    try:
        return StoredObject.objects.get(pk=object_id, owner=user)
    except (StoredObject.DoesNotExist, ValueError, TypeError) as exc:
        raise ObjectNotFound(str(object_id)) from exc


def read_meta(user, muk, obj) -> dict:
    raw = keys.unwrap_dek(muk, bytes(obj.meta), _aad(user, obj.id, obj.category, "meta"))
    return json.loads(raw.decode("utf-8"))


def list_entries(user, muk, category=None):
    qs = StoredObject.objects.filter(owner=user)
    if category:
        qs = qs.filter(category=category)
    entries = []
    for obj in qs:
        try:
            meta = read_meta(user, muk, obj)
        except ce.IntegrityError:
            meta = {"filename": "(unreadable)", "mime": ""}
        entries.append(
            {
                "id": obj.id,
                "category": obj.category,
                "label": obj.get_category_display(),
                "filename": meta["filename"],
                "size": obj.plain_size,
                "created_at": obj.created_at,
            }
        )
    return entries


def load_object(user, muk, object_id, cipher="aes") -> LoadedObject:
    if cipher not in ce.CIPHERS:
        raise ValueError(f"unknown cipher {cipher!r}")
    obj = _get(user, object_id)
    t0 = time.perf_counter_ns()
    blob = _read_blob(obj, cipher)
    io_ns = time.perf_counter_ns() - t0
    meta = read_meta(user, muk, obj)
    res = sealing.open_one(
        cipher, blob, bytes(obj.wrapped_dek), bytes(obj.digest), muk, _aad(user, obj.id, obj.category)
    )
    return LoadedObject(
        id=obj.id,
        category=obj.category,
        filename=meta["filename"],
        mime=meta["mime"],
        data=res.plaintext,
        cipher=cipher,
        io_ns=io_ns,
        unwrap_ns=res.unwrap_ns,
        decrypt_ns=res.decrypt_ns,
        verify_ns=res.verify_ns,
    )


def _load_json(user, muk, category, cipher):
    obj = StoredObject.objects.filter(owner=user, category=category).first()
    if obj is None:
        return None
    return json.loads(load_object(user, muk, obj.id, cipher).data.decode("utf-8"))


def load_profile(user, muk, cipher="aes"):
    return _load_json(user, muk, PROFILE, cipher)


def kyc_missing(user):
    have = set(StoredObject.objects.filter(owner=user, category__in=KYC_CATEGORIES).values_list("category", flat=True))
    return [c for c in KYC_CATEGORIES if c not in have]


def store_loan(user, muk, amount: int, purpose: str) -> StoredObject:
    if not LOAN_MIN <= amount <= LOAN_MAX:
        raise LoanRejected(f"Amount must be between {LOAN_MIN:,} and {LOAN_MAX:,}.")
    with transaction.atomic():
        if kyc_missing(user):
            raise LoanRejected("Complete all KYC steps before requesting a loan.")
        if StoredObject.objects.filter(owner=user, category=LOAN).exists():
            raise LoanRejected("You already have a loan request.")
        payload = sealing.dump_json({"amount": amount, "purpose": purpose})
        return _seal_into(user, muk, LOAN, "loan.json", "application/json", payload)


def load_loan(user, muk, cipher="aes"):
    return _load_json(user, muk, LOAN, cipher)


def delete_object(user, object_id) -> None:
    _delete(_get(user, object_id))
