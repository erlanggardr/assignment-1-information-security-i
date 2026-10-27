from django.core.cache import cache
from django.test import Client, override_settings

no_manifest = override_settings(
    STORAGES={
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }
)


def new_client():
    # allauth rate-limits signups per ip and tests sign up a lot
    cache.clear()
    return Client(HTTP_HOST="127.0.0.1")


def signup(client, username, password):
    return client.post(
        "/accounts/signup/", {"username": username, "password1": password, "password2": password}
    )


def login(client, username, password):
    return client.post("/accounts/login/", {"login": username, "password": password})
