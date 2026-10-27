import threading
import time

from django.conf import settings

DEFAULT_TTL_SECONDS = 3600


class Keyring:
    def __init__(self, ttl=None, clock=time.monotonic):
        self._ttl = ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._items = {}

    @property
    def ttl(self) -> float:
        if self._ttl is not None:
            return self._ttl
        return getattr(settings, "VAULT_KEY_TTL_SECONDS", DEFAULT_TTL_SECONDS)

    def put(self, session_key: str, muk: bytes) -> None:
        with self._lock:
            self._purge()
            self._items[session_key] = (muk, self._clock() + self.ttl)

    def get(self, session_key):
        if not session_key:
            return None
        with self._lock:
            self._purge()
            item = self._items.get(session_key)
            if item is None:
                return None
            self._items[session_key] = (item[0], self._clock() + self.ttl)
            return item[0]

    def drop(self, session_key) -> None:
        with self._lock:
            self._items.pop(session_key, None)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        with self._lock:
            self._purge()
            return len(self._items)

    def _purge(self) -> None:
        now = self._clock()
        for key in [k for k, (_, exp) in self._items.items() if exp <= now]:
            del self._items[key]


keyring = Keyring()
