from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any


@dataclass(frozen=True)
class CacheEntry:
    value: str
    expires_at: datetime


class SemanticCache:
    """Authorization-scoped cache. This local version uses normalized exact semantics."""

    def __init__(self, ttl_seconds: int = 300) -> None:
        self._ttl = timedelta(seconds=ttl_seconds)
        self._entries: dict[str, CacheEntry] = {}
        self._lock = Lock()

    @staticmethod
    def _key(
        *, workspace_id: str, user_id: str, authorization_context: set[str], prompt: str
    ) -> str:
        payload = {
            "workspace_id": workspace_id,
            "user_id": user_id,
            "authorization_context": sorted(authorization_context),
            "prompt": " ".join(prompt.lower().split()),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def get(self, **context: Any) -> str | None:
        key = self._key(**context)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_at <= datetime.now(UTC):
                del self._entries[key]
                return None
            return entry.value

    def put(self, *, value: str, sensitive: bool = False, **context: Any) -> bool:
        if sensitive:
            return False
        key = self._key(**context)
        with self._lock:
            self._entries[key] = CacheEntry(value=value, expires_at=datetime.now(UTC) + self._ttl)
        return True
