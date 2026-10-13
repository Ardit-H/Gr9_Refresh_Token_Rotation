"""Common interface for the refresh-token strategies under study."""

from __future__ import annotations

import secrets
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass

from gr9_refresh_token_rotation.storage.token_store import (
    ACTIVE,
    TokenRecord,
    TokenStore,
    hash_token,
)


@dataclass
class RefreshResult:
    ok: bool
    access_token: str | None = None
    refresh_token: str | None = None
    family_id: str | None = None
    # True when the strategy recognised a reused (already consumed) token.
    reuse_detected: bool = False
    error: str | None = None


class RefreshStrategy(ABC):
    name: str

    def __init__(self, store: TokenStore) -> None:
        self.store = store

    async def issue_initial(self) -> RefreshResult:
        """Start a new token family (the 'login' step)."""
        family_id = uuid.uuid4().hex
        return await self._issue(family_id)

    async def _issue(self, family_id: str) -> RefreshResult:
        refresh = secrets.token_urlsafe(32)
        await self.store.put(TokenRecord(hash_token(refresh), family_id, ACTIVE))
        return RefreshResult(
            ok=True,
            access_token=secrets.token_urlsafe(24),
            refresh_token=refresh,
            family_id=family_id,
        )

    async def _reject_reuse(self, family_id: str) -> RefreshResult:
        """Reuse detected: revoke the whole family (legitimate session too)."""
        await self.store.revoke_family(family_id)
        return RefreshResult(
            ok=False, family_id=family_id, reuse_detected=True, error="reuse_detected"
        )

    @abstractmethod
    async def refresh(self, refresh_token: str) -> RefreshResult: ...