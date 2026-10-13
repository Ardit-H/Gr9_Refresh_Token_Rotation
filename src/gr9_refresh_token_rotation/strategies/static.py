"""Baseline: the refresh token is never rotated and can be reused forever."""

from __future__ import annotations

import secrets

from .base import RefreshResult, RefreshStrategy
from gr9_refresh_token_rotation.storage.token_store import hash_token


class StaticStrategy(RefreshStrategy):
    name = "static"

    async def refresh(self, refresh_token: str) -> RefreshResult:
        rec = await self.store.get(hash_token(refresh_token))
        if rec is None:
            return RefreshResult(ok=False, error="invalid_token")
        if await self.store.is_family_revoked(rec.family_id):
            return RefreshResult(ok=False, family_id=rec.family_id, error="family_revoked")
        return RefreshResult(
            ok=True,
            access_token=secrets.token_urlsafe(24),
            refresh_token=refresh_token,
            family_id=rec.family_id,
        )