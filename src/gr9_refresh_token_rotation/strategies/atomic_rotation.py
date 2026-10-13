"""Atomic rotation: consume the token with a single compare-and-set."""

from __future__ import annotations

from .base import RefreshResult, RefreshStrategy
from gr9_refresh_token_rotation.storage.token_store import ACTIVE, USED, hash_token


class AtomicRotationStrategy(RefreshStrategy):
    name = "atomic_rotation"

    async def refresh(self, refresh_token: str) -> RefreshResult:
        token_hash = hash_token(refresh_token)

        # Only one concurrent caller can flip ACTIVE -> USED.
        if await self.store.compare_and_set_status(token_hash, ACTIVE, USED):
            rec = await self.store.get(token_hash)
            if await self.store.is_family_revoked(rec.family_id):
                return RefreshResult(ok=False, family_id=rec.family_id, error="family_revoked")
            return await self._issue(rec.family_id)

        rec = await self.store.get(token_hash)
        if rec is None:
            return RefreshResult(ok=False, error="invalid_token")
        if await self.store.is_family_revoked(rec.family_id):
            return RefreshResult(ok=False, family_id=rec.family_id, error="family_revoked")
        return await self._reject_reuse(rec.family_id)