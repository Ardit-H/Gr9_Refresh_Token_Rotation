"""Naive rotation: check the token state, then update it in a separate step.

The check and the update are two distinct store operations (a classic
time-of-check-to-time-of-use pattern), so two concurrent requests can both
see the token as ``active`` and both succeed, forking the token family.
``race_window`` (seconds) widens the gap between the two steps to make the
race reproducible in the harness; 0 still yields to the event loop once.
"""

from __future__ import annotations

import asyncio

from .base import RefreshResult, RefreshStrategy
from gr9_refresh_token_rotation.storage.token_store import (
    ACTIVE,
    USED,
    TokenStore,
    hash_token,
)


class NaiveRotationStrategy(RefreshStrategy):
    name = "naive_rotation"

    def __init__(self, store: TokenStore, race_window: float = 0.0) -> None:
        super().__init__(store)
        self.race_window = race_window

    async def refresh(self, refresh_token: str) -> RefreshResult:
        token_hash = hash_token(refresh_token)

        # 1. CHECK
        rec = await self.store.get(token_hash)
        if rec is None:
            return RefreshResult(ok=False, error="invalid_token")
        if await self.store.is_family_revoked(rec.family_id):
            return RefreshResult(ok=False, family_id=rec.family_id, error="family_revoked")
        if rec.status != ACTIVE:
            return await self._reject_reuse(rec.family_id)

        await asyncio.sleep(self.race_window)  # vulnerable window

        # 2. USE (unconditional write: does not re-check the state)
        await self.store.set_status(token_hash, USED)
        return await self._issue(rec.family_id)