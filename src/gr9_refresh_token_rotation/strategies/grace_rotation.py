"""Atomic rotation plus a reuse grace window.

Many servers tolerate a just-rotated token being presented again for a short
time, so a client that lost the response to a refresh can retry safely.
Here the first caller consumes the token with a compare-and-set; a later
caller presenting the same token within ``grace_window`` seconds is treated
as a benign retry and is issued a fresh token in the same family, with no
reuse alert. Outside the window the token is treated as stolen and the
family is revoked.

The side effect under study: an attacker holding a stolen token can use it
inside the window and silently obtain a valid token (family takeover).
"""

from __future__ import annotations

import time
from collections.abc import Callable

from .base import RefreshResult, RefreshStrategy
from gr9_refresh_token_rotation.storage.token_store import (
    ACTIVE,
    USED,
    TokenStore,
    hash_token,
)


class GraceWindowStrategy(RefreshStrategy):
    name = "grace_rotation"

    def __init__(
        self,
        store: TokenStore,
        grace_window: float = 0.05,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(store)
        self.grace_window = grace_window
        self._clock = clock

    async def refresh(self, refresh_token: str) -> RefreshResult:
        token_hash = hash_token(refresh_token)

        if await self.store.compare_and_set_status(token_hash, ACTIVE, USED):
            await self.store.set_used_at(token_hash, self._clock())
            rec = await self.store.get(token_hash)
            if await self.store.is_family_revoked(rec.family_id):
                return RefreshResult(ok=False, family_id=rec.family_id, error="family_revoked")
            return await self._issue(rec.family_id)

        rec = await self.store.get(token_hash)
        if rec is None:
            return RefreshResult(ok=False, error="invalid_token")
        if await self.store.is_family_revoked(rec.family_id):
            return RefreshResult(ok=False, family_id=rec.family_id, error="family_revoked")

        # used_at is None only while the winner is still between its
        # compare-and-set and its timestamp write, i.e. a concurrent retry.
        if rec.status == USED and (
            rec.used_at is None or self._clock() - rec.used_at <= self.grace_window
        ):
            return await self._issue(rec.family_id)  # silent: no alert, no revoke
        return await self._reject_reuse(rec.family_id)
