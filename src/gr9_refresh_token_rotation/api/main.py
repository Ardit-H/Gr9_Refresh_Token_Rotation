"""Authentication service under test.

Run: uvicorn gr9_refresh_token_rotation.api.main:app
Set REDIS_URL to use Redis; otherwise an in-memory store is used.
Set RACE_WINDOW (seconds) to widen the naive strategy's check/use gap.
Set GRACE_WINDOW (seconds) for the grace-window strategy's reuse tolerance.
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from gr9_refresh_token_rotation.storage.token_store import (
    InMemoryTokenStore,
    RedisTokenStore,
    TokenStore,
)
from gr9_refresh_token_rotation.strategies import (
    AtomicRotationStrategy,
    GraceWindowStrategy,
    NaiveRotationStrategy,
    StaticStrategy,
)

from .routes import router


def create_app(
    store: TokenStore | None = None, race_window: float = 0.0, grace_window: float = 0.05
) -> FastAPI:
    if store is None:
        redis_url = os.environ.get("REDIS_URL")
        if redis_url:
            import redis.asyncio as aioredis

            store = RedisTokenStore(aioredis.from_url(redis_url, decode_responses=True))
        else:
            store = InMemoryTokenStore()

    app = FastAPI(title="Gr9 refresh-token service")
    app.state.store = store
    app.state.strategies = {
        StaticStrategy.name: StaticStrategy(store),
        NaiveRotationStrategy.name: NaiveRotationStrategy(store, race_window),
        AtomicRotationStrategy.name: AtomicRotationStrategy(store),
        GraceWindowStrategy.name: GraceWindowStrategy(store, grace_window),
    }
    app.include_router(router)
    return app


app = create_app(
    race_window=float(os.environ.get("RACE_WINDOW", "0")),
    grace_window=float(os.environ.get("GRACE_WINDOW", "0.05")),
)
