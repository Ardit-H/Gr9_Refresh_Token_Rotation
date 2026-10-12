"""Runs only when a Redis server is reachable (REDIS_URL, default localhost)."""

import asyncio
import os

import pytest
import redis.asyncio as aioredis

from gr9_refresh_token_rotation.storage.token_store import RedisTokenStore
from gr9_refresh_token_rotation.strategies import AtomicRotationStrategy


@pytest.fixture
async def store():
    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    client = aioredis.from_url(url, decode_responses=True)
    try:
        await client.ping()
    except Exception:
        await client.aclose()
        pytest.skip("Redis not available")
    s = RedisTokenStore(client, prefix="gr9test")
    await s.clear()
    yield s
    await s.clear()
    await client.aclose()


async def test_redis_cas_has_single_winner(store):
    s = AtomicRotationStrategy(store)
    login = await s.issue_initial()

    results = await asyncio.gather(*(s.refresh(login.refresh_token) for _ in range(20)))

    assert sum(r.ok for r in results) == 1
    assert await store.is_family_revoked(login.family_id)
