import asyncio

import pytest

from gr9_refresh_token_rotation.storage.token_store import InMemoryTokenStore
from gr9_refresh_token_rotation.strategies import (
    AtomicRotationStrategy,
    NaiveRotationStrategy,
    StaticStrategy,
)


@pytest.fixture
def store():
    return InMemoryTokenStore()


async def _race(strategy, token, n=2):
    return await asyncio.gather(*(strategy.refresh(token) for _ in range(n)))


# --- static -----------------------------------------------------------------

async def test_static_token_is_reusable(store):
    s = StaticStrategy(store)
    login = await s.issue_initial()
    for _ in range(3):
        r = await s.refresh(login.refresh_token)
        assert r.ok and r.refresh_token == login.refresh_token


async def test_static_unknown_token_rejected(store):
    r = await StaticStrategy(store).refresh("nope")
    assert not r.ok and r.error == "invalid_token"


# --- sequential behaviour (naive and atomic must agree) ---------------------

@pytest.mark.parametrize("cls", [NaiveRotationStrategy, AtomicRotationStrategy])
async def test_rotation_issues_new_token_and_detects_reuse(store, cls):
    s = cls(store)
    login = await s.issue_initial()

    first = await s.refresh(login.refresh_token)
    assert first.ok and first.refresh_token != login.refresh_token

    replay = await s.refresh(login.refresh_token)  # old token reused
    assert not replay.ok and replay.reuse_detected

    # Reuse detection revokes the family: the legitimate successor dies too.
    survivor = await s.refresh(first.refresh_token)
    assert not survivor.ok and survivor.error == "family_revoked"


# --- concurrency: the difference the project is about -----------------------

async def test_naive_race_forks_the_family(store):
    s = NaiveRotationStrategy(store)
    login = await s.issue_initial()

    results = await _race(s, login.refresh_token)

    assert sum(r.ok for r in results) == 2          # both consumed the same token
    assert not any(r.reuse_detected for r in results)  # and no alert was raised
    assert len({r.refresh_token for r in results}) == 2  # two valid successors


async def test_atomic_race_allows_exactly_one_winner(store):
    s = AtomicRotationStrategy(store)
    login = await s.issue_initial()

    results = await _race(s, login.refresh_token, n=10)

    assert sum(r.ok for r in results) == 1
    # The first loser raises the alert and revokes the family; later losers
    # then see "family_revoked", so the alert fires exactly once.
    assert sum(r.reuse_detected for r in results) == 1
    assert sum(r.error == "family_revoked" for r in results) == 8
    assert await store.is_family_revoked(login.family_id)