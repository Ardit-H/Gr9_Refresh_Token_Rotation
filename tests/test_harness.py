import pytest

from gr9_refresh_token_rotation.harness.scenarios import concurrent_race, sequential_replay
from gr9_refresh_token_rotation.storage.token_store import InMemoryTokenStore
from gr9_refresh_token_rotation.strategies import (
    AtomicRotationStrategy,
    NaiveRotationStrategy,
    StaticStrategy,
)


@pytest.fixture
def store():
    return InMemoryTokenStore()


async def test_static_replay_is_never_detected(store):
    out = await sequential_replay(StaticStrategy(store), store)
    assert out.attacker_successes == 1
    assert not out.detected and out.legit_survived


@pytest.mark.parametrize("cls", [NaiveRotationStrategy, AtomicRotationStrategy])
@pytest.mark.parametrize("attacker_first", [False, True])
async def test_rotation_detects_sequential_replay(store, cls, attacker_first):
    out = await sequential_replay(cls(store), store, attacker_first=attacker_first)
    assert out.detected and out.family_revoked
    assert not out.legit_survived          # revocation kills the real session too
    assert out.detection_latency_s is not None


async def test_naive_race_forks_silently(store):
    out = await concurrent_race(NaiveRotationStrategy(store), store)
    assert out.attacker_successes == 1 and out.legit_successes == 1
    assert out.forked and not out.detected
    assert out.legit_survived              # nobody notices the attacker


async def test_atomic_race_has_one_winner_and_alerts(store):
    out = await concurrent_race(AtomicRotationStrategy(store), store)
    assert out.attacker_successes + out.legit_successes == 1
    assert out.detected and out.family_revoked and not out.forked


# --- grace window (secondary research question) -----------------------------

from gr9_refresh_token_rotation.harness.scenarios import delayed_replay  # noqa: E402
from gr9_refresh_token_rotation.strategies import GraceWindowStrategy  # noqa: E402


async def test_grace_window_allows_silent_takeover(store):
    s = GraceWindowStrategy(store, grace_window=0.2)
    out = await delayed_replay(s, store, delay=0.0)
    assert out.attacker_successes == 1
    assert not out.detected and out.forked and out.legit_survived


async def test_replay_after_grace_window_is_detected(store):
    s = GraceWindowStrategy(store, grace_window=0.01)
    out = await delayed_replay(s, store, delay=0.05)
    assert out.attacker_successes == 0
    assert out.detected and out.family_revoked


async def test_atomic_has_no_grace_window(store):
    out = await delayed_replay(AtomicRotationStrategy(store), store, delay=0.0)
    assert out.attacker_successes == 0 and out.detected
