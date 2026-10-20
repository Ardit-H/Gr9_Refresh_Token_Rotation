"""Attack scenarios run against a refresh-token strategy.

Each scenario simulates a legitimate client and an attacker who has stolen
the client's current refresh token, and returns a ``TrialOutcome`` with the
security measurements for that single trial.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass

from gr9_refresh_token_rotation.storage.token_store import ACTIVE, TokenStore
from gr9_refresh_token_rotation.strategies import RefreshResult, RefreshStrategy


@dataclass
class TrialOutcome:
    scenario: str
    strategy: str
    attacker_successes: int      # refreshes the attacker got a new token from
    legit_successes: int         # refreshes the legitimate client completed
    reuse_alerts: int            # responses flagged as reuse_detected
    active_tokens: int           # live tokens left in the family (>1 = forked)
    family_revoked: bool
    legit_survived: bool         # legit client can still refresh afterwards
    detection_latency_s: float | None  # scenario start -> first reuse alert

    @property
    def detected(self) -> bool:
        return self.reuse_alerts > 0

    @property
    def forked(self) -> bool:
        return self.active_tokens > 1


class _Actor:
    """A client or attacker: holds a token and records timed refresh results."""

    def __init__(self, strategy: RefreshStrategy, token: str, t0: float) -> None:
        self._strategy = strategy
        self.token = token
        self._t0 = t0
        self.results: list[RefreshResult] = []
        self.alert_times: list[float] = []

    async def refresh(self, token: str | None = None) -> RefreshResult:
        result = await self._strategy.refresh(token or self.token)
        if result.reuse_detected:
            self.alert_times.append(time.perf_counter() - self._t0)
        self.results.append(result)
        if result.ok and result.refresh_token:
            self.token = result.refresh_token
        return result

    @property
    def successes(self) -> int:
        return sum(r.ok for r in self.results)

    @property
    def alerts(self) -> int:
        return sum(r.reuse_detected for r in self.results)


async def _finish(
    scenario: str,
    strategy: RefreshStrategy,
    store: TokenStore,
    family_id: str,
    legit: _Actor,
    attacker: _Actor,
) -> TrialOutcome:
    tokens = await store.family_tokens(family_id)
    active = sum(t.status == ACTIVE for t in tokens)
    revoked = await store.is_family_revoked(family_id)

    # Session survival: can the legitimate client still refresh with the
    # token it holds? (Done last because the probe itself mutates state.)
    probe = await strategy.refresh(legit.token)
    alert_times = sorted(legit.alert_times + attacker.alert_times)

    return TrialOutcome(
        scenario=scenario,
        strategy=strategy.name,
        attacker_successes=attacker.successes,
        legit_successes=legit.successes,
        reuse_alerts=legit.alerts + attacker.alerts,
        active_tokens=active,
        family_revoked=revoked,
        legit_survived=probe.ok,
        detection_latency_s=alert_times[0] if alert_times else None,
    )


async def sequential_replay(
    strategy: RefreshStrategy, store: TokenStore, attacker_first: bool = False
) -> TrialOutcome:
    """Attacker and client use the same stolen token one after the other.

    ``attacker_first=False``: the client rotates, then the attacker replays
    the now-stale token.  ``True``: the attacker rotates first and the client
    is the one presenting a stale token.
    """
    login = await strategy.issue_initial()
    t0 = time.perf_counter()
    legit = _Actor(strategy, login.refresh_token, t0)
    attacker = _Actor(strategy, login.refresh_token, t0)
    stolen = login.refresh_token

    first, second = (attacker, legit) if attacker_first else (legit, attacker)
    await first.refresh(stolen)
    await second.refresh(stolen)

    return await _finish("sequential_replay", strategy, store, login.family_id, legit, attacker)


async def concurrent_race(
    strategy: RefreshStrategy, store: TokenStore
) -> TrialOutcome:
    """Client and attacker present the same token at the same moment."""
    login = await strategy.issue_initial()
    t0 = time.perf_counter()
    legit = _Actor(strategy, login.refresh_token, t0)
    attacker = _Actor(strategy, login.refresh_token, t0)
    stolen = login.refresh_token

    gate = asyncio.Event()

    async def go(actor: _Actor) -> None:
        await gate.wait()
        await actor.refresh(stolen)

    # Random start order so neither side is systematically scheduled first.
    actors = [legit, attacker]
    random.shuffle(actors)
    tasks = [asyncio.create_task(go(a)) for a in actors]
    await asyncio.sleep(0)  # let both tasks reach the gate
    gate.set()
    await asyncio.gather(*tasks)

    return await _finish("concurrent_race", strategy, store, login.family_id, legit, attacker)


async def delayed_replay(
    strategy: RefreshStrategy, store: TokenStore, delay: float = 0.0
) -> TrialOutcome:
    """The client rotates; the attacker replays the stolen token ``delay`` s later.

    Probes whether a grace window lets the attacker in without an alert.
    """
    login = await strategy.issue_initial()
    t0 = time.perf_counter()
    legit = _Actor(strategy, login.refresh_token, t0)
    attacker = _Actor(strategy, login.refresh_token, t0)
    stolen = login.refresh_token

    await legit.refresh(stolen)
    await asyncio.sleep(delay)
    await attacker.refresh(stolen)

    return await _finish("delayed_replay", strategy, store, login.family_id, legit, attacker)


SCENARIOS = {
    "delayed_replay": delayed_replay,
    "sequential_replay": sequential_replay,
    "concurrent_race": concurrent_race,
}
