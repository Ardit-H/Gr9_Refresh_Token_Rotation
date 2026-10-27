"""Run the proposal's four scenarios against a real authorization server.

Same two-party setup as harness/scenarios.py (a legitimate client and an
attacker holding a copy of the same refresh token), but over HTTP against
Keycloak or Ory Hydra:

  sequential_replay      client refreshes first, attacker replays
  attacker_first_replay  attacker refreshes first, client presents stale token
  concurrent_race        both refresh the same token at the same instant
  delayed_replay         attacker replays DELAY s after the client's rotation

A real server does not report "reuse detected" to the caller, so detection
is observed from its effect: after the stale token is presented, the token
that *did* rotate successfully stops working (the server revoked the
session/family). For each trial we record:
  attacker_ok      attacker got a new token in the scenario
  legit_ok         client got a new token in the scenario
  forked           both got one (the single token yielded two successors)
  revoked          a previously valid successor was killed after the reuse
  legit_survived   the client can still refresh afterwards
  attacker_survived  the attacker can still refresh afterwards (the two
                   probes run in random order, since after a fork a server
                   may keep only the chain that is used first)
  attacker_tokens  access tokens the attacker obtained: scenario + up to 3
                   further refreshes with its own token

Usage:  python experiments/run_server_scenarios.py keycloak|hydra [trials] [delay_s]
Writes results/<server>_scenarios/trials.json and summary.json.
"""

from __future__ import annotations

import asyncio
import json
import random
import sys
from pathlib import Path

from gr9_refresh_token_rotation.metrics.aggregate import rate_with_ci

ROOT = Path(__file__).resolve().parents[1]
FOLLOW_UPS = 3


def make_client(server: str):
    if server == "keycloak":
        from gr9_refresh_token_rotation.servers.keycloak_client import KeycloakClient
        return KeycloakClient()
    if server == "hydra":
        from gr9_refresh_token_rotation.servers.hydra_client import HydraClient
        return HydraClient()
    raise SystemExit(f"unknown server '{server}' (use keycloak or hydra)")


async def still_works(client, token: str | None) -> tuple[bool, str | None]:
    """Refresh once; returns (ok, new token). Used as the survival probe."""
    if not token:
        return False, None
    r = await client.refresh(token)
    return r.ok, (r.refresh_token if r.ok else None)


async def follow_ups(client, token: str | None) -> int:
    n = 0
    for _ in range(FOLLOW_UPS):
        ok, token = await still_works(client, token)
        if not ok:
            break
        n += 1
    return n


async def one_trial(client, scenario: str, delay: float) -> dict:
    login = await client.login()
    if not login.ok:
        raise RuntimeError(f"login failed: {login.error}")
    stolen = login.refresh_token

    if scenario == "concurrent_race":
        gate = asyncio.Event()

        async def go():
            await gate.wait()
            return await client.refresh(stolen)

        order = ["legit", "attacker"]
        random.shuffle(order)
        tasks = {who: asyncio.create_task(go()) for who in order}
        await asyncio.sleep(0)
        gate.set()
        legit, attacker = await tasks["legit"], await tasks["attacker"]
    elif scenario == "attacker_first_replay":
        attacker = await client.refresh(stolen)
        legit = await client.refresh(stolen)
    else:  # sequential_replay / delayed_replay: client rotates first
        legit = await client.refresh(stolen)
        if scenario == "delayed_replay":
            await asyncio.sleep(delay)
        attacker = await client.refresh(stolen)

    # Detection by its effect: whoever rotated successfully, is their new
    # token still accepted after the other party presented the stale one?
    # After a fork, a server may keep only the chain that is used first, so
    # the order of the two probes is randomized per trial.
    attacker_probed_first = random.random() < 0.5
    attacker_tokens = int(attacker.ok)
    if attacker_probed_first and attacker.ok:
        attacker_tokens += await follow_ups(client, attacker.refresh_token)
    legit_survived, _ = await still_works(client, legit.refresh_token)
    if not attacker_probed_first and attacker.ok:
        attacker_tokens += await follow_ups(client, attacker.refresh_token)

    one_ok = legit.ok != attacker.ok
    winner_alive = legit_survived if legit.ok else attacker_tokens > 1
    return {
        "scenario": scenario,
        "attacker_ok": attacker.ok,
        "legit_ok": legit.ok,
        "forked": legit.ok and attacker.ok,
        "revoked": one_ok and not winner_alive,
        "legit_survived": legit_survived,
        "attacker_survived": attacker_tokens > 1,
        "attacker_tokens": attacker_tokens,
        "attacker_probed_first": attacker_probed_first,
        "statuses": {"legit": legit.status, "attacker": attacker.status},
    }


def summarize(rows: list[dict]) -> dict:
    n = len(rows)
    out = {"trials": n}
    for key in ("attacker_ok", "forked", "revoked", "legit_survived", "attacker_survived"):
        out[key] = rate_with_ci(sum(r[key] for r in rows), n)
    out["mean_attacker_tokens"] = sum(r["attacker_tokens"] for r in rows) / n
    # After a fork: which chain survives, split by who refreshed again first.
    for first in (True, False):
        g = [r for r in rows if r["forked"] and r["attacker_probed_first"] == first]
        out[f"forked_attacker_first={first}"] = {
            "n": len(g),
            "attacker_survived": sum(r["attacker_survived"] for r in g),
            "legit_survived": sum(r["legit_survived"] for r in g),
        }
    return out


async def main() -> None:
    server = sys.argv[1] if len(sys.argv) > 1 else "keycloak"
    trials = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    delay = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
    scenarios = ["sequential_replay", "attacker_first_replay",
                 "concurrent_race", "delayed_replay"]

    client = make_client(server)
    rows: list[dict] = []
    try:
        print(f"Waiting for {server}...")
        await client.wait_ready()
        for sc in scenarios:
            for _ in range(trials):
                rows.append(await one_trial(client, sc, delay))
    finally:
        await client.aclose()

    summary = {"server": server, "delay_s": delay, "follow_ups": FOLLOW_UPS}
    for sc in scenarios:
        s = summarize([r for r in rows if r["scenario"] == sc])
        summary[sc] = s
        print(f"{sc:22s} attacker={s['attacker_ok']['rate']:.2f} "
              f"fork={s['forked']['rate']:.2f} revoked={s['revoked']['rate']:.2f} "
              f"legit_survived={s['legit_survived']['rate']:.2f} "
              f"attacker_tokens={s['mean_attacker_tokens']:.2f}")

    out = ROOT / "results" / f"{server}_scenarios"
    out.mkdir(parents=True, exist_ok=True)
    (out / "trials.json").write_text(json.dumps(rows, indent=2))
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"Wrote {out}")


if __name__ == "__main__":
    asyncio.run(main())
