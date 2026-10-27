"""Reproduce CVE-2026-1035 against the project's local Keycloak container.

CVE-2026-1035: with strict refresh-token rotation enabled
(revokeRefreshToken=true, refreshTokenMaxReuse=0), Keycloak's check-then-use
of refresh-token status is not atomic, so concurrent refresh requests using
the same token can each receive a new token pair. This mirrors the
project's own ``naive_rotation`` strategy and its ``concurrent_race``
harness scenario, run here against the real server instead of the
in-process implementation, as external validation of the harness.

Usage:  python experiments/run_keycloak_validation.py [trials] [concurrency]
Requires the keycloak service from docker-compose.yml to be up:
    docker compose up -d keycloak
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from gr9_refresh_token_rotation.metrics.aggregate import wilson_ci
from gr9_refresh_token_rotation.servers.keycloak_client import KeycloakClient

ROOT = Path(__file__).resolve().parents[1]


async def one_trial(client: KeycloakClient, concurrency: int) -> dict:
    login = await client.login()
    if not login.ok:
        raise RuntimeError("login failed; is the realm imported and the user enabled?")
    stolen = login.refresh_token

    gate = asyncio.Event()

    async def attempt():
        await gate.wait()
        return await client.refresh(stolen)

    tasks = [asyncio.create_task(attempt()) for _ in range(concurrency)]
    await asyncio.sleep(0)
    gate.set()
    results = await asyncio.gather(*tasks)

    successes = sum(r.ok for r in results)
    return {
        "successes": successes,
        "forked": successes > 1,  # more than one caller got a fresh token pair
        "statuses": [r.status for r in results],
    }


async def sequential_replay_check(client: KeycloakClient) -> dict:
    login = await client.login()
    first = await client.refresh(login.refresh_token)
    replay = await client.refresh(login.refresh_token)  # stale token reused
    return {"first_ok": first.ok, "replay_ok": replay.ok, "replay_status": replay.status}


async def main() -> None:
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    concurrency = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    client = KeycloakClient()
    try:
        print("Waiting for Keycloak realm...")
        await client.wait_ready()

        seq = await sequential_replay_check(client)
        print(f"sequential replay: first_ok={seq['first_ok']} "
              f"replay_ok={seq['replay_ok']} replay_status={seq['replay_status']}")

        rows = [await one_trial(client, concurrency) for _ in range(trials)]
    finally:
        await client.aclose()

    forked = sum(r["forked"] for r in rows)
    lo, hi = wilson_ci(forked, trials)
    print(f"\n{trials} trials, {concurrency} concurrent refreshes of the same token each")
    print(f"family forked (>1 success): {forked}/{trials} "
          f"({forked / trials:.0%}, 95% CI [{lo:.0%}, {hi:.0%}])")

    # Concurrency 10 is the headline run; other levels go to their own folder.
    out = ROOT / "results" / ("keycloak_validation" if concurrency == 10 else f"keycloak_validation_c{concurrency}")
    out.mkdir(parents=True, exist_ok=True)
    (out / "trials.json").write_text(json.dumps(
        {"trials": trials, "concurrency": concurrency, "forked": forked,
         "fork_rate": forked / trials, "ci95_lo": lo, "ci95_hi": hi,
         "sequential_replay": seq, "race": rows},
        indent=2,
    ))
    print(f"Wrote {out / 'trials.json'}")


if __name__ == "__main__":
    asyncio.run(main())
