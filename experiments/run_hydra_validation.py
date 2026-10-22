"""Check refresh-token rotation behaviour against the project's local Hydra.

Hydra's strict mode (rotation_grace_period: 0s, the default in
infra/docker/hydra/hydra.yml) is the counterpart to Keycloak's
refreshTokenMaxReuse=0 in run_keycloak_validation.py: a rotated-out token
should be rejected, and only one of several concurrent refreshes of the
same token should succeed.

Usage:  python experiments/run_hydra_validation.py [trials] [concurrency]
Requires the hydra service from docker-compose.yml to be up:
    docker compose up -d hydra
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from gr9_refresh_token_rotation.metrics.aggregate import wilson_ci
from gr9_refresh_token_rotation.servers.hydra_client import HydraClient

ROOT = Path(__file__).resolve().parents[1]


async def one_trial(client: HydraClient, concurrency: int) -> dict:
    login = await client.login()
    if not login.ok:
        raise RuntimeError(f"login failed: {login.error}")
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
    return {"successes": successes, "forked": successes > 1,
            "statuses": [r.status for r in results]}


async def sequential_replay_check(client: HydraClient) -> dict:
    login = await client.login()
    first = await client.refresh(login.refresh_token)
    replay = await client.refresh(login.refresh_token)  # stale token reused
    return {"first_ok": first.ok, "replay_ok": replay.ok, "replay_status": replay.status}


async def main() -> None:
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    concurrency = int(sys.argv[2]) if len(sys.argv) > 2 else 2

    client = HydraClient()
    try:
        print("Waiting for Hydra...")
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

    out = ROOT / "results" / "hydra_validation"
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
