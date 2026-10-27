"""Secondary research question, against real Hydra: does its refresh-token
reuse grace period enable a silent token-family takeover?

Mirrors experiments/configs/grace.yaml's delayed_replay scenario against
the project's own grace_rotation strategy, but here against Ory Hydra's
own oauth2.grant.refresh_token.rotation_grace_period setting.

Requires Hydra to be started with a non-zero grace period, e.g.:
    HYDRA_GRACE_PERIOD=5s docker compose up -d hydra
(0s, the compose default, is strict rotation and should reject every delay.)

Usage:  python experiments/run_hydra_grace_validation.py [--trials N] [delays...]
Delays are in seconds, e.g.:
    python experiments/run_hydra_grace_validation.py --trials 20 1 3 6
Each delay is repeated N times (default 20); rates get a 95% Wilson CI.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from gr9_refresh_token_rotation.metrics.aggregate import rate_with_ci
from gr9_refresh_token_rotation.servers.hydra_client import HydraClient

ROOT = Path(__file__).resolve().parents[1]


async def delayed_replay(client: HydraClient, delay: float) -> dict:
    """Client rotates; the attacker replays the stolen token `delay` s later."""
    login = await client.login()
    stolen = login.refresh_token

    legit_first = await client.refresh(stolen)
    await asyncio.sleep(delay)
    attacker_replay = await client.refresh(stolen)

    # Session survival: can the legitimate client still refresh its own
    # (correctly rotated) token after the attacker's replay attempt?
    legit_survived = (await client.refresh(legit_first.refresh_token)).ok if legit_first.ok else False

    return {
        "delay_s": delay,
        "attacker_succeeded": attacker_replay.ok,  # silent takeover if True
        "attacker_status": attacker_replay.status,
        "legit_survived": legit_survived,
    }


async def main() -> None:
    args = sys.argv[1:]
    trials = 20
    if "--trials" in args:
        k = args.index("--trials")
        trials = int(args[k + 1])
        del args[k:k + 2]
    delays = [float(x) for x in args] or [1.0, 3.0, 6.0]

    client = HydraClient()
    try:
        print("Waiting for Hydra...")
        await client.wait_ready()
        rows = []
        for d in delays:
            for _ in range(trials):
                rows.append(await delayed_replay(client, d))
    finally:
        await client.aclose()

    summary = []
    print(f"\n{'delay (s)':>10}  {'silent takeover':>24}  {'legit survived':>24}")
    for d in delays:
        g = [r for r in rows if r["delay_s"] == d]
        att = rate_with_ci(sum(r["attacker_succeeded"] for r in g), len(g))
        surv = rate_with_ci(sum(r["legit_survived"] for r in g), len(g))
        summary.append({"delay_s": d, "trials": len(g),
                        "silent_takeover": att, "legit_survived": surv})
        print(f"{d:>10}  {att['rate']:>7.0%} [{att['ci95_lo']:.0%}, {att['ci95_hi']:.0%}]"
              f"       {surv['rate']:>7.0%} [{surv['ci95_lo']:.0%}, {surv['ci95_hi']:.0%}]")

    out = ROOT / "results" / "hydra_grace_validation"
    out.mkdir(parents=True, exist_ok=True)
    (out / "trials.json").write_text(json.dumps(rows, indent=2))
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    asyncio.run(main())