"""Secondary research question, against real Hydra: does its refresh-token
reuse grace period enable a silent token-family takeover?

Mirrors experiments/configs/grace.yaml's delayed_replay scenario against
the project's own grace_rotation strategy, but here against Ory Hydra's
own oauth2.grant.refresh_token.rotation_grace_period setting.

Requires Hydra to be started with a non-zero grace period, e.g.:
    HYDRA_GRACE_PERIOD=5s docker compose up -d hydra
(0s, the compose default, is strict rotation and should reject every delay.)

Usage:  python experiments/run_hydra_grace_validation.py [delays...]
Delays are in seconds, e.g.: python experiments/run_hydra_grace_validation.py 1 3 6
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

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
    delays = [float(x) for x in sys.argv[1:]] or [0.5, 2.0, 5.0, 8.0]

    client = HydraClient()
    try:
        print("Waiting for Hydra...")
        await client.wait_ready()
        rows = [await delayed_replay(client, d) for d in delays]
    finally:
        await client.aclose()

    print(f"\n{'delay (s)':>10}  {'attacker ok':>12}  {'legit survived':>15}")
    for r in rows:
        print(f"{r['delay_s']:>10}  {str(r['attacker_succeeded']):>12}  {str(r['legit_survived']):>15}")

    out = ROOT / "results" / "hydra_grace_validation"
    out.mkdir(parents=True, exist_ok=True)
    (out / "trials.json").write_text(json.dumps(rows, indent=2))
    print(f"\nWrote {out / 'trials.json'}")


if __name__ == "__main__":
    asyncio.run(main())