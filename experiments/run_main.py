"""Run the security experiment described by a YAML config.

Usage:  python experiments/run_main.py [experiments/configs/main.yaml]
Writes results/<name>/trials.csv (raw) and results/<name>/summary.json.
"""

from __future__ import annotations

import asyncio
import csv
import dataclasses
import functools
import json
import os
import sys
from pathlib import Path

import yaml

from gr9_refresh_token_rotation.harness.scenarios import SCENARIOS, TrialOutcome
from gr9_refresh_token_rotation.metrics.aggregate import summarize
from gr9_refresh_token_rotation.storage.token_store import (
    InMemoryTokenStore,
    RedisTokenStore,
    TokenStore,
)
from gr9_refresh_token_rotation.strategies import (
    STRATEGIES,
    GraceWindowStrategy,
    NaiveRotationStrategy,
)

ROOT = Path(__file__).resolve().parents[1]


def make_store(cfg: dict) -> tuple[TokenStore, object | None]:
    if cfg.get("backend", "memory") == "redis":
        import redis.asyncio as aioredis

        url = os.environ.get("REDIS_URL", cfg["redis_url"])  # override inside Docker
        client = aioredis.from_url(url, decode_responses=True)
        return RedisTokenStore(client, prefix="gr9exp"), client
    return InMemoryTokenStore(), None


def variants(cfg: dict) -> list[tuple[str, str, dict]]:
    """(label, strategy name, constructor kwargs) for every configured variant."""
    out = []
    for name in cfg["strategies"]:
        if name == NaiveRotationStrategy.name:
            for rw in cfg.get("race_windows", [0]):
                out.append((f"{name}@rw={rw}", name, {"race_window": rw}))
        elif name == GraceWindowStrategy.name:
            for gw in cfg.get("grace_windows", [0.05]):
                out.append((f"{name}@gw={gw}", name, {"grace_window": gw}))
        else:
            out.append((name, name, {}))
    return out


async def run(cfg: dict) -> tuple[list[dict], dict]:
    store, client = make_store(cfg)
    await store.clear()
    rows: list[dict] = []
    summary: dict = {}
    try:
        for label, name, kwargs in variants(cfg):
            strategy = STRATEGIES[name](store, **kwargs)
            for spec in cfg["scenarios"]:
                # A scenario is a name, or {name: ..., <param>: ...} for a parameter.
                params = {} if isinstance(spec, str) else {k: v for k, v in spec.items() if k != "name"}
                base = spec if isinstance(spec, str) else spec["name"]
                scenario_name = base + "".join(f"@{v}" for v in params.values())
                scenario = functools.partial(SCENARIOS[base], **params)
                outcomes: list[TrialOutcome] = []
                for trial in range(cfg["trials"]):
                    o = await scenario(strategy, store)
                    outcomes.append(o)
                    rows.append({"variant": label, "trial": trial, **dataclasses.asdict(o)})
                summary[f"{label}/{scenario_name}"] = summarize(outcomes)
                print(f"{label:28s} {scenario_name:18s} "
                      f"attacker={summary[f'{label}/{scenario_name}']['attacker_success_rate']:.2f} "
                      f"detect={summary[f'{label}/{scenario_name}']['reuse_detection_rate']:.2f} "
                      f"fork={summary[f'{label}/{scenario_name}']['family_fork_rate']:.2f}")
    finally:
        await store.clear()
        if client is not None:
            await client.aclose()
    return rows, summary


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "experiments/configs/main.yaml"
    cfg = yaml.safe_load(path.read_text())
    rows, summary = asyncio.run(run(cfg))

    out = ROOT / "results" / cfg["name"]
    out.mkdir(parents=True, exist_ok=True)
    with (out / "trials.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
