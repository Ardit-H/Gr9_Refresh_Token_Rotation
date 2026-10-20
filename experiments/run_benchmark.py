"""Benchmark /refresh latency, throughput, and resource usage over HTTP.

Usage:  python experiments/run_benchmark.py [experiments/configs/bench.yaml]
Starts the FastAPI service in a subprocess, drives it with N concurrent
clients (each rotating its own token family, so there is no contention on a
single token), and writes results/<name>/bench.csv (raw) and bench_summary.csv/json (median over repeats).

CPU/memory sampling of the server process requires psutil; if it is not
installed, the benchmark still runs and those columns are simply omitted.
"""

from __future__ import annotations

import asyncio
import csv
import json
import os
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import yaml

from gr9_refresh_token_rotation.metrics.aggregate import percentile

try:
    import psutil
except ImportError:
    psutil = None

ROOT = Path(__file__).resolve().parents[1]


class ResourceSampler:
    """Samples a process's CPU% and RSS memory on a background thread while
    a benchmark call is in flight. psutil's cpu_percent() is blocking and
    needs a priming call plus a polling interval, so this runs off the
    asyncio event loop entirely rather than interleaving with it."""

    def __init__(self, pid: int, interval: float = 0.05) -> None:
        self._samples: list[tuple[float, int]] = []  # (cpu_percent, rss_bytes)
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._proc = psutil.Process(pid) if psutil else None

    def __enter__(self) -> "ResourceSampler":
        if self._proc is not None:
            self._proc.cpu_percent(interval=None)  # prime; first call is meaningless
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._thread is not None:
            self._stop.set()
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                cpu = self._proc.cpu_percent(interval=None)
                rss = self._proc.memory_info().rss
                self._samples.append((cpu, rss))
            except psutil.NoSuchProcess:
                break
            time.sleep(self._interval)

    def summary(self) -> dict:
        if not self._samples:
            return {"cpu_pct_mean": None, "cpu_pct_max": None,
                     "rss_mb_mean": None, "rss_mb_max": None}
        cpus = [c for c, _ in self._samples]
        rss_mb = [r / (1024 * 1024) for _, r in self._samples]
        return {
            "cpu_pct_mean": sum(cpus) / len(cpus),
            "cpu_pct_max": max(cpus),
            "rss_mb_mean": sum(rss_mb) / len(rss_mb),
            "rss_mb_max": max(rss_mb),
        }


def start_server(cfg: dict) -> subprocess.Popen:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    if cfg["backend"] == "redis":
        env["REDIS_URL"] = cfg["redis_url"]
    else:
        env.pop("REDIS_URL", None)
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "gr9_refresh_token_rotation.api.main:app",
         "--port", str(cfg["port"]), "--log-level", "warning"],
        env=env,
    )


async def wait_ready(base: str, timeout: float = 20.0) -> None:
    async with httpx.AsyncClient(base_url=base) as c:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if (await c.get("/health")).status_code == 200:
                    return
            except httpx.TransportError:
                pass
            await asyncio.sleep(0.2)
    raise RuntimeError("server did not become ready")


async def client_loop(c: httpx.AsyncClient, strategy: str, n: int, latencies: list, errors: list):
    token = (await c.post("/login", params={"strategy": strategy})).json()["refresh_token"]
    for _ in range(n):
        t = time.perf_counter()
        r = await c.post("/refresh", params={"strategy": strategy}, json={"refresh_token": token})
        latencies.append(time.perf_counter() - t)
        if r.status_code != 200:
            errors.append(r.status_code)
            return
        token = r.json()["refresh_token"]


async def measure(base: str, strategy: str, clients: int, n: int, server_pid: int) -> dict:
    latencies: list[float] = []
    errors: list[int] = []
    limits = httpx.Limits(max_connections=clients, max_keepalive_connections=clients)
    with ResourceSampler(server_pid) as sampler:
        async with httpx.AsyncClient(base_url=base, limits=limits, timeout=30) as c:
            start = time.perf_counter()
            await asyncio.gather(*(client_loop(c, strategy, n, latencies, errors) for _ in range(clients)))
            elapsed = time.perf_counter() - start
    ms = [x * 1000 for x in latencies]
    return {
        "strategy": strategy,
        "clients": clients,
        "requests": len(latencies),
        "errors": len(errors),
        "throughput_rps": len(latencies) / elapsed,
        "p50_ms": percentile(ms, 50),
        "p95_ms": percentile(ms, 95),
        "p99_ms": percentile(ms, 99),
        "mean_ms": sum(ms) / len(ms),
        **sampler.summary(),
    }


async def run(cfg: dict) -> tuple[list[dict], list[dict]]:
    if psutil is None:
        print("psutil not installed: CPU/memory columns will be empty "
              "(pip install psutil to enable them).")
    base = f"http://127.0.0.1:{cfg['port']}"
    server = start_server(cfg)
    rows: list[dict] = []
    try:
        await wait_ready(base)
        for strategy in cfg["strategies"]:
            await measure(base, strategy, 1, cfg["warmup_requests"], server.pid)  # warm-up, discarded
        # Interleave strategies within each repeat so machine drift hits all equally.
        for rep in range(cfg.get("repeats", 1)):
            for strategy in cfg["strategies"]:
                for clients in cfg["concurrency"]:
                    row = {"rep": rep,
                           **await measure(base, strategy, clients, cfg["requests_per_client"], server.pid)}
                    rows.append(row)
                    cpu = f"{row['cpu_pct_mean']:.0f}" if row["cpu_pct_mean"] is not None else "n/a"
                    rss = f"{row['rss_mb_mean']:.0f}" if row["rss_mb_mean"] is not None else "n/a"
                    print(f"rep={rep} {strategy:16s} clients={clients:3d} rps={row['throughput_rps']:7.1f} "
                          f"p50={row['p50_ms']:6.2f} p99={row['p99_ms']:7.2f} ms errors={row['errors']} "
                          f"cpu={cpu}% rss={rss}MB")
    finally:
        server.terminate()
        server.wait(timeout=10)
    return rows, summarize_reps(rows)


def summarize_reps(rows: list[dict]) -> list[dict]:
    """Median (and min/max) across repeats for each strategy x client count."""
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault((r["strategy"], r["clients"]), []).append(r)
    out = []
    for (strategy, clients), g in groups.items():
        entry = {"strategy": strategy, "clients": clients, "repeats": len(g),
                 "errors": sum(r["errors"] for r in g)}
        for key in ("throughput_rps", "p50_ms", "p95_ms", "p99_ms",
                    "cpu_pct_mean", "cpu_pct_max", "rss_mb_mean", "rss_mb_max"):
            vals = [r[key] for r in g if r.get(key) is not None]
            if not vals:
                entry[f"{key}_median"] = entry[f"{key}_min"] = entry[f"{key}_max"] = None
                continue
            entry[f"{key}_median"] = statistics.median(vals)
            entry[f"{key}_min"] = min(vals)
            entry[f"{key}_max"] = max(vals)
        out.append(entry)
    return out


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "experiments/configs/bench.yaml"
    cfg = yaml.safe_load(path.read_text())
    rows, summary = asyncio.run(run(cfg))
    out = ROOT / "results" / cfg["name"]
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / "bench.csv", rows)
    write_csv(out / "bench_summary.csv", summary)
    (out / "bench_summary.json").write_text(json.dumps(summary, indent=2))

    print("\nMedian [min-max] over repeats:")
    for e in summary:
        cpu = f"{e['cpu_pct_mean_median']:.0f}%" if e["cpu_pct_mean_median"] is not None else "n/a"
        rss = f"{e['rss_mb_mean_median']:.0f}MB" if e["rss_mb_mean_median"] is not None else "n/a"
        print(f"{e['strategy']:16s} clients={e['clients']:3d} "
              f"p50={e['p50_ms_median']:6.2f} [{e['p50_ms_min']:.2f}-{e['p50_ms_max']:.2f}] "
              f"p99={e['p99_ms_median']:7.2f} [{e['p99_ms_min']:.1f}-{e['p99_ms_max']:.1f}] "
              f"rps={e['throughput_rps_median']:6.1f} [{e['throughput_rps_min']:.0f}-{e['throughput_rps_max']:.0f}] "
              f"cpu={cpu} rss={rss}")
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()