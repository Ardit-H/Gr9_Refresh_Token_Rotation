# Gr9 — Refresh-Token Lifecycle Security Under Concurrent Compromise

Information Security seminar project (Group 9) investigating how different
OAuth 2.0 / JWT refresh-token rotation strategies behave under **concurrent**
refresh requests, and what that means for reuse detection, legitimate-session
survival, and performance after a token has been compromised.

> Full project proposal: [`docs/proposal/proposal.tex`](docs/proposal/proposal.tex)

## Research question

> How do different refresh-token rotation strategies affect reuse detection,
> legitimate-session survival, and performance under concurrent refresh
> requests?

**Secondary question:** does a configured grace window enable a silent
token-family takeover, with no reuse alert raised?

## What this project does

1. Implements a small authentication service with three interchangeable
   refresh-token strategies: **static**, **naive rotation** (non-atomic
   read-then-write), and **atomic rotation** (compare-and-set).
2. Runs a Python test harness that simulates a legitimate client and an
   attacker issuing refresh requests under controlled timing (sequential and
   concurrent/race scenarios).
3. Compares the controlled implementation against real open-source
   authorization servers (Keycloak, Ory Hydra) running locally in Docker,
   including an attempt to reproduce a known race-condition defect
   (CVE-2026-1035) as harness validation.
4. Collects security metrics (successful attacker refreshes, reuse-detection
   rate and latency, token-family forking, session survival) and performance
   metrics (refresh latency p50/p95/p99, throughput, resource usage).

## Project status

Core implementation and both Phase 4 validation targets are done and
passing (26 tests). What's in:

- **Service, strategies, storage** — FastAPI service with `static`,
  `naive_rotation`, `atomic_rotation` and `grace_rotation` strategies,
  backed by an in-memory or Redis token store.
- **Harness** (`harness/scenarios.py`) — sequential replay, concurrent race
  and delayed replay scenarios, each returning a `TrialOutcome`.
- **Security experiment runner** (`experiments/run_main.py` +
  `metrics/aggregate.py`) — runs every strategy × scenario combination over
  N trials and writes rates/latency percentiles to `results/`.
- **Performance benchmark** (`experiments/run_benchmark.py`) — drives the
  real HTTP service and reports p50/p95/p99 latency and throughput per
  strategy, with repeats for median/spread.
- **Real-server comparison (Phase 4)** — Keycloak and Ory Hydra run via
  `docker-compose.yml`; `experiments/run_keycloak_validation.py` and
  `run_hydra_validation.py` attempt to reproduce the same concurrent-race
  pattern against them. Result so far: the race does **not** reproduce
  against Keycloak 26.2.5 over ordinary HTTP concurrency (consistent with
  CVE-2026-1035's "High" attack-complexity rating), but it **does**
  reproduce against Hydra v26.2.0 (a bounded fraction of concurrent
  refreshes succeed). This itself is a result worth reporting, not a gap.

- **Grace-window cross-check (`experiments/run_hydra_grace_validation.py`)**
  — run against Hydra's own `rotation_grace_period` (set via
  `HYDRA_GRACE_PERIOD`, default `0s`/strict in `docker-compose.yml`). With a
  5s window: replays inside the window silently succeed (no error, no
  alert — the same silent takeover `grace_rotation` models); past the
  window, the replay is rejected **and it revokes the legitimate client's
  already-rotated token too**, mirroring `family_revoked` in the project's
  own harness almost exactly.

Still open: the analysis/plots for the final paper haven't been written up
from the `results/` CSVs yet.

## Repository structure

```text
.
├── README.md
├── pyproject.toml
├── docker-compose.yml          # Redis + Keycloak + Ory Hydra
├── .env.example
├── docs/
│   └── proposal/
│       └── proposal.tex        # project proposal (LaTeX / IEEEtran)
├── src/
│   └── gr9_refresh_token_rotation/
│       ├── api/                 # authentication service (FastAPI)
│       │   ├── main.py
│       │   ├── routes.py
│       │   └── models.py
│       ├── strategies/          # the independent variable under study
│       │   ├── base.py
│       │   ├── static.py
│       │   ├── naive_rotation.py
│       │   ├── atomic_rotation.py
│       │   └── grace_rotation.py
│       ├── storage/
│       │   └── token_store.py   # InMemoryTokenStore / RedisTokenStore
│       ├── harness/
│       │   └── scenarios.py     # sequential_replay / concurrent_race / delayed_replay
│       ├── servers/              # clients for the real-server comparison
│       │   ├── keycloak_client.py
│       │   └── hydra_client.py
│       └── metrics/
│           └── aggregate.py      # rates, percentiles, summarize()
├── experiments/
│   ├── run_main.py               # security experiment: strategy x scenario, N trials
│   ├── run_benchmark.py          # HTTP latency/throughput benchmark
│   ├── run_keycloak_validation.py
│   ├── run_hydra_validation.py
│   ├── run_hydra_grace_validation.py
│   └── configs/
│       ├── main.yaml
│       ├── grace.yaml
│       ├── bench.yaml
│       └── static.yaml
├── infra/
│   └── docker/
│       ├── keycloak/realm.json   # strict rotation realm, auto-imported
│       └── hydra/hydra.yml       # rotation_grace_period config
├── results/                      # gitignored; written by the experiments/ scripts
└── tests/
    ├── test_strategies.py
    ├── test_harness.py
    ├── test_api.py
    ├── test_redis_store.py       # skips if Redis isn't up
    ├── test_keycloak_integration.py  # skips if Keycloak isn't up
    └── test_hydra_integration.py     # skips if Hydra isn't up
```

### Why this layout

- **`src/gr9_refresh_token_rotation/`** is the installable package, split by
  responsibility: `api` (the service under test), `strategies` (the
  independent variable), `storage` (how token state is persisted —
  atomicity is the whole point), `harness` (the experiment driver),
  `servers` (real-world comparison targets), and `metrics` (what gets
  measured).
- **`experiments/`** holds the run scripts and their YAML configs, separate
  from the library code so a trial's parameters change without touching
  `src/`.
- **`infra/docker/`** holds the Keycloak realm and Hydra config needed to
  reproduce the comparison servers from a clean checkout.
- **`results/`** is where the experiment scripts write CSV/JSON output; it's
  git-ignored since it's regenerated by re-running the scripts.
- **`tests/`** covers the library code with fast unit tests
  (`test_strategies.py`, `test_harness.py`) plus integration tests against
  the real services that skip cleanly when a container isn't running.

## Getting started

```bash
# clone and enter the repo
git clone https://github.com/ErblinSyla/Gr9_Refresh_Token_Rotation.git
cd Gr9_Refresh_Token_Rotation

# install the package in editable mode
pip install -e ".[dev]"

# bring up Redis, Keycloak and Hydra (skip any you don't need right now)
docker compose up -d

# run the test suite (integration tests skip cleanly if a container isn't up)
pytest

# run the main security experiment: every strategy x scenario, N trials each
python experiments/run_main.py

# run the secondary grace-window experiment
python experiments/run_main.py experiments/configs/grace.yaml

# benchmark refresh latency/throughput over real HTTP
python experiments/run_benchmark.py

# attempt to reproduce the concurrent-race pattern against each real server
python experiments/run_keycloak_validation.py
python experiments/run_hydra_validation.py

# grace-window takeover check against Hydra's own rotation_grace_period
HYDRA_GRACE_PERIOD=5s docker compose up -d hydra
python experiments/run_hydra_grace_validation.py 1 3 6
docker compose up -d hydra   # back to strict (0s) before running the test suite
```

Results land in `results/<name>/` as CSV/JSON (git-ignored).

## Team

| Member | Responsibility |
|---|---|
| Albena Veseli | TBD |
| Ardit Hyseni | TBD |
| Erblin Syla | TBD |

## Scope and limitations

This project assumes a refresh token has already been compromised and does
not investigate how it was stolen (XSS, malware, device compromise are out
of scope). All testing targets only the group's own local systems with
synthetic clients. See `docs/proposal/proposal.tex` for the full discussion
of limitations and safety constraints.

## References

- RFC 9700 — OAuth 2.0 Security Best Current Practice
- RFC 6819 — OAuth 2.0 Threat Model and Security Considerations
- CVE-2026-1035 — Keycloak refresh-token TOCTOU race condition (reproduction
  attempted in `experiments/run_keycloak_validation.py`; see Project status)

Full reference list in the proposal/paper.

## License

TBD (add a `LICENSE` file — MIT or similar is typical for a student research
prototype, confirm with your course's requirements).