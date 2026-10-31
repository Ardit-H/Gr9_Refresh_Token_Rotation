# Gr9 — Refresh-Token Lifecycle Security Under Concurrent Compromise

Information Security seminar project (Group 9) investigating how different
OAuth 2.0 refresh-token rotation strategies behave under **concurrent**
refresh requests, and what that means for reuse detection, legitimate-session
survival, and performance after a token has been compromised.

> Full project proposal: [`docs/proposal/Projekt-propozimi – Grupi 9.pdf`](docs/proposal/Projekt-propozimi%20%E2%80%93%20Grupi%209.pdf)  
> Paper: [`docs/paper/paper.tex`](docs/paper/paper.tex)

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
passing (32 tests; integration tests skip when their container is down). What's in:

- **Service, strategies, storage** — FastAPI service with `static`,
  `naive_rotation`, `atomic_rotation` and `grace_rotation` strategies,
  backed by an in-memory or Redis token store.
- **Harness** (`harness/scenarios.py`) — sequential replay, concurrent race
  and delayed replay scenarios, each returning a `TrialOutcome`.
- **Security experiment runner** (`experiments/run_main.py` +
  `metrics/aggregate.py`) — runs every strategy × scenario combination over
  N trials and writes rates/latency percentiles to `results/`.
- **Performance benchmark** (`experiments/run_benchmark.py`) — drives the
  real HTTP service and reports p50/p95/p99 latency, throughput and
  server CPU/memory per strategy, with repeats for median/spread.
- **Scenarios** — all four from the proposal: legitimate client first
  (`sequential_replay`), attacker first (`attacker_first_replay`),
  concurrent race (`concurrent_race`), and old-token reuse after rotation
  (`delayed_replay`).
- **Docker** — `Dockerfile` plus `auth-service` and `harness` services in
  `docker-compose.yml`, so the service and harness run containerized.
- **Real-server comparison (Phase 4)** — Keycloak and Ory Hydra run via
  `docker-compose.yml`. `experiments/run_server_scenarios.py` runs the same
  four two-party scenarios against each server; `run_keycloak_validation.py`
  and `run_hydra_validation.py` send k simultaneous refreshes of one token.
  Results:
  - **CVE-2026-1035 reproduced on Keycloak 26.2.5**: with 2 simultaneous
    refreshes, both succeed in 51% [41%, 61%] of trials and both token
    chains stay valid (durable fork, like `naive_rotation`). The window
    narrows with more competing requests (7% at 5, 0% at 10+).
  - **Hydra v26.2.0** accepts one token more than once (98% at 10
    concurrent requests). After the fork it keeps at most the chain used
    first, so an attacker who refreshes first keeps the session and the
    client is locked out (13/24 trials; client survived 0/24).
  - On both servers a detected sequential reuse revokes the legitimate
    session too, like `atomic_rotation`.

- **Grace-window cross-check (`experiments/run_hydra_grace_validation.py`)**
  — run against Hydra's own `rotation_grace_period` (set via
  `HYDRA_GRACE_PERIOD`, default `0s`/strict in `docker-compose.yml`), 20
  trials per delay. With a 5s window: replays at 1s and 3s silently succeed
  in 100% [84%, 100%] of trials (the same silent takeover `grace_rotation`
  models); at 6s the replay is rejected **and it revokes the legitimate
  client's already-rotated token too**.

- **Analysis and paper** — `experiments/analyze.py` builds the figures and
  tables in `docs/paper/` from `results/`; the write-up is in
  `docs/paper/paper.tex`.

## Repository structure

```text
.
├── README.md
├── pyproject.toml
├── Dockerfile                  # image for auth-service + harness
├── docker-compose.yml          # Redis, auth-service, harness, Keycloak, Ory Hydra
├── .env.example
├── docs/
│   ├── proposal/              # project proposal (PDF)
│   └── paper/                 # paper.tex, figures/, tables/
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
│       │   └── scenarios.py     # sequential / attacker_first / concurrent_race / delayed
│       ├── servers/              # clients for the real-server comparison
│       │   ├── keycloak_client.py
│       │   └── hydra_client.py
│       └── metrics/
│           └── aggregate.py      # rates, percentiles, summarize()
├── experiments/
│   ├── run_main.py               # security experiment: strategy x scenario, N trials
│   ├── analyze.py                # figures + LaTeX tables for the paper
│   ├── run_benchmark.py          # HTTP latency/throughput benchmark
│   ├── run_server_scenarios.py   # the four scenarios against Keycloak / Hydra
│   ├── run_keycloak_validation.py
│   ├── run_hydra_validation.py
│   ├── run_hydra_grace_validation.py
│   └── configs/
│       ├── main.yaml
│       ├── main_redis.yaml       # same, on the Redis store
│       ├── grace.yaml
│       ├── grace_redis.yaml
│       ├── pilot.yaml            # small pre-run check of the harness
│       └── bench.yaml
├── infra/
│   └── docker/
│       ├── keycloak/realm.json   # strict rotation realm, auto-imported
│       └── hydra/hydra.yml       # rotation_grace_period config
├── results/                      # CSV/JSON written by the experiments/ scripts (committed)
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
- **`results/`** is where the experiment scripts write CSV/JSON output; it is
  committed so the paper's figures can be rebuilt without re-running everything.
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

# build the paper's figures and tables from results/
python experiments/analyze.py

# or run the service / harness fully in Docker
docker compose up -d auth-service
docker compose run --rm harness

# run the main security experiment: every strategy x scenario, N trials each
python experiments/run_main.py

# pilot run, and the Redis-backed variants (needs: docker compose up -d redis)
python experiments/run_main.py experiments/configs/pilot.yaml
python experiments/run_main.py experiments/configs/main_redis.yaml
python experiments/run_main.py experiments/configs/grace_redis.yaml

# run the secondary grace-window experiment
python experiments/run_main.py experiments/configs/grace.yaml

# benchmark refresh latency/throughput over real HTTP
python experiments/run_benchmark.py

# attempt to reproduce the concurrent-race pattern against each real server
python experiments/run_server_scenarios.py keycloak 60 1
python experiments/run_server_scenarios.py hydra 60 1
python experiments/run_keycloak_validation.py 50 10    # k=10 headline run
python experiments/run_keycloak_validation.py 100 2    # also 30 5, 10 20, 5 50
python experiments/run_hydra_validation.py 50 10

# grace-window takeover check against Hydra's own rotation_grace_period
HYDRA_GRACE_PERIOD=5s docker compose up -d hydra
python experiments/run_hydra_grace_validation.py --trials 20 1 3 6
docker compose up -d hydra   # back to strict (0s) before running the test suite
```

Results land in `results/<name>/` as CSV/JSON.

## Team

| Member | Responsibility |
|---|---|
| Albena Veseli | Strategy implementations and tests, metrics module, performance benchmark, Hydra grace-window cross-check, paper figures/tables |
| Ardit Hyseni | Project scaffolding, FastAPI service, main experiment runner, Keycloak integration and CVE-2026-1035 reproduction, Hydra compose setup |
| Erblin Syla | Token store (in-memory/Redis), concurrency harness, grace-window strategy, Hydra client and validation |

## Scope and limitations

This project assumes a refresh token has already been compromised and does
not investigate how it was stolen (XSS, malware, device compromise are out
of scope). All testing targets only the group's own local systems with
synthetic clients. See the Limitations section of `docs/paper/paper.tex`
for the full discussion.

## References

- RFC 9700 — OAuth 2.0 Security Best Current Practice
- RFC 6819 — OAuth 2.0 Threat Model and Security Considerations
- CVE-2026-1035 — Keycloak refresh-token TOCTOU race condition (reproduced
  in `experiments/run_keycloak_validation.py`; see Project status)

Full reference list in the proposal/paper.

## License

MIT — see [`LICENSE`](LICENSE).
