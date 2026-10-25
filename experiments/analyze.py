"""Build the paper's figures and results table from results/*/summary.json.

Reads results/main (strategy x scenario security metrics), results/grace
(secondary research question), results/bench (performance), and the
Keycloak/Hydra validation JSON files; writes PNGs to docs/paper/figures/
and a LaTeX table to docs/paper/tables/main_results.tex.

Usage:  python experiments/analyze.py
Run experiments/run_main.py, run_main.py experiments/configs/grace.yaml and
run_benchmark.py first so results/ is populated.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
FIGURES = ROOT / "docs" / "paper" / "figures"
TABLES = ROOT / "docs" / "paper" / "tables"

# Display order / labels, independent of dict insertion order in summary.json.
STRATEGY_ORDER = ["static", "naive_rotation@rw=0", "atomic_rotation"]
STRATEGY_LABELS = {"static": "static", "naive_rotation@rw=0": "naive rotation",
                    "atomic_rotation": "atomic rotation",
                    "grace_rotation@gw=0.05": "grace rotation (50 ms)"}
COLORS = {"static": "#c0392b", "naive_rotation@rw=0": "#e67e22", "atomic_rotation": "#27ae60",
          "grace_rotation@gw=0.05": "#8e44ad"}


def load(name: str) -> dict:
    return json.loads((RESULTS / name / "summary.json").read_text())


def fig_security_bars() -> None:
    """Fig 1: attacker success / reuse detection / family fork, per strategy,
    for the concurrent_race scenario (the project's central comparison).
    Error bars show the 95% Wilson confidence interval on each rate."""
    summary = load("main")
    metrics = ["attacker_success_rate", "reuse_detection_rate", "family_fork_rate"]
    ci_keys = ["attacker_success_ci95", "reuse_detection_ci95", "family_fork_ci95"]
    metric_labels = ["Attacker success", "Reuse detected", "Family forked"]

    fig, ax = plt.subplots(figsize=(6, 4))
    width = 0.25
    x = range(len(STRATEGY_ORDER))
    for i, (metric, ci_key, label) in enumerate(zip(metrics, ci_keys, metric_labels)):
        rows = [summary[f"{s}/concurrent_race"] for s in STRATEGY_ORDER]
        values = [r[metric] for r in rows]
        err_lo = [r[metric] - r[ci_key][0] for r in rows]
        err_hi = [r[ci_key][1] - r[metric] for r in rows]
        offset = (i - 1) * width
        ax.bar([xi + offset for xi in x], values, width, label=label,
               yerr=[err_lo, err_hi], capsize=3)

    ax.set_xticks(list(x))
    ax.set_xticklabels([STRATEGY_LABELS[s] for s in STRATEGY_ORDER])
    ax.set_ylabel("Rate (concurrent_race, N=200 trials, 95% CI)")
    ax.set_ylim(0, 1.05)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=3, frameon=False)
    ax.set_title("Security outcomes under a concurrent refresh race")
    fig.tight_layout()
    fig.savefig(FIGURES / "security_concurrent_race.png", dpi=150)
    plt.close(fig)


def fig_grace_window() -> None:
    """Fig 2: silent-takeover rate vs. replay delay, grace vs. atomic."""
    summary = load("grace")
    delays = [0.01, 0.03, 0.1]

    fig, ax = plt.subplots(figsize=(6, 4))
    for strategy in ["atomic_rotation", "grace_rotation@gw=0.05"]:
        rates = [summary[f"{strategy}/delayed_replay@{d}"]["silent_compromise_rate"] for d in delays]
        ax.plot([d * 1000 for d in delays], rates, marker="o",
                 label=STRATEGY_LABELS.get(strategy, strategy), color=COLORS.get(strategy))

    ax.axvline(50, color="gray", linestyle="--", linewidth=1, label="grace window (50 ms)")
    ax.set_xlabel("Attacker replay delay (ms)")
    ax.set_ylabel("Silent-compromise rate")
    ax.set_ylim(-0.05, 1.05)
    ax.set_title("Grace window: silent takeover vs. replay delay")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(FIGURES / "grace_window_takeover.png", dpi=150)
    plt.close(fig)


def fig_benchmark_latency() -> None:
    """Fig 3: single-client p50 latency per strategy, median with min/max."""
    rows = json.loads((RESULTS / "bench" / "bench_summary.json").read_text())
    order = ["static", "naive_rotation", "atomic_rotation", "grace_rotation"]
    one_client = {r["strategy"]: r for r in rows if r["clients"] == 1}

    medians = [one_client[s]["p50_ms_median"] for s in order]
    lo = [one_client[s]["p50_ms_median"] - one_client[s]["p50_ms_min"] for s in order]
    hi = [one_client[s]["p50_ms_max"] - one_client[s]["p50_ms_median"] for s in order]

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(range(len(order)), medians, yerr=[lo, hi], capsize=4,
           color=[COLORS.get(s, "#3498db") for s in order])
    ax.set_xticks(range(len(order)))
    ax.set_xticklabels([s.replace("_", " ") for s in order])
    ax.set_ylabel("p50 refresh latency, 1 client (ms)")
    ax.set_title("HTTP refresh latency by strategy (median of 5 repeats)")
    fig.tight_layout()
    fig.savefig(FIGURES / "benchmark_latency.png", dpi=150)
    plt.close(fig)


def _pct_ci(rate: float, ci: tuple[float, float]) -> str:
    """'52% [45%, 59%]', with every % escaped for LaTeX."""
    return f"{rate:.0%} [{ci[0]:.0%}, {ci[1]:.0%}]".replace("%", r"\%")


def fig_benchmark_resources() -> None:
    """Fig 4: single-client mean CPU% and RSS memory per strategy."""
    rows = json.loads((RESULTS / "bench" / "bench_summary.json").read_text())
    order = ["static", "naive_rotation", "atomic_rotation", "grace_rotation"]
    one_client = {r["strategy"]: r for r in rows if r["clients"] == 1}
    if any(one_client[s]["cpu_pct_mean_median"] is None for s in order):
        print("Skipping resource figure: no CPU/memory samples in bench_summary.json "
              "(psutil was not installed when the benchmark ran).")
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9, 4))
    cpu = [one_client[s]["cpu_pct_mean_median"] for s in order]
    rss = [one_client[s]["rss_mb_mean_median"] for s in order]
    colors = [COLORS.get(s, "#3498db") for s in order]
    labels = [s.replace("_", " ") for s in order]

    ax1.bar(range(len(order)), cpu, color=colors)
    ax1.set_xticks(range(len(order)))
    ax1.set_xticklabels(labels, rotation=20, ha="right")
    ax1.set_ylabel("Mean CPU (%)")
    ax1.set_title("Server CPU usage, 1 client")

    ax2.bar(range(len(order)), rss, color=colors)
    ax2.set_xticks(range(len(order)))
    ax2.set_xticklabels(labels, rotation=20, ha="right")
    ax2.set_ylabel("Mean RSS memory (MB)")
    ax2.set_title("Server memory usage, 1 client")

    fig.tight_layout()
    fig.savefig(FIGURES / "benchmark_resources.png", dpi=150)
    plt.close(fig)


def table_main_results() -> None:
    """LaTeX table: strategy x concurrent_race, the headline comparison.
    Each rate is reported with its 95% Wilson confidence interval."""
    summary = load("main")
    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{Security outcomes under a concurrent refresh race "
        r"(N=200 trials; brackets show the 95\% Wilson confidence interval).}",
        r"\label{tab:main-results}",
        r"\begin{tabular}{lccc}",
        r"\toprule",
        r"Strategy & Attacker success & Reuse detected & Family forked \\",
        r"\midrule",
    ]
    for s in STRATEGY_ORDER:
        m = summary[f"{s}/concurrent_race"]
        row = (
            f"{STRATEGY_LABELS[s]} & "
            f"{_pct_ci(m['attacker_success_rate'], m['attacker_success_ci95'])} & "
            f"{_pct_ci(m['reuse_detection_rate'], m['reuse_detection_ci95'])} & "
            f"{_pct_ci(m['family_fork_rate'], m['family_fork_ci95'])} \\\\"
        )
        lines.append(row)
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    TABLES.mkdir(parents=True, exist_ok=True)
    (TABLES / "main_results.tex").write_text("\n".join(lines))


def table_real_server_comparison() -> None:
    """LaTeX table: Keycloak vs. Hydra race reproduction (Phase 4 result)."""
    kc = json.loads((RESULTS / "keycloak_validation" / "trials.json").read_text())
    hy = json.loads((RESULTS / "hydra_validation" / "trials.json").read_text())

    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{Concurrent-race reproduction against real authorization servers "
        r"(brackets show the 95\% Wilson confidence interval).}",
        r"\label{tab:real-server}",
        r"\begin{tabular}{lcc}",
        r"\toprule",
        r"Server & Trials & Family fork rate \\",
        r"\midrule",
        f"Keycloak 26.2.5 & {kc['trials']} & "
        f"{_pct_ci(kc['fork_rate'], (kc['ci95_lo'], kc['ci95_hi']))} \\\\",
        f"Ory Hydra v26.2.0 & {hy['trials']} & "
        f"{_pct_ci(hy['fork_rate'], (hy['ci95_lo'], hy['ci95_hi']))} \\\\",
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
        "",
    ]
    TABLES.mkdir(parents=True, exist_ok=True)
    (TABLES / "real_server_comparison.tex").write_text("\n".join(lines))


def main() -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig_security_bars()
    fig_grace_window()
    fig_benchmark_latency()
    fig_benchmark_resources()
    table_main_results()
    table_real_server_comparison()
    print(f"Wrote figures to {FIGURES}")
    print(f"Wrote tables to {TABLES}")


if __name__ == "__main__":
    main()