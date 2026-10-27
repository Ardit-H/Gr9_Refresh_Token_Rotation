"""Aggregate per-trial outcomes into the security metrics of the study."""

from __future__ import annotations

import math
from collections.abc import Sequence

from gr9_refresh_token_rotation.harness.scenarios import TrialOutcome


def percentile(values: Sequence[float], p: float) -> float | None:
    """Nearest-rank percentile (p in 0..100); None for an empty sample."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(p / 100 * len(ordered)))
    return ordered[rank - 1]


def wilson_ci(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion (default: 95% CI).

    Preferred over the naive normal-approximation interval because it stays
    inside [0, 1] and is well-behaved at the extremes (e.g. 0/n or n/n),
    which plain-rate reporting hits constantly in this study.
    """
    if n == 0:
        return (0.0, 1.0)
    p_hat = successes / n
    denom = 1 + z**2 / n
    center = p_hat + z**2 / (2 * n)
    margin = z * math.sqrt(p_hat * (1 - p_hat) / n + z**2 / (4 * n**2))
    return (max(0.0, (center - margin) / denom), min(1.0, (center + margin) / denom))


def rate_with_ci(successes: int, n: int) -> dict:
    lo, hi = wilson_ci(successes, n)
    return {"rate": successes / n if n else 0.0, "ci95_lo": lo, "ci95_hi": hi, "n": n}


def summarize(outcomes: Sequence[TrialOutcome]) -> dict:
    n = len(outcomes)
    if n == 0:
        raise ValueError("no outcomes to summarize")
    latencies = [o.detection_latency_s for o in outcomes if o.detection_latency_s is not None]

    def rate_metric(pred) -> dict:
        successes = sum(1 for o in outcomes if pred(o))
        return rate_with_ci(successes, n)

    attacker = rate_metric(lambda o: o.attacker_successes > 0)
    detected = rate_metric(lambda o: o.detected)
    forked = rate_metric(lambda o: o.forked)
    silent = rate_metric(lambda o: o.attacker_successes > 0 and not o.detected)
    survived = rate_metric(lambda o: o.legit_survived)

    return {
        "trials": n,
        "attacker_success_rate": attacker["rate"],
        "attacker_success_ci95": (attacker["ci95_lo"], attacker["ci95_hi"]),
        "mean_attacker_successes": sum(o.attacker_successes for o in outcomes) / n,
        # Access tokens obtained after compromise (scenario + follow-ups).
        "mean_attacker_tokens": sum(o.attacker_tokens for o in outcomes) / n,
        "attacker_persistent_rate": rate_with_ci(
            sum(1 for o in outcomes if o.attacker_tokens > o.attacker_successes), n)["rate"],
        "reuse_detection_rate": detected["rate"],
        "reuse_detection_ci95": (detected["ci95_lo"], detected["ci95_hi"]),
        "family_fork_rate": forked["rate"],
        "family_fork_ci95": (forked["ci95_lo"], forked["ci95_hi"]),
        # Attacker got a token AND nothing was flagged: the silent-takeover case.
        "silent_compromise_rate": silent["rate"],
        "silent_compromise_ci95": (silent["ci95_lo"], silent["ci95_hi"]),
        "legit_session_survival_rate": survived["rate"],
        "legit_session_survival_ci95": (survived["ci95_lo"], survived["ci95_hi"]),
        "detection_latency_p50_s": percentile(latencies, 50),
        "detection_latency_p95_s": percentile(latencies, 95),
        "detection_latency_p99_s": percentile(latencies, 99),
    }