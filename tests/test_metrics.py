from gr9_refresh_token_rotation.metrics.aggregate import percentile, wilson_ci


def test_wilson_ci_matches_known_values():
    # 0/50: a one-sided interval starting at 0, upper bound well below 10%.
    lo, hi = wilson_ci(0, 50)
    assert lo == 0.0
    assert 0.0 < hi < 0.10

    # 50/50: symmetric case, upper bound capped at 1.0.
    lo, hi = wilson_ci(50, 50)
    assert hi == 1.0
    assert 0.90 < lo < 1.0

    # 100/200 (50%): interval should be roughly symmetric around 0.5 and
    # narrower than the naive normal approximation would give for small n.
    lo, hi = wilson_ci(100, 200)
    assert 0.43 < lo < 0.47
    assert 0.53 < hi < 0.57


def test_wilson_ci_empty_sample():
    assert wilson_ci(0, 0) == (0.0, 1.0)


def test_percentile_basic():
    assert percentile([1, 2, 3, 4, 5], 50) == 3
    assert percentile([], 50) is None