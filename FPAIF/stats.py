"""
stats.py - small statistics helpers for the FPAIF experiments (no numpy needed)

  wilson(k, n)            95% confidence interval for a proportion (e.g. 0 failures out of 1000)
  bootstrap_ci(values)    95% confidence interval for the mean/median of repeated-run values
  summarize(values)       n, mean, sd, cv, 95% CI, median, min, max
  percentile(values, q)   linear-interpolated percentile (q in 0..100)
"""

import math
import random
import statistics


def wilson(k, n, z=1.96):
    """Wilson score interval for k successes out of n. Returns (low, high) as fractions.

    Unlike the normal approximation it stays sensible at k=0 or k=n, which is
    exactly the case for 'zero false accepts' claims.
    """
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def percentile(values, q):
    """Linear-interpolated percentile, q in [0, 100]."""
    if not values:
        return 0.0
    s = sorted(values)
    pos = (len(s) - 1) * q / 100
    lo, hi = int(math.floor(pos)), int(math.ceil(pos))
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def bootstrap_ci(values, stat=statistics.mean, n_boot=10000, alpha=0.05, seed=1):
    """Percentile-bootstrap confidence interval of `stat` over `values`.

    No normality assumption (latencies are usually right-skewed). With a single
    value there is no spread to estimate, so the interval collapses to that value.
    """
    if not values:
        return (0.0, 0.0)
    if len(values) == 1:
        return (values[0], values[0])
    rng = random.Random(seed)
    n = len(values)
    boots = sorted(stat([values[rng.randrange(n)] for _ in range(n)]) for _ in range(n_boot))
    return (boots[int(n_boot * alpha / 2)], boots[int(n_boot * (1 - alpha / 2)) - 1])


def diff_ci(a, b, n_boot=10000, alpha=0.05, seed=1):
    """Bootstrap 95% CI for mean(b) - mean(a) from two independent lists of run values.

    If the interval excludes 0 the two systems differ beyond run-to-run noise.
    Returns (diff, low, high).
    """
    if not a or not b:
        return (0.0, 0.0, 0.0)
    rng = random.Random(seed)
    na, nb = len(a), len(b)
    diffs = sorted(
        statistics.mean(b[rng.randrange(nb)] for _ in range(nb)) -
        statistics.mean(a[rng.randrange(na)] for _ in range(na))
        for _ in range(n_boot))
    return (statistics.mean(b) - statistics.mean(a),
            diffs[int(n_boot * alpha / 2)], diffs[int(n_boot * (1 - alpha / 2)) - 1])


def summarize(values, digits=3):
    """Summary of repeated-run values with a bootstrap 95% CI of the mean."""
    if not values:
        return {"n": 0}
    mean = statistics.mean(values)
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    lo, hi = bootstrap_ci(values)
    r = lambda x: round(x, digits)
    return {
        "n": len(values),
        "mean": r(mean),
        "sd": r(sd),
        "cv_pct": r(100 * sd / mean) if mean else 0.0,
        "ci95_low": r(lo),
        "ci95_high": r(hi),
        "median": r(statistics.median(values)),
        "min": r(min(values)),
        "max": r(max(values)),
    }


def fmt(s, unit=""):
    """'14.74 (95% CI 14.2-15.3) ms, n=30 runs' style string from summarize()."""
    if not s.get("n"):
        return "n/a"
    return f"{s['mean']} (95% CI {s['ci95_low']}-{s['ci95_high']}){unit}, sd={s['sd']}, n={s['n']} runs"
