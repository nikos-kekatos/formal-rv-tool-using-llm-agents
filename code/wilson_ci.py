#!/usr/bin/env python3
"""Wilson 95% score confidence intervals for the paper's headline proportions.
No external deps. z=1.96. Prints [lo, hi] in percent for each (k, n)."""
import math

Z = 1.959963985


def wilson(k, n):
    if n == 0:
        return (float('nan'), float('nan'))
    p = k / n
    d = 1 + Z * Z / n
    c = (p + Z * Z / (2 * n)) / d
    h = (Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n))) / d
    return (100 * (c - h), 100 * (c + h))


RATES = [
    ("STAC final-step detection",            347, 483),
    ("AgentDojo detection on successful",    1190, 1931),
    ("AgentDojo over-block (benign)",          39, 123),
    ("R-Judge detection (unsafe)",             71, 301),
    ("R-Judge FPR (safe)",                     44, 270),
    ("R-Judge IoT detection",                   6, 19),
    ("R-Judge IoT FPR",                         3, 11),
    ("banking generic O3 detect",             456, 576),
    ("banking parametric detect",             403, 576),
    ("banking generic O3 over-block",          11, 25),
    ("banking parametric over-block",           6, 25),
    ("workspace generic O4 detect",           220, 518),
    ("workspace parametric detect",           203, 518),
    ("workspace generic O4 over-block",         7, 46),
    ("workspace parametric over-block",         5, 46),
]

if __name__ == "__main__":
    print(f"{'rate':<38} {'k/n':>10} {'pt%':>7}  Wilson95%")
    for name, k, n in RATES:
        lo, hi = wilson(k, n)
        print(f"{name:<38} {f'{k}/{n}':>10} {100*k/n:6.1f}%  [{lo:.1f}, {hi:.1f}]")
