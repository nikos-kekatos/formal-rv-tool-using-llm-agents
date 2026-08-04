#!/usr/bin/env python3
"""Exact McNemar test on the paired BENIGN runs for each parametric refinement.

The parametric obligation is a strict refinement of the generic one (it adds a
conjunct), so on every run param-fires implies generic-fires: the paired 2x2 is
therefore concordant except for the discordant cell b = (generic fires, param does
not) and c = (param fires, generic does not) = 0 by construction. We run the EXACT
(binomial) McNemar test -- appropriate for the tiny benign denominators (banking
n=25, workspace n=46) where the chi-square approximation is invalid.

Paired counts come from agentdojo_param.py / agentdojo_param2.py (GPT-4o benign):
  banking   : n=25, generic fires 11, param fires 6  -> b=5, c=0
  workspace : n=46, generic fires  7, param fires 5  -> b=2, c=0
"""
from math import comb


def mcnemar_exact(b, c):
    """Two-sided exact (binomial) McNemar p-value for discordant counts b, c."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    # two-sided: 2 * P(X <= k) under Binomial(n, 0.5), capped at 1
    tail = sum(comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


CASES = [
    # name, n_benign, generic_fires, param_fires
    ("banking  payee-provenance", 25, 11, 6),
    ("workspace ext-recipient",   46,  7, 5),
]

if __name__ == "__main__":
    print("Exact McNemar test, paired benign runs (param refinement subset of generic)\n")
    print(f"{'case':<28} {'n':>3} {'gen':>4} {'par':>4} {'b':>3} {'c':>3} {'p(exact)':>9}")
    for name, n, g, p in CASES:
        b, c = g - p, 0          # param fires => generic fires, so c = 0
        pv = mcnemar_exact(b, c)
        print(f"{name:<28} {n:>3} {g:>4} {p:>4} {b:>3} {c:>3} {pv:>9.4f}")
    print("\nBanking p=0.0625 (> 0.05): the 44%->24% over-block reduction is NOT")
    print("significant at alpha=0.05 on n=25 benign runs (borderline, 5 discordant).")
    print("Workspace p=0.5: the 15.2%->10.9% reduction is clearly not significant")
    print("(n=46, only 2 discordant). Both parametric/generic Wilson CIs overlap")
    print("heavily; the reductions are small-sample effects, reported without over-claim.")
