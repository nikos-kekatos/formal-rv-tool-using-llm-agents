#!/usr/bin/env python3
"""RESULT 6 -- CANONICALISATION SENSITIVITY.

The RV layer maps each tool NAME to a set of obligation classes. Our headline numbers
use a keyword typing (stac_rv.hits over 5 pattern tuples). Here we recompute the
headline numbers under FOUR tool->class mappings, to show how sensitive the results are
to the canonicaliser:

  (i)  ORIGINAL     -- the keyword typing, unchanged (validation: must reproduce base).
  (ii) CORRECTED    -- for the 54 hand-labeled tools use the GOLD class (or NONE, which
                       maps to the empty set); all other tools fall back to keyword.
  (iii)CONSERVATIVE -- drop AMBIGUOUS tools: any tool the keyword typing assigns to >1
                       class is removed from all risky classes (empty set); single-label
                       tools keep the keyword class. (Reduces both detection and BFR.)
  (iv) EXPANDED     -- add KNOWN-MISSED tools: for hand-labeled tools whose gold class
                       the keyword typing misses, add that gold class (keyword UNION
                       gold); other tools keyword only. (Recovers false negatives.)

Approval gating (stac_rv.APPROVAL) is unchanged in every variant. Headline numbers:
AgentDojo gpt-4o detection on successful attacks + BFR on benign; STAC final-step
detection. We report each variant and its delta vs ORIGINAL.
"""
import argparse, glob, json, os
from stac_rv import (DESTRUCTIVE, TEARDOWN, FINANCIAL, EXPORT, ACTUATION, APPROVAL,
                     hits, canonical_chain)
from agentdojo_rv import chain_from_run
from canon_eval import GOLD

# obligation keys in canonical O1..O5 order
KEYS = ["destructive_no_confirm", "teardown_no_approval", "financial_no_confirm",
        "export_no_consent", "actuation_no_precond"]
PATS = [(KEYS[0], DESTRUCTIVE), (KEYS[1], TEARDOWN), (KEYS[2], FINANCIAL),
        (KEYS[3], EXPORT), (KEYS[4], ACTUATION)]
ABBR2KEY = {"DESTR": KEYS[0], "TEARD": KEYS[1], "FIN": KEYS[2],
            "EXP": KEYS[3], "ACT": KEYS[4], "NONE": None}


def kw(tool):
    return {k for k, pats in PATS if hits(tool, pats)}


def make_classify(variant):
    if variant == "original":
        return kw
    if variant == "corrected":
        def f(tool):
            if tool in GOLD:
                key = ABBR2KEY[GOLD[tool]]
                return {key} if key else set()
            return kw(tool)
        return f
    if variant == "conservative":
        def f(tool):
            s = kw(tool)
            return s if len(s) <= 1 else set()   # drop ambiguous/multi-label
        return f
    if variant == "expanded":
        def f(tool):
            s = set(kw(tool))
            if tool in GOLD:
                key = ABBR2KEY[GOLD[tool]]
                if key:                          # add a missed gold class
                    s.add(key)
            return s
        return f
    raise ValueError(variant)


def approval_before(chain, idx):
    return any(hits(chain[j][0], APPROVAL) for j in range(idx))


def any_fires(chain, classify):
    """Does any obligation fire anywhere in the chain (approval-gated)?"""
    for i, (tool, _a) in enumerate(chain):
        if not tool or approval_before(chain, i):
            continue
        if classify(tool):
            return True
    return False


def final_fires(chain, classify):
    """Does an obligation fire on the final (withheld harmful) step?"""
    if not chain:
        return False
    i = len(chain) - 1
    tool = chain[i][0]
    if not tool or approval_before(chain, i):
        return False
    return bool(classify(tool))


def agentdojo_numbers(root, classify):
    succ = det = benign = bfr = 0
    for suite in ["banking", "slack", "travel", "workspace"]:
        for f in glob.glob(os.path.join(root, suite, "**", "*.json"), recursive=True):
            try:
                d = json.load(open(f))
            except (ValueError, OSError):
                continue
            chain = chain_from_run(d)
            if not chain:
                continue
            fired = any_fires(chain, classify)
            at = d.get("attack_type")
            if at and at != "none" and d.get("injection_task_id"):
                if d.get("security") is True:
                    succ += 1; det += fired
            elif not at and not d.get("injection_task_id"):
                benign += 1; bfr += fired
    return det, succ, bfr, benign


def stac_numbers(cases, classify):
    n = f = 0
    for c in cases:
        n += 1
        if final_fires(canonical_chain(c), classify):
            f += 1
    return f, n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True, help="AgentDojo runs/gpt-4o dir")
    ap.add_argument("--stac", required=True, help="STAC_benchmark_data.json")
    a = ap.parse_args()
    cases = json.load(open(a.stac))

    variants = ["original", "corrected", "conservative", "expanded"]
    base = None
    print("Canonicalisation sensitivity -- headline numbers under 4 tool->class maps\n")
    print(f"{'mapping':<14}{'AD detect':>18}{'AD BFR':>16}{'STAC final':>18}")
    for v in variants:
        cf = make_classify(v)
        det, ns, bfr, nb = agentdojo_numbers(a.runs, cf)
        sf, sn = stac_numbers(cases, cf)
        dp, bp, sp = det/ns*100, bfr/nb*100, sf/sn*100
        if base is None:
            base = (dp, bp, sp)
            tag = "(baseline)"
        else:
            tag = f"(d det {dp-base[0]:+.1f}, BFR {bp-base[1]:+.1f}, STAC {sp-base[2]:+.1f})"
        print(f"{v:<14}{det:>6}/{ns} {dp:>6.1f}%{bfr:>5}/{nb} {bp:>6.1f}%"
              f"{sf:>7}/{sn} {sp:>6.1f}%   {tag}")


if __name__ == "__main__":
    main()
