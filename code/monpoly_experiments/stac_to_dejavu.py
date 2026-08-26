#!/usr/bin/env python3
"""Independent-engine cross-validation: STAC obligation in DejaVu (QTL) vs MonPoly.

MonPoly agreeing with our own Python reference monitor is a weak check: both consume the
same canonical log and the same semantics. DejaVu is an independently developed
first-order past-time monitor with a different decision procedure (BDDs over quantified
past-time LTL), so agreement on the same specification fragment is a real cross-check.

Common fragment: the STAC obligation is untimed past-time first order --
  a typed risky action on case c is a violation unless an approval on c happened before.
DejaVu's QTL expresses exactly this; no metric operator is needed, so the fragment
transfers without weakening.

We emit the SAME canonical event stream stac_to_monpoly.py emits, in DejaVu CSV form,
and compare the violation count against MonPoly's 347.
"""
import os, subprocess, sys, argparse, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))
from stac_rv import (OBLIGATIONS, canonical_chain, approval_event, obligation_event)
JAR = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..",
                                   "paper_abstraction", "dejavu", "vendor", "dejavu.jar"))
SCALA_2 = "2.13.18"
OUT = os.path.join(HERE, "dejavu_stac")

SPEC = """prop stac_obligation :
  Forall c . risky(c) -> P approved(c)
"""

def build(cases):
    """One event per case: approved(c) if an approval precedes the final action,
    then risky(c) for the final typed action. Same canonicalisation as MonPoly."""
    rows, fired_expected = [], 0
    for i, case in enumerate(cases):
        cid = f"c{i}"
        chain = canonical_chain(case)
        if not chain:
            continue
        final = len(chain) - 1
        tool = chain[final][0]
        typed = any(obligation_event(tool, pats) for _k, pats, _d in OBLIGATIONS)
        appr = any(approval_event(chain[j][0]) for j in range(final))
        if appr:
            rows.append(f"approved,{cid}")
        if typed:
            rows.append(f"risky,{cid}")
            if not appr:
                fired_expected += 1
    return rows, fired_expected

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.abspath(os.path.join(
        HERE, "..", "..", "data", "stac", "STAC_benchmark_data.json")))
    ap.add_argument("--bits", type=int, default=20)
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    raw = json.load(open(a.data))
    cases = raw if isinstance(raw, list) else raw.get("cases", raw.get("data", []))
    rows, expected = build(cases)
    csvp = os.path.join(OUT, "stac.csv"); qtlp = os.path.join(OUT, "stac.qtl")
    open(csvp, "w").write("\n".join(rows) + "\n")
    open(qtlp, "w").write(SPEC)
    print(f"exported {len(rows)} events over {len(cases)} cases -> {csvp}")
    print(f"reference monitor expects {expected} violations")
    if not os.path.exists(JAR):
        print("dejavu.jar not found at", JAR); return
    work = os.path.join(OUT, "work"); os.makedirs(work, exist_ok=True)
    g = subprocess.run(["java","-cp",JAR,"dejavu.Verify",os.path.abspath(qtlp)],
                       cwd=work, capture_output=True, text=True, timeout=600)
    if not os.path.exists(os.path.join(work,"TraceMonitor.scala")):
        print("synthesis failed:", (g.stdout+g.stderr)[-400:]); return
    r = subprocess.run(["scala-cli","run","TraceMonitor.scala","--scala",SCALA_2,
                        "--jar",JAR,"--",os.path.abspath(csvp),str(a.bits)],
                       cwd=work, capture_output=True, text=True, timeout=2400)
    viol = sum(1 for l in r.stdout.splitlines() if "violated on event number" in l)
    print(f"DejaVu violations: {viol}")
    print(f"AGREEMENT: {'YES' if viol==expected else 'NO'}  (dejavu={viol}, reference={expected})")
    if viol != expected: print((r.stdout+r.stderr)[-600:])

if __name__ == "__main__":
    main()
