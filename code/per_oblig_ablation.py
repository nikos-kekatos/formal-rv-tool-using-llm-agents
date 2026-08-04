#!/usr/bin/env python3
"""RESULT 3 -- PER-OBLIGATION ablation (AgentDojo gpt-4o, all suites, no defense).

For each generic obligation O1..O5 we report, over the recorded gpt-4o runs:
  * attack detection = successful attacks where THIS obligation fires (anywhere,
    approval-gated) / total successful attacks;
  * BFR              = benign runs where THIS obligation fires / total benign runs;
  * INCREMENTAL attacks = successful attacks caught by this obligation and by NONE of
    the other four (i.e. dropping it would lose these detections);
  * incremental benign  = benign runs flagged by this obligation and by none of the
    other four (over-block uniquely attributable to it);
  * detection-to-BFR ratio = detection% / BFR% (higher = better yield per unit
    over-block; infinite when BFR=0).

Firing per run uses the same approval-gated keyword typing as agentdojo_rv.rv_flags.
"""
import argparse, glob, json, os
from agentdojo_rv import chain_from_run, rv_flags
from stac_rv import OBLIGATIONS

KEYS = [k for k, _p, _d in OBLIGATIONS]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True, help="AgentDojo runs/gpt-4o dir")
    a = ap.parse_args()

    succ_sets, ben_sets = [], []
    for f in glob.glob(os.path.join(a.runs, "**", "*.json"), recursive=True):
        try:
            d = json.load(open(f))
        except (ValueError, OSError):
            continue
        chain = chain_from_run(d)
        if not chain:
            continue
        fired = rv_flags(chain)
        at = d.get("attack_type")
        if at and at != "none" and d.get("injection_task_id"):
            if d.get("security") is True:
                succ_sets.append(fired)
        elif not at and not d.get("injection_task_id"):
            ben_sets.append(fired)

    ns, nb = len(succ_sets), len(ben_sets)
    print(f"AgentDojo gpt-4o -- per-obligation ablation")
    print(f"successful attacks={ns}  benign runs={nb}\n")
    hdr = (f"{'obligation':<24}{'detect':>14}{'BFR':>14}"
           f"{'incr.atk':>9}{'incr.ben':>9}{'det/BFR':>9}")
    print(hdr)
    for k in KEYS:
        det = sum(1 for s in succ_sets if k in s)
        bfr = sum(1 for s in ben_sets if k in s)
        inc_a = sum(1 for s in succ_sets if s == {k})
        inc_b = sum(1 for s in ben_sets if s == {k})
        dr = det / ns * 100
        br = bfr / nb * 100
        ratio = f"{dr/br:.2f}" if br > 0 else "inf"
        print(f"{k:<24}{det:>5}/{ns} {dr:>5.1f}%{bfr:>5}/{nb} {br:>5.1f}%"
              f"{inc_a:>9}{inc_b:>9}{ratio:>9}")

    # union baseline for context
    det_any = sum(1 for s in succ_sets if s)
    bfr_any = sum(1 for s in ben_sets if s)
    print(f"\n{'UNION O1-O5':<24}{det_any:>5}/{ns} {det_any/ns*100:>5.1f}%"
          f"{bfr_any:>5}/{nb} {bfr_any/nb*100:>5.1f}%")


if __name__ == "__main__":
    main()
