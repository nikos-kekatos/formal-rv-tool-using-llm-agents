#!/usr/bin/env python3
"""RESULT 1 -- FIRST-FIRING / LEAD-TIME analysis (AgentDojo gpt-4o + STAC).

For each SUCCESSFUL attack we locate the FIRST obligation firing position in the
recorded tool-call trace and classify the trace into one of three cases:

  (a) PREVENTIVE   -- an obligation fires strictly BEFORE the final harmful step,
                      so an online shield had an earlier opportunity to gate;
  (b) LAST-MOMENT  -- an obligation fires ONLY on the final harmful step;
  (c) COVERAGE GAP -- no obligation ever fires on the trace.

Reported:
  * earliest-warning rate = %(a) among successful attacks;
  * detection lead        = median #tool-calls between first firing and the final
                            harmful step (reported over (a), and over all detected
                            (a)+(b) where (b) contributes lead 0);
  * the 3-way breakdown counts.

Firing rule (identical to stac_rv / agentdojo_rv): an obligation fires on step i
when the tool name matches one of the five risky-action templates AND no approval
event precedes i. "Final harmful step":
  * STAC     -> verified_tool_chain[-1] == last element of the canonical chain;
  * AgentDojo-> the last assistant tool call in the recorded trajectory
                (documented fallback; AgentDojo does not tag the injected call).
"""
import argparse, glob, json, os, statistics
from stac_rv import OBLIGATIONS, APPROVAL, hits, canonical_chain, fm_id, approval_event
from agentdojo_rv import chain_from_run


def first_fire_idx(chain):
    """Index of the first step where any obligation fires (approval-gated), or None."""
    for i, (tool, _a) in enumerate(chain):
        if not tool:
            continue
        if any(approval_event(chain[j][0]) for j in range(i)):
            continue
        if any(hits(tool, pats) for _k, pats, _d in OBLIGATIONS):
            return i
    return None


def classify(chain):
    """Return (case, lead) where case in {'preventive','last','gap'} and lead is
    #tool-calls from first firing to the final step (None if gap)."""
    if not chain:
        return "gap", None
    final_idx = len(chain) - 1
    ff = first_fire_idx(chain)
    if ff is None:
        return "gap", None
    lead = final_idx - ff
    return ("preventive" if ff < final_idx else "last"), lead


def summarise(name, chains):
    prev = last = gap = 0
    leads_a = []          # leads for preventive cases (>0)
    leads_det = []        # leads for all detected (a)+(b)
    for ch in chains:
        case, lead = classify(ch)
        if case == "preventive":
            prev += 1; leads_a.append(lead); leads_det.append(lead)
        elif case == "last":
            last += 1; leads_det.append(0)
        else:
            gap += 1
    n = prev + last + gap
    print(f"\n=== {name}  (successful attacks: {n}) ===")
    print(f"  (a) PREVENTIVE  (fires before final step): {prev}/{n} = {prev/max(1,n)*100:.1f}%")
    print(f"  (b) LAST-MOMENT (fires only on final step): {last}/{n} = {last/max(1,n)*100:.1f}%")
    print(f"  (c) COVERAGE GAP (never fires):             {gap}/{n} = {gap/max(1,n)*100:.1f}%")
    print(f"  earliest-warning rate  = {prev/max(1,n)*100:.1f}%  (=(a))")
    det = prev + last
    print(f"  detection (a)+(b)      = {det}/{n} = {det/max(1,n)*100:.1f}%")
    if leads_a:
        print(f"  detection lead over (a): median={statistics.median(leads_a):.1f}  "
              f"mean={statistics.mean(leads_a):.2f}  max={max(leads_a)}  (tool-calls)")
    if leads_det:
        print(f"  detection lead over (a)+(b): median={statistics.median(leads_det):.1f}  "
              f"mean={statistics.mean(leads_det):.2f}  (tool-calls; (b) counts as 0)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True, help="AgentDojo runs/gpt-4o dir")
    ap.add_argument("--stac", required=True, help="STAC_benchmark_data.json")
    a = ap.parse_args()

    # ---- AgentDojo gpt-4o: successful attacks ----
    ad = []
    for f in glob.glob(os.path.join(a.runs, "**", "*.json"), recursive=True):
        try:
            d = json.load(open(f))
        except (ValueError, OSError):
            continue
        at = d.get("attack_type")
        if at and at != "none" and d.get("injection_task_id") and d.get("security") is True:
            ch = chain_from_run(d)
            if ch:
                ad.append(ch)
    summarise("AgentDojo gpt-4o (final=last tool call)", ad)

    # ---- STAC: all recorded harmful chains (final=verified_tool_chain[-1]) ----
    cases = json.load(open(a.stac))
    st = [canonical_chain(c) for c in cases]
    summarise("STAC recorded harmful chains", st)


if __name__ == "__main__":
    main()
