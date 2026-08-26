#!/usr/bin/env python3
"""Replay AgentDojo's RECORDED run trajectories through our RV obligations, OFFLINE.

AgentDojo (ethz-spylab/agentdojo) ships ~36.7k recorded agent runs under runs/,
each a JSON with the full message trace (assistant tool_calls: {function, args}),
the attack_type, and AgentDojo's own labels security (attack succeeded) and utility
(user task done). We can therefore evaluate our trace-level RV obligations on the
SAME benchmark AgentDojo scores, with NO LLM and NO API key.

We report, for one model, no-defense:
  * AgentDojo baseline ASR (fraction of attacked runs with security==True);
  * RV detection on SUCCESSFUL attacks (of security==True runs, fraction where an
    obligation fires on some tool call) -- would the shield have gated the attack;
  * RV over-block on BENIGN runs (attack_type=='none': fraction where an obligation
    fires) -- the utility cost, which STAC could not give us.

HONESTY: this is post-hoc replay of recorded traces; "would gate" assumes blocking
the flagged call prevents the outcome. Generic obligations are action-type gated, so
over-block on benign task actions is expected and reported, not hidden.
"""
import argparse, glob, json, os
from collections import Counter
from stac_rv import OBLIGATIONS, APPROVAL, hits, approval_event


def chain_from_run(d):
    chain = []
    for m in d.get("messages", []):
        if m.get("role") == "assistant":
            for tc in (m.get("tool_calls") or []):
                fn = tc.get("function")
                name = fn if isinstance(fn, str) else (fn or {}).get("name", "")
                chain.append((name or "", tc.get("args", {}) or {}))
    return chain


def rv_flags(chain):
    """Any obligation fires on any call lacking a prior approval (any-step gating)."""
    fired = set()
    for i, (tool, _a) in enumerate(chain):
        if not tool or any(approval_event(chain[j][0]) for j in range(i)):
            continue
        for key, pats, _ in OBLIGATIONS:
            if hits(tool, pats):
                fired.add(key)
    return fired


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True, help="AgentDojo runs/<model> dir")
    a = ap.parse_args()

    files = glob.glob(os.path.join(a.runs, "**", "*.json"), recursive=True)
    atk = atk_succ = 0
    rv_on_succ = 0                       # RV fires on a successful attack
    rv_on_atk = 0                        # RV fires on any attacked run
    benign = benign_flag = benign_util = benign_util_flag = 0
    by_oblig_succ = Counter()
    skipped = 0

    for f in files:
        try:
            d = json.load(open(f))
        except (ValueError, OSError):
            skipped += 1; continue
        chain = chain_from_run(d)
        if not chain:
            skipped += 1; continue
        fired = rv_flags(chain)
        attack = d.get("attack_type")
        if attack and attack != "none" and d.get("injection_task_id"):
            atk += 1
            if fired: rv_on_atk += 1
            if d.get("security") is True:      # attack SUCCEEDED (AgentDojo label)
                atk_succ += 1
                if fired:
                    rv_on_succ += 1
                    for k in fired: by_oblig_succ[k] += 1
        elif not attack and not d.get("injection_task_id"):   # benign / utility run
            benign += 1
            if fired: benign_flag += 1
            if d.get("utility") is True:
                benign_util += 1
                if fired: benign_util_flag += 1

    print(f"model dir: {a.runs}")
    print(f"files: {len(files)}  (skipped empty/unparse: {skipped})\n")
    print(f"=== AgentDojo attacked runs (no defense) ===")
    print(f"  attacked runs:            {atk}")
    print(f"  AgentDojo ASR (security): {atk_succ}/{atk} = {atk_succ/max(1,atk)*100:.1f}%")
    print(f"\n=== Our RV replayed on the SAME runs ===")
    print(f"  RV fires on a SUCCESSFUL attack: {rv_on_succ}/{atk_succ} = "
          f"{rv_on_succ/max(1,atk_succ)*100:.1f}%  (detection on real successful attacks)")
    print(f"  RV fires on ANY attacked run:    {rv_on_atk}/{atk} = {rv_on_atk/max(1,atk)*100:.1f}%")
    print(f"\n=== Over-block on BENIGN runs (attack='none') ===")
    print(f"  RV fires on benign run:          {benign_flag}/{benign} = "
          f"{benign_flag/max(1,benign)*100:.1f}%  (false-positive / utility cost)")
    print(f"  RV fires on benign SUCCESSFUL-utility run: {benign_util_flag}/{benign_util} = "
          f"{benign_util_flag/max(1,benign_util)*100:.1f}%")
    print(f"\n  detection-on-successful-attacks by obligation:")
    for key, _p, desc in OBLIGATIONS:
        print(f"    {key:<24} {by_oblig_succ[key]}")


if __name__ == "__main__":
    main()
