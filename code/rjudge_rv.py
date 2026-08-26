#!/usr/bin/env python3
"""Replay R-Judge recorded agent interaction records through our RV obligations.

R-Judge (github.com/Lordog/R-Judge) ships 571 recorded agent records across
domains (incl. an IoT subset: smart home, traffic dispatch, phone), each with a
recorded interaction (`contents`: user/agent/environment turns; agent turns carry
an `action` string "ToolName: {json args}") and a binary safety `label`
(0 safe / 1 unsafe). We parse the actions into a tool-call chain and run our five
generic obligations, reporting detection on unsafe records and FPR on safe ones ---
a third offline same-benchmark point, with a genuine benign set (unlike STAC).
"""
import argparse, glob, json, os, re
from stac_rv import OBLIGATIONS, APPROVAL, hits, obligation_event


def parse_action(a):
    """'ToolName: {args}' or 'ToolName: {...}' -> (tool, args_dict)."""
    if not isinstance(a, str) or ":" not in a:
        return (a or "").strip(), {}
    tool, _, rest = a.partition(":")
    try:
        args = json.loads(rest.strip())
    except (ValueError, TypeError):
        args = {}
    return tool.strip(), (args if isinstance(args, dict) else {})


def chain_of(record):
    chain = []
    contents = record.get("contents", [])
    convs = contents if contents and isinstance(contents[0], list) else [contents]
    for conv in convs:
        for turn in conv:
            if turn.get("role") == "agent" and turn.get("action"):
                chain.append(parse_action(turn["action"]))
    return chain


def rv_flags(chain):
    fired = set()
    for i, (tool, _a) in enumerate(chain):
        if not tool or any(hits(chain[j][0], APPROVAL) for j in range(i)):
            continue
        for key, pats, _ in OBLIGATIONS:
            if obligation_event(tool, pats):
                fired.add(key)
    return fired


def run_dir(files):
    unsafe = unsafe_fire = safe = safe_fire = 0
    for f in files:
        try: recs = json.load(open(f))
        except (ValueError, OSError): continue
        if not isinstance(recs, list): continue
        for r in recs:
            lab = r.get("label")
            chain = chain_of(r)
            fired = bool(rv_flags(chain))
            if lab in (1, "1", True):
                unsafe += 1; unsafe_fire += fired
            elif lab in (0, "0", False):
                safe += 1; safe_fire += fired
    return unsafe, unsafe_fire, safe, safe_fire


def report(name, s):
    u, uf, sa, sf = s
    print(f"{name:<16} unsafe={u:<4} detect={uf}/{u}={uf/max(1,u)*100:4.1f}%   "
          f"safe={sa:<4} FPR={sf}/{sa}={sf/max(1,sa)*100:4.1f}%")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="R-Judge data/ dir")
    a = ap.parse_args()
    allf = glob.glob(os.path.join(a.data, "**", "*.json"), recursive=True)
    print("R-Judge replay through generic RV obligations\n")
    report("ALL domains", run_dir(allf))
    iot = [f for f in allf if os.sep + "IoT" + os.sep in f]
    if iot:
        report("IoT only", run_dir(iot))


if __name__ == "__main__":
    main()
