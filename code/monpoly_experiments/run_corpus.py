#!/usr/bin/env python3
"""Feed the synthetic corpus through the REAL MonPoly (docker rv-fabric-impl-backend).

Per policy we run ONE container that loops the unmodified monpoly binary over every
trace log (a fresh monpoly process per trace => full isolation, so global-state
policies p1/lock never leak across traces). We parse firings, derive the verdict
(fired>=1 => violating, else compliant) and compare to the intended label.

Metrics per policy:
  verdict_acc  : fraction of traces whose MonPoly verdict == intended label
  binding_acc  : among violating traces, fraction where the flagged tuple contains
                 the expected object/zone/device id (parameter-binding correctness)
  boundary_acc : among boundary traces (event exactly on / just off the edge),
                 fraction whose verdict matches intended label
"""
import os, re, json, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
IMG = "rv-fabric-impl-backend"
CORPUS = os.path.join(HERE, "corpus")
POLICIES = ["p1", "p2", "p3", "t1", "t2", "t3", "lock"]
TUPLE_RE = re.compile(r"\):\s*\((.*)\)\s*$")

def run_policy(pol):
    pdir = os.path.join(CORPUS, pol)
    meta = json.load(open(os.path.join(pdir, "meta.json")))
    loop = (f'for f in /w/logs/*.log; do echo "@@@FILE $(basename $f)"; '
            f'monpoly -sig /w/{pol}.sig -formula /w/{pol}.mfotl -log "$f" 2>/dev/null; done')
    out = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{pdir}:/w", "--entrypoint", "sh", IMG, "-c", loop],
        capture_output=True, text=True).stdout

    # split into per-file blocks
    blocks, cur = {}, None
    for ln in out.splitlines():
        if ln.startswith("@@@FILE "):
            cur = ln[len("@@@FILE "):].strip(); blocks[cur] = []
        elif cur is not None:
            blocks[cur].append(ln)

    v_ok = v_tot = 0
    b_ok = b_tot = 0
    bind_ok = bind_tot = 0
    fp = fn = 0
    for fn_name, info in meta.items():
        lines = blocks.get(fn_name, [])
        tuples = [TUPLE_RE.search(l).group(1) for l in lines if TUPLE_RE.search(l)]
        fired = len(tuples) > 0
        verdict = "violating" if fired else "compliant"
        match = verdict == info["label"]
        v_ok += match; v_tot += 1
        if not match:
            if info["label"] == "compliant": fp += 1
            else: fn += 1
        if info["kind"] != "core":
            b_ok += match; b_tot += 1
        if info["label"] == "violating":
            bind_tot += 1
            ids = set()
            for tp in tuples:
                for x in re.findall(r"-?\d+", tp):
                    ids.add(int(x))
            if all(eid in ids for eid in info["expected_ids"]):
                bind_ok += 1
    return {
        "policy": pol, "n": v_tot,
        "verdict_acc": round(v_ok / v_tot, 4), "verdict_ok": v_ok,
        "false_pos": fp, "false_neg": fn,
        "binding_acc": round(bind_ok / max(1, bind_tot), 4),
        "binding_ok": bind_ok, "binding_tot": bind_tot,
        "boundary_acc": round(b_ok / max(1, b_tot), 4) if b_tot else None,
        "boundary_ok": b_ok, "boundary_tot": b_tot,
    }

if __name__ == "__main__":
    res = [run_policy(p) for p in POLICIES]
    json.dump(res, open(os.path.join(HERE, "corpus_results.json"), "w"), indent=1)
    hdr = ["policy","n","verdict_acc","false_pos","false_neg","binding_acc","boundary_acc"]
    print(",".join(hdr))
    for r in res:
        print(",".join(str(r[k]) for k in hdr))
