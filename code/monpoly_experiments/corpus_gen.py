#!/usr/bin/env python3
"""Synthetic POLICY-VALIDATION corpus generator (NOT attack data).

For each CPS/IoT policy we SYSTEMATICALLY generate compliant and violating traces
by varying zones/devices/users/time-windows/ordering/maintenance-mode/auth-freshness/
actuation-frequency. Every trace is emitted with an INTENDED label and (for
violations) the object id that MUST be flagged, plus a flag marking boundary traces
(an event placed exactly on / just off the ONCE / SINCE interval edge).

Output layout per policy P:
  corpus/P/P.sig, corpus/P/P.mfotl, corpus/P/logs/NNNN.log
  corpus/P/meta.json : {filename: {label, expected_ids, kind}}
label: "violating" (>=1 firing intended) | "compliant" (0 firings intended)
kind:  "core" | "boundary_on" (on edge, compliant) | "boundary_off" (just off, violating)
"""
import os, json, random, shutil

random.seed(1234)
ROOT = os.path.join(os.path.dirname(__file__), "corpus")

SIGS = {
 "p1": "maint_on()\nmaint_off()\nsetpoint(int,int)\ndamper_open(int)\ncompressor_start(int)\nbadge_auth(int)\ndoor_unlock(int)\n",
 "p2": "maint_on()\nmaint_off()\nsetpoint(int,int)\ndamper_open(int)\ncompressor_start(int)\nbadge_auth(int)\ndoor_unlock(int)\n",
 "p3": "maint_on()\nmaint_off()\nsetpoint(int,int)\ndamper_open(int)\ncompressor_start(int)\nbadge_auth(int)\ndoor_unlock(int)\n",
 "t1": "consent(int)\nexport(int)\n",
 "t2": "actuate(int,int)\n",
 "t3": "request(int)\nexecute(int)\n",
 "lock": "consent()\ngrant_access(int,int)\n",
}
FORMULAS = {
 "p1": "setpoint(z,v) AND v > 28 AND NOT ((NOT maint_off()) SINCE maint_on())\n",
 "p2": "compressor_start(z) AND NOT (ONCE[0,3] damper_open(z))\n",
 "p3": "door_unlock(d) AND NOT (ONCE[0,3] badge_auth(d))\n",
 "t1": "export(o) AND NOT (ONCE[0,24] consent(o))\n",
 "t2": "(c <- CNT s; d (ONCE[0,6] actuate(d,s))) AND c >= 3\n",
 "t3": "execute(x) AND NOT (ONCE[0,8] request(x))\n",
 "lock": "grant_access(g,p) AND p = 1 AND NOT (ONCE consent())\n",
}

def emit(events):
    """events: list of (t, 'pred(args)'). Return log text (one time point/line)."""
    return "".join(f"@{t} {e}\n" for t, e in events)

# ---- per-policy generators: yield (events, label, expected_ids, kind) ----

def gen_p1(i):
    z = 100 + i          # unique zone id per trace
    v_hi = random.randint(29, 45)
    v_lo = random.randint(15, 28)
    t = random.randint(0, 5)
    r = i % 4
    if r == 0:   # compliant: high setpoint DURING maintenance
        ev = [(t, "maint_on()"), (t+random.randint(1,4), f"setpoint({z},{v_hi})")]
        return ev, "compliant", [], "core"
    if r == 1:   # compliant: low setpoint, no maintenance (v<=28)
        ev = [(t, f"setpoint({z},{v_lo})")]
        return ev, "compliant", [], "core"
    if r == 2:   # violating: high setpoint, never in maintenance
        ev = [(t, f"setpoint({z},{v_hi})")]
        return ev, "violating", [z], "core"
    # violating: high setpoint AFTER maint_off (maint ended)
    ev = [(t, "maint_on()"), (t+2, "maint_off()"), (t+4, f"setpoint({z},{v_hi})")]
    return ev, "violating", [z], "core"

def gen_window(i, pred_pre, pred_act, W):
    """generic ONCE[0,W] precondition policy (p2,p3,t1,t3). Returns tuple."""
    oid = 200 + i
    t = random.randint(0, 5)
    r = i % 8
    if r == 0:   # compliant: precondition just before, within window
        d = random.randint(0, W)
        ev = [(t, f"{pred_pre}({oid})"), (t+d, f"{pred_act}({oid})")]
        return ev, "compliant", [], "core"
    if r == 1:   # compliant: precondition + irrelevant event, still within window
        d = random.randint(0, max(0, W-1))
        ev = [(t, f"{pred_pre}({oid})"), (t+d, f"{pred_pre}({oid+700})"),
              (t+d, f"{pred_act}({oid})")]
        return ev, "compliant", [], "core"
    if r == 2:   # compliant: two preconditions, latest within window
        ev = [(t, f"{pred_pre}({oid})"), (t+1, f"{pred_pre}({oid})"),
              (t+2, f"{pred_act}({oid})")]
        return ev, "compliant", [], "core"
    if r == 3:   # boundary_on: precondition exactly W units before -> compliant
        ev = [(t, f"{pred_pre}({oid})"), (t+W, f"{pred_act}({oid})")]
        return ev, "compliant", [], "boundary_on"
    if r == 4:   # violating: action with NO precondition at all
        ev = [(t, f"{pred_act}({oid})")]
        return ev, "violating", [oid], "core"
    if r == 5:   # violating: precondition too old (window+ small extra)
        ev = [(t, f"{pred_pre}({oid})"), (t+W+random.randint(1,5), f"{pred_act}({oid})")]
        return ev, "violating", [oid], "core"
    if r == 6:   # violating: precondition for a DIFFERENT object id
        other = oid + 500
        ev = [(t, f"{pred_pre}({other})"), (t+1, f"{pred_act}({oid})")]
        return ev, "violating", [oid], "core"
    # boundary_off: precondition W+1 before -> violating
    ev = [(t, f"{pred_pre}({oid})"), (t+W+1, f"{pred_act}({oid})")]
    return ev, "violating", [oid], "boundary_off"

def gen_t2(i):
    d = 300 + i          # unique device id per trace
    t = random.randint(0, 5)
    r = i % 6
    if r == 0:   # compliant: only 2 actuations within window
        ev = [(t, f"actuate({d},1)"), (t+1, f"actuate({d},2)")]
        return ev, "compliant", [], "core"
    if r == 1:   # compliant: 3 actuations but spread > window apart (never 3-in-6)
        ev = [(t, f"actuate({d},1)"), (t+7, f"actuate({d},2)"), (t+14, f"actuate({d},3)")]
        return ev, "compliant", [], "core"
    if r == 2:   # violating: 3 distinct actuations within 6
        ev = [(t, f"actuate({d},1)"), (t+2, f"actuate({d},2)"), (t+4, f"actuate({d},3)")]
        return ev, "violating", [d], "core"
    if r == 3:   # violating: 4 actuations quickly
        ev = [(t, f"actuate({d},1)"), (t+1, f"actuate({d},2)"),
              (t+2, f"actuate({d},3)"), (t+3, f"actuate({d},4)")]
        return ev, "violating", [d], "core"
    if r == 4:   # boundary_on: 3 actuations spanning exactly 6 (0,3,6) -> fires
        ev = [(t, f"actuate({d},1)"), (t+3, f"actuate({d},2)"), (t+6, f"actuate({d},3)")]
        return ev, "violating", [d], "boundary_on"
    # boundary_off: 3 spanning 7 (0,1,7): at last, oldest drops out -> count 2 -> compliant
    ev = [(t, f"actuate({d},1)"), (t+1, f"actuate({d},2)"), (t+7, f"actuate({d},3)")]
    return ev, "compliant", [], "boundary_off"

def gen_lock(i):
    g = 400 + i
    t = random.randint(0, 5)
    r = i % 4
    if r == 0:   # compliant: consent before grant of protected resource (p=1)
        ev = [(t, "consent()"), (t+2, f"grant_access({g},1)")]
        return ev, "compliant", [], "core"
    if r == 1:   # compliant: grant of non-protected resource (p!=1), no consent needed
        ev = [(t, f"grant_access({g},{random.choice([0,2,3])})")]
        return ev, "compliant", [], "core"
    if r == 2:   # violating: protected grant, no consent ever
        ev = [(t, f"grant_access({g},1)")]
        return ev, "violating", [g], "core"
    # violating: protected grant, consent comes only AFTER (too late)
    ev = [(t, f"grant_access({g},1)"), (t+3, "consent()")]
    return ev, "violating", [g], "core"

GENERATORS = {
 "p1": gen_p1,
 "p2": lambda i: gen_window(i, "damper_open", "compressor_start", 3),
 "p3": lambda i: gen_window(i, "badge_auth", "door_unlock", 3),
 "t1": lambda i: gen_window(i, "consent", "export", 24),
 "t2": gen_t2,
 "t3": lambda i: gen_window(i, "request", "execute", 8),
 "lock": gen_lock,
}

N = 200  # ~ balanced comp/viol per policy by construction

def build():
    if os.path.exists(ROOT):
        shutil.rmtree(ROOT)
    summary = {}
    for pol, gen in GENERATORS.items():
        pdir = os.path.join(ROOT, pol); logs = os.path.join(pdir, "logs")
        os.makedirs(logs)
        open(os.path.join(pdir, f"{pol}.sig"), "w").write(SIGS[pol])
        open(os.path.join(pdir, f"{pol}.mfotl"), "w").write(FORMULAS[pol])
        meta = {}
        nc = nv = nb = 0
        for i in range(N):
            ev, label, exp, kind = gen(i)
            # ensure timestamps non-decreasing
            ev = sorted(ev, key=lambda x: x[0])
            fn = f"{i:04d}.log"
            open(os.path.join(logs, fn), "w").write(emit(ev))
            meta[fn] = {"label": label, "expected_ids": exp, "kind": kind}
            nc += label == "compliant"; nv += label == "violating"
            nb += kind != "core"
        json.dump(meta, open(os.path.join(pdir, "meta.json"), "w"), indent=1)
        summary[pol] = {"n": N, "compliant": nc, "violating": nv, "boundary": nb}
    json.dump(summary, open(os.path.join(ROOT, "summary.json"), "w"), indent=1)
    for p, s in summary.items():
        print(p, s)

if __name__ == "__main__":
    build()
