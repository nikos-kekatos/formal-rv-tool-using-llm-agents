#!/usr/bin/env python3
"""Metamorphic / boundary tests against the REAL MonPoly.

For each policy we take a base trace and apply ONE single change, with a predicted
effect on the verdict (a metamorphic relation). Transformation classes:

  move_across_window : move the enabling event inside vs outside the ONCE window
  change_identifier  : change the object/zone/door/device/recipient id
  reorder            : move the enabling event to AFTER the guarded action
  insert_irrelevant  : add an unrelated event  (verdict MUST NOT change)
  duplicate_action   : duplicate the guarded action (verdict MUST NOT change)
  boundary           : enabling event exactly on the edge vs one tick past it

Each case is (events, expected_fire). We run every case through monpoly and score a
pass when MonPoly's verdict (fired? ) equals expected_fire. Pass rate is reported
per transformation class and per policy.
"""
import os, re, json, subprocess, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
IMG = "rv-fabric-impl-backend"
ROOT = os.path.join(HERE, "meta")
TUPLE_RE = re.compile(r"\):\s*\((.*)\)\s*$")

SIGS = {
 "p2": "damper_open(int)\ncompressor_start(int)\nbadge_auth(int)\ndoor_unlock(int)\n",
 "p3": "damper_open(int)\ncompressor_start(int)\nbadge_auth(int)\ndoor_unlock(int)\n",
 "t1": "consent(int)\nexport(int)\n",
 "t3": "request(int)\nexecute(int)\n",
 "t2": "actuate(int,int)\n",
 "p1": "maint_on()\nmaint_off()\nsetpoint(int,int)\ndamper_open(int)\n",
 "lock": "consent()\ngrant_access(int,int)\n",
}
FORMULAS = {
 "p2": "compressor_start(z) AND NOT (ONCE[0,3] damper_open(z))\n",
 "p3": "door_unlock(d) AND NOT (ONCE[0,3] badge_auth(d))\n",
 "t1": "export(o) AND NOT (ONCE[0,24] consent(o))\n",
 "t3": "execute(x) AND NOT (ONCE[0,8] request(x))\n",
 "t2": "(c <- CNT s; d (ONCE[0,6] actuate(d,s))) AND c >= 3\n",
 "p1": "setpoint(z,v) AND v > 28 AND NOT ((NOT maint_off()) SINCE maint_on())\n",
 "lock": "grant_access(g,p) AND p = 1 AND NOT (ONCE consent())\n",
}

WINDOW = {"p2": ("damper_open", "compressor_start", 3),
          "p3": ("badge_auth", "door_unlock", 3),
          "t1": ("consent", "export", 24),
          "t3": ("request", "execute", 8)}

def cases_window(pol, k):
    pre, act, W = WINDOW[pol]
    oid = 10*k + 1; other = oid + 1000
    C = []
    # move_across_window
    C.append(("move_across_window", [(0, f"{pre}({oid})"), (W, f"{act}({oid})")], False))
    C.append(("move_across_window", [(0, f"{pre}({oid})"), (W+2, f"{act}({oid})")], True))
    # change_identifier: base compliant, then break the id match
    C.append(("change_identifier", [(0, f"{pre}({oid})"), (1, f"{act}({oid})")], False))
    C.append(("change_identifier", [(0, f"{pre}({other})"), (1, f"{act}({oid})")], True))
    # reorder: enabling event AFTER the action
    C.append(("reorder", [(0, f"{pre}({oid})"), (1, f"{act}({oid})")], False))
    C.append(("reorder", [(0, f"{act}({oid})"), (1, f"{pre}({oid})")], True))
    # insert_irrelevant: must not change verdict (both stay compliant)
    C.append(("insert_irrelevant", [(0, f"{pre}({oid})"), (1, f"{act}({oid})")], False))
    C.append(("insert_irrelevant", [(0, f"{pre}({oid})"), (1, f"{pre}({other})"),
                                    (1, f"{act}({oid})")], False))
    # duplicate_action: must not change verdict (violating stays violating)
    C.append(("duplicate_action", [(0, f"{act}({oid})")], True))
    C.append(("duplicate_action", [(0, f"{act}({oid})"), (1, f"{act}({oid})")], True))
    # boundary: exactly on edge (compliant) vs one tick past (violating)
    C.append(("boundary", [(0, f"{pre}({oid})"), (W, f"{act}({oid})")], False))
    C.append(("boundary", [(0, f"{pre}({oid})"), (W+1, f"{act}({oid})")], True))
    return C

def cases_t2(k):
    d = 10*k + 1; d2 = d + 1000
    C = []
    C.append(("move_across_window", [(0, f"actuate({d},1)"), (3, f"actuate({d},2)"),
                                     (6, f"actuate({d},3)")], True))
    C.append(("move_across_window", [(0, f"actuate({d},1)"), (1, f"actuate({d},2)"),
                                     (7, f"actuate({d},3)")], False))
    C.append(("change_identifier", [(0, f"actuate({d},1)"), (1, f"actuate({d},2)"),
                                    (2, f"actuate({d},3)")], True))
    C.append(("change_identifier", [(0, f"actuate({d},1)"), (1, f"actuate({d},2)"),
                                    (2, f"actuate({d2},3)")], False))  # 3rd on other device -> 2 only
    C.append(("insert_irrelevant", [(0, f"actuate({d},1)"), (1, f"actuate({d},2)"),
                                    (2, f"actuate({d},3)")], True))
    C.append(("insert_irrelevant", [(0, f"actuate({d},1)"), (1, f"actuate({d2},9)"),
                                    (1, f"actuate({d},2)"), (2, f"actuate({d},3)")], True))
    C.append(("duplicate_action", [(0, f"actuate({d},1)"), (1, f"actuate({d},2)")], False))
    C.append(("duplicate_action", [(0, f"actuate({d},1)"), (0, f"actuate({d},1)"),
                                   (1, f"actuate({d},2)")], False))  # dup same seq -> still 2 distinct
    C.append(("boundary", [(0, f"actuate({d},1)"), (3, f"actuate({d},2)"),
                           (6, f"actuate({d},3)")], True))
    C.append(("boundary", [(0, f"actuate({d},1)"), (1, f"actuate({d},2)"),
                           (7, f"actuate({d},3)")], False))
    return C

def cases_p1(k):
    z = 10*k + 1; v = 35; z2 = z + 1000
    C = []
    C.append(("move_across_window", [(0, "maint_on()"), (2, f"setpoint({z},{v})")], False))
    C.append(("move_across_window", [(0, "maint_on()"), (1, "maint_off()"),
                                     (2, f"setpoint({z},{v})")], True))
    C.append(("change_identifier", [(0, f"setpoint({z},{v})")], True))
    C.append(("change_identifier", [(0, f"setpoint({z2},{v})")], True))  # still fires, other zone
    C.append(("reorder", [(0, "maint_on()"), (1, f"setpoint({z},{v})")], False))
    C.append(("reorder", [(0, f"setpoint({z},{v})"), (1, "maint_on()")], True))
    C.append(("insert_irrelevant", [(0, "maint_on()"), (1, f"setpoint({z},{v})")], False))
    C.append(("insert_irrelevant", [(0, "maint_on()"), (1, "damper_open(9)"),
                                    (2, f"setpoint({z},{v})")], False))
    C.append(("duplicate_action", [(0, f"setpoint({z},{v})")], True))
    C.append(("duplicate_action", [(0, f"setpoint({z},{v})"), (1, f"setpoint({z},{v})")], True))
    return C

def cases_lock(k):
    g = 10*k + 1; g2 = g + 1000
    C = []
    C.append(("move_across_window", [(0, "consent()"), (2, f"grant_access({g},1)")], False))
    C.append(("move_across_window", [(0, f"grant_access({g},1)"), (2, "consent()")], True))
    C.append(("change_identifier", [(0, "consent()"), (2, f"grant_access({g},1)")], False))
    C.append(("change_identifier", [(0, f"grant_access({g},1)")], True))   # protected, no consent
    C.append(("change_identifier", [(0, f"grant_access({g},2)")], False))  # p!=1 -> never fires
    C.append(("reorder", [(0, "consent()"), (1, f"grant_access({g},1)")], False))
    C.append(("reorder", [(0, f"grant_access({g},1)"), (1, "consent()")], True))
    C.append(("insert_irrelevant", [(0, "consent()"), (1, f"grant_access({g2},2)"),
                                    (2, f"grant_access({g},1)")], False))
    C.append(("duplicate_action", [(0, f"grant_access({g},1)")], True))
    C.append(("duplicate_action", [(0, f"grant_access({g},1)"), (1, f"grant_access({g},1)")], True))
    return C

def build():
    if os.path.exists(ROOT):
        shutil.rmtree(ROOT)
    index = {}
    for pol in ["p2","p3","t1","t3","t2","p1","lock"]:
        pdir = os.path.join(ROOT, pol); logs = os.path.join(pdir, "logs")
        os.makedirs(logs)
        open(os.path.join(pdir, f"{pol}.sig"), "w").write(SIGS[pol])
        open(os.path.join(pdir, f"{pol}.mfotl"), "w").write(FORMULAS[pol])
        allc = []
        for k in range(10):                 # 10 instances per class (varied ids/times)
            if pol in WINDOW: allc += cases_window(pol, k)
            elif pol == "t2": allc += cases_t2(k)
            elif pol == "p1": allc += cases_p1(k)
            elif pol == "lock": allc += cases_lock(k)
        meta = {}
        for j, (cls, ev, exp) in enumerate(allc):
            ev = sorted(ev, key=lambda x: x[0])
            fn = f"{j:04d}.log"
            open(os.path.join(logs, fn), "w").write("".join(f"@{t} {e}\n" for t, e in ev))
            meta[fn] = {"cls": cls, "expected_fire": exp}
        json.dump(meta, open(os.path.join(pdir, "meta.json"), "w"), indent=1)
        index[pol] = len(allc)
    return index

def run_policy(pol):
    pdir = os.path.join(ROOT, pol)
    meta = json.load(open(os.path.join(pdir, "meta.json")))
    loop = (f'for f in /w/logs/*.log; do echo "@@@FILE $(basename $f)"; '
            f'monpoly -sig /w/{pol}.sig -formula /w/{pol}.mfotl -log "$f" 2>/dev/null; done')
    out = subprocess.run(["docker","run","--rm","-v",f"{pdir}:/w","--entrypoint","sh",
                          IMG,"-c",loop], capture_output=True, text=True).stdout
    blocks, cur = {}, None
    for ln in out.splitlines():
        if ln.startswith("@@@FILE "):
            cur = ln[8:].strip(); blocks[cur] = []
        elif cur is not None:
            blocks[cur].append(ln)
    per_cls = {}
    fails = []
    for fn, info in meta.items():
        fired = any(TUPLE_RE.search(l) for l in blocks.get(fn, []))
        ok = fired == info["expected_fire"]
        d = per_cls.setdefault(info["cls"], [0,0])
        d[0] += ok; d[1] += 1
        if not ok: fails.append((pol, fn, info, fired))
    return per_cls, fails

if __name__ == "__main__":
    build()
    classes = ["move_across_window","change_identifier","reorder",
               "insert_irrelevant","duplicate_action","boundary"]
    agg = {c: [0,0] for c in classes}
    per_policy = {}
    all_fails = []
    for pol in ["p2","p3","t1","t3","t2","p1","lock"]:
        pc, fails = run_policy(pol)
        all_fails += fails
        pok = pn = 0
        for c, (ok, n) in pc.items():
            agg[c][0] += ok; agg[c][1] += n; pok += ok; pn += n
        per_policy[pol] = (pok, pn)
    print("=== pass rate per transformation class (all policies) ===")
    for c in classes:
        ok, n = agg[c]
        if n: print(f"  {c:20s} {ok}/{n} = {ok/n*100:.1f}%")
    print("=== pass rate per policy ===")
    tot_ok = tot_n = 0
    for pol,(ok,n) in per_policy.items():
        print(f"  {pol:5s} {ok}/{n} = {ok/n*100:.1f}%"); tot_ok+=ok; tot_n+=n
    print(f"=== OVERALL {tot_ok}/{tot_n} = {tot_ok/tot_n*100:.1f}% ===")
    if all_fails:
        print("FAILURES:")
        for f in all_fails: print("  ", f)
    json.dump({"agg":agg,"per_policy":per_policy,"fails":all_fails},
              open(os.path.join(HERE,"meta_results.json"),"w"), indent=1)
