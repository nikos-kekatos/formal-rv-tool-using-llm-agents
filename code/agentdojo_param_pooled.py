#!/usr/bin/env python3
"""Pool the parametric-vs-generic comparison across ALL AgentDojo model dirs to get
statistical power the single-model McNemar lacked. Sampling unit = one model x task
benign run (an independent recorded trajectory). Reports pooled benign firing rates,
the discordant pairs, and an EXACT two-sided McNemar p-value.
"""
import glob, json, os, argparse, statistics
from math import comb
import agentdojo_param as P1        # banking payee-provenance
import agentdojo_param2 as P2       # workspace external-recipient


def exact_mcnemar(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(comb(n, i) for i in range(0, k + 1)) * (0.5 ** n)
    return min(1.0, 2 * tail)


def exact_sign_test(pos, neg):
    """Two-sided exact sign test p-value; ties excluded by caller. pos = #decreased,
    neg = #increased."""
    n = pos + neg
    if n == 0:
        return 1.0
    k = min(pos, neg)
    tail = sum(comb(n, i) for i in range(0, k + 1)) * (0.5 ** n)
    return min(1.0, 2 * tail)


def per_dir_deltas(suite, analyse, root, keep=None):
    """Per model-dir generic-vs-parametric BENIGN firing on <suite>. Returns list of
    dicts: dir, nb (benign runs), gfire, pfire, red_pp (BFR reduction in pct points).
    Only dirs with >=1 benign run in the suite are returned. keep(name)->bool filters
    which model dirs are included (default: all)."""
    out = []
    for sd in sorted(glob.glob(os.path.join(root, "*", suite))):
        name = os.path.basename(os.path.dirname(sd))
        if keep is not None and not keep(name):
            continue
        nb = gfire = pfire = 0
        for f in glob.glob(os.path.join(sd, "**", "*.json"), recursive=True):
            try:
                d = json.load(open(f))
            except (ValueError, OSError):
                continue
            if not d.get("messages"):
                continue
            _has, g, p = analyse(d)
            atk = d.get("attack_type")
            if not atk and not d.get("injection_task_id"):        # benign
                nb += 1; gfire += g; pfire += p
        if nb == 0:
            continue
        red_pp = (gfire - pfire) / nb * 100
        out.append(dict(dir=name, nb=nb, gfire=gfire, pfire=pfire, red_pp=red_pp))
    return out


def sign_report(title, rows):
    dec = sum(1 for r in rows if r["gfire"] > r["pfire"])
    unch = sum(1 for r in rows if r["gfire"] == r["pfire"])
    inc = sum(1 for r in rows if r["gfire"] < r["pfire"])
    p = exact_sign_test(dec, inc)
    reds = [r["red_pp"] for r in rows]
    print(f"\n=== SIGN TEST: {title} ({len(rows)} model dirs) ===")
    print(f"  {'dir':<36}{'benign':>7}{'gen':>5}{'par':>5}{'BFR_gen%':>9}{'BFR_par%':>9}{'red_pp':>8}")
    for r in sorted(rows, key=lambda x: -x["red_pp"]):
        print(f"  {r['dir']:<36}{r['nb']:>7}{r['gfire']:>5}{r['pfire']:>5}"
              f"{r['gfire']/r['nb']*100:>9.1f}{r['pfire']/r['nb']*100:>9.1f}{r['red_pp']:>8.1f}")
    print(f"  decreased={dec}  unchanged={unch}  increased={inc}  of {len(rows)}")
    if reds:
        srt = sorted(reds)
        q1 = statistics.quantiles(reds, n=4)[0] if len(reds) >= 2 else reds[0]
        q3 = statistics.quantiles(reds, n=4)[2] if len(reds) >= 2 else reds[0]
        print(f"  BFR reduction (pct points): median={statistics.median(reds):.1f}  "
              f"IQR=[{q1:.1f},{q3:.1f}]  min={min(reds):.1f}  max={max(reds):.1f}")
    print(f"  exact two-sided sign-test p = {p:.3e}  "
          f"({'SIGNIFICANT' if p < 0.05 else 'ns'} at alpha=0.05; ties excluded)")


def pooled(suite, analyse, root):
    nb = gfire = pfire = bb = cc = 0
    at_tot = at_g = at_p = 0
    for sd in sorted(glob.glob(os.path.join(root, "*", suite))):
        for f in glob.glob(os.path.join(sd, "**", "*.json"), recursive=True):
            try:
                d = json.load(open(f))
            except (ValueError, OSError):
                continue
            if not d.get("messages"):
                continue
            has, g, p = analyse(d)
            atk = d.get("attack_type")
            if not atk and not d.get("injection_task_id"):        # benign
                nb += 1; gfire += g; pfire += p
                if g and not p: bb += 1
                elif p and not g: cc += 1
            elif atk and atk != "none" and d.get("injection_task_id") and d.get("security") is True:
                at_tot += 1; at_g += g; at_p += p
    return dict(nb=nb, gfire=gfire, pfire=pfire, b=bb, c=cc,
                at_tot=at_tot, at_g=at_g, at_p=at_p)


def report(name, s):
    p = exact_mcnemar(s["b"], s["c"])
    gr = s["gfire"] / max(1, s["nb"]) * 100
    pr = s["pfire"] / max(1, s["nb"]) * 100
    dg = s["at_g"] / max(1, s["at_tot"]) * 100
    dp = s["at_p"] / max(1, s["at_tot"]) * 100
    print(f"\n=== {name} (pooled over all model dirs) ===")
    print(f"  benign runs pooled: {s['nb']}")
    print(f"  benign firing rate  generic {s['gfire']}/{s['nb']}={gr:.1f}%  "
          f"parametric {s['pfire']}/{s['nb']}={pr:.1f}%")
    print(f"  discordant: generic-fires-only b={s['b']}  parametric-fires-only c={s['c']}")
    print(f"  EXACT McNemar two-sided p = {p:.2e}   "
          f"{'SIGNIFICANT' if p < 0.05 else 'not significant'} at alpha=0.05")
    print(f"  detection on successful attacks: generic {dg:.1f}%  parametric {dp:.1f}%  "
          f"(n={s['at_tot']})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="AgentDojo runs/ dir")
    ap.add_argument("--per-dir", action="store_true",
                    help="also emit per-model-dir BFR deltas + sign test")
    a = ap.parse_args()
    report("Banking payee-provenance", pooled("banking", P1.analyse, a.root))
    report("Workspace external-recipient", pooled("workspace", P2.analyse, a.root))
    if a.per_dir:
        sign_report("banking payee BFR (generic O3 -> parametric)",
                    per_dir_deltas("banking", P1.analyse, a.root))
        sign_report("workspace recipient BFR (generic O4 -> parametric)",
                    per_dir_deltas("workspace", P2.analyse, a.root))


if __name__ == "__main__":
    main()
