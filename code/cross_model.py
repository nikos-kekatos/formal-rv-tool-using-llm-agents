#!/usr/bin/env python3
"""RESULT 4 -- CROSS-MODEL table + SIGN TEST (AgentDojo, no-defense base models).

For every base (no-defense) model dir present under runs/ we report:
  * successful attacked runs (security==True over attacked runs);
  * benign runs (attack_type unset, no injection);
  * detection %  = generic RV (O1-O5) fires on a successful attack / successful;
  * BFR %        = generic RV fires on a benign run / benign;
  * banking payee BFR reduction = generic-O3 banking BFR - parametric-payee banking BFR
    (percentage points; >=0 since parametric is a subset of generic).

Then a SIGN TEST across model dirs (via agentdojo_param_pooled.per_dir_deltas /
sign_report): in how many dirs the banking payee BFR decreased / unchanged / increased,
median/IQR/min/max of the per-model reduction, and the exact two-sided sign-test p.

Defense-variant dirs (suffix -repeat_user_prompt / -tool_filter / -spotlighting* /
-transformers_pi_detector) are excluded; this is the base-model view.
"""
import argparse, glob, json, os
from agentdojo_rv import chain_from_run, rv_flags
import agentdojo_param as P1
from agentdojo_param_pooled import per_dir_deltas, sign_report

DEF_SUFFIXES = ("-repeat_user_prompt", "-tool_filter", "-spotlighting_with_delimiting",
                "-transformers_pi_detector")


def is_base(name):
    return not any(name.endswith(s) for s in DEF_SUFFIXES)


def model_stats(mdir):
    succ = det = benign = bfr = 0
    for f in glob.glob(os.path.join(mdir, "**", "*.json"), recursive=True):
        try:
            d = json.load(open(f))
        except (ValueError, OSError):
            continue
        chain = chain_from_run(d)
        if not chain:
            continue
        fired = bool(rv_flags(chain))
        at = d.get("attack_type")
        if at and at != "none" and d.get("injection_task_id"):
            if d.get("security") is True:
                succ += 1; det += fired
        elif not at and not d.get("injection_task_id"):
            benign += 1; bfr += fired
    return succ, det, benign, bfr


def banking_payee_reduction(mdir):
    """(generic_bfr_pct, param_bfr_pct, reduction_pp) on the model's banking benign
    runs, or None if no banking benign runs."""
    bdir = os.path.join(mdir, "banking")
    if not os.path.isdir(bdir):
        return None
    nb = g = p = 0
    for f in glob.glob(os.path.join(bdir, "**", "*.json"), recursive=True):
        try:
            d = json.load(open(f))
        except (ValueError, OSError):
            continue
        if not d.get("messages"):
            continue
        _h, gg, pp = P1.analyse(d)
        at = d.get("attack_type")
        if not at and not d.get("injection_task_id"):
            nb += 1; g += gg; p += pp
    if nb == 0:
        return None
    return g / nb * 100, p / nb * 100, (g - p) / nb * 100


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="AgentDojo runs/ dir")
    a = ap.parse_args()
    dirs = sorted(d for d in os.listdir(a.root)
                  if os.path.isdir(os.path.join(a.root, d)) and is_base(d))

    print("=== CROSS-MODEL (base, no-defense) ===")
    hdr = (f"{'model':<36}{'succ':>6}{'benign':>7}{'detect%':>9}{'BFR%':>8}"
           f"{'bank gBFR%':>11}{'bank pBFR%':>11}{'red_pp':>8}")
    print(hdr)
    reported = 0
    for m in dirs:
        mdir = os.path.join(a.root, m)
        succ, det, ben, bfr = model_stats(mdir)
        if succ == 0 and ben == 0:
            continue
        reported += 1
        red = banking_payee_reduction(mdir)
        detp = det / succ * 100 if succ else float('nan')
        bfrp = bfr / ben * 100 if ben else float('nan')
        if red:
            g, p, r = red
            tail = f"{g:>11.1f}{p:>11.1f}{r:>8.1f}"
        else:
            tail = f"{'-':>11}{'-':>11}{'-':>8}"
        print(f"{m:<36}{succ:>6}{ben:>7}{detp:>9.1f}{bfrp:>8.1f}{tail}")
    print(f"\nbase model dirs reported: {reported}")

    # sign test across BASE model dirs (reuses the extended pooled module)
    sign_report("banking payee BFR (generic O3 -> parametric), base dirs",
                per_dir_deltas("banking", P1.analyse, a.root, keep=is_base))


if __name__ == "__main__":
    main()
