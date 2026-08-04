#!/usr/bin/env python3
"""Extended offline AgentDojo comparisons: across models, vs AgentDojo's own
built-in defenses, and per-suite. Reuses the RV replay from agentdojo_rv.

Metrics per run set:
  attacked            = runs with a real attack (attack_type set, injection set)
  ASR                 = fraction of attacked runs with security==True (AgentDojo's
                        own label = attack succeeded)
  RV-detect(success)  = of successful attacks, fraction where an obligation fires
  RV residual ASR     = successful AND RV did NOT fire, over attacked (post-hoc:
                        if the shield gates the flagged call the attack is prevented)
  over-block          = fraction of benign runs where an obligation fires
NB the defenses' ASR come from AgentDojo actually running with the defense; our RV
residual is a post-hoc replay estimate -- labelled as such, not identical methodology.
"""
import argparse, glob, json, os
from agentdojo_rv import chain_from_run, rv_flags


def stats(runs_dir):
    atk = succ = rv_succ = benign = benign_flag = 0
    for f in glob.glob(os.path.join(runs_dir, "**", "*.json"), recursive=True):
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
            atk += 1
            if d.get("security") is True:
                succ += 1
                if fired:
                    rv_succ += 1
        elif not at and not d.get("injection_task_id"):
            benign += 1
            if fired:
                benign_flag += 1
    return dict(atk=atk, succ=succ, rv_succ=rv_succ, benign=benign, benign_flag=benign_flag)


def fmt(s):
    atk, succ, rv = s["atk"], s["succ"], s["rv_succ"]
    asr = succ / atk * 100 if atk else 0
    det = rv / succ * 100 if succ else 0
    resid = (succ - rv) / atk * 100 if atk else 0
    ob = s["benign_flag"] / s["benign"] * 100 if s["benign"] else 0
    return f"{atk:>5} {asr:>6.1f}% {det:>7.1f}% {resid:>8.1f}% {ob:>7.1f}%"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="AgentDojo runs/ dir")
    a = ap.parse_args()
    R = a.root
    hdr = f"{'run set':<40} {'atk':>5} {'ASR':>6} {'RVdet':>7} {'RVresid':>8} {'overblk':>7}"

    print("=== (1) ACROSS MODELS (no defense) ===")
    print(hdr)
    models = ["gpt-4o-2024-05-13", "gpt-4-turbo-2024-04-09", "gpt-4o-mini-2024-07-18",
              "claude-3-5-sonnet-20241022", "claude-3-opus-20240229",
              "claude-3-7-sonnet-20250219", "gemini-1.5-pro-002",
              "gemini-2.0-flash-001", "command-r-plus", "gpt-3.5-turbo-0125",
              "meta-llama_Llama-3.3-70B-Instruct"]
    for m in models:
        d = os.path.join(R, m)
        if os.path.isdir(d):
            print(f"{m:<40} {fmt(stats(d))}")

    print("\n=== (2) vs AGENTDOJO'S OWN DEFENSES (gpt-4o) ===")
    print(hdr)
    base = "gpt-4o-2024-05-13"
    for suffix, label in [("", "none (no defense)"),
                          ("-repeat_user_prompt", "repeat_user_prompt"),
                          ("-tool_filter", "tool_filter"),
                          ("-spotlighting_with_delimiting", "spotlighting"),
                          ("-transformers_pi_detector", "pi_detector")]:
        d = os.path.join(R, base + suffix)
        if os.path.isdir(d):
            print(f"{label:<40} {fmt(stats(d))}")

    print("\n=== (3) PER SUITE (gpt-4o, no defense) ===")
    print(hdr)
    for suite in ["banking", "slack", "travel", "workspace"]:
        d = os.path.join(R, base, suite)
        if os.path.isdir(d):
            print(f"{suite:<40} {fmt(stats(d))}")


if __name__ == "__main__":
    main()
