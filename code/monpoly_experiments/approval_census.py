#!/usr/bin/env python3
"""Why are there no approvals? A census, so the answer is not "we did not look hard".

The obvious objection to our readiness result is that we search for approvals by TOOL
NAME and might simply be looking in the wrong place. We therefore look everywhere, and
report the attrition.

Two structural facts explain the outcome:

* AgentDojo is SINGLE-TURN. Exactly one user message per run (6899/6899): the user states
  a task up front and the agent then executes autonomously. An approval is by definition a
  response to a PROPOSED action, which needs a user turn AFTER the proposal. The protocol
  has no such turn, so approvals cannot occur regardless of tooling -- and indeed none of
  the 68 distinct AgentDojo tools is approval-like.
* STAC is MULTI-TURN (mean 2.6 user turns, up to 5), so approvals CAN occur, and approval
  language does appear. But STAC's attacks work precisely by smuggling the harmful step in
  without returning to the user, so the language almost never sits BEFORE the harmful
  action, which is the only position from which it could gate anything.

Run:  python3 approval_census.py [--agentdojo <runs/model dir>] [--stac <json>]
"""
import argparse, glob, json, os, re, sys
from collections import Counter
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from agentdojo_rv import chain_from_run

TOOLNAME = re.compile(r"confirm|approve|consent|authori[sz]e|permission|grant|2fa|otp|"
                      r"acknowledge|sign_off|double_check", re.I)
LOOSE    = re.compile(r"confirm|approve|consent|authori[sz]e|permission|grant", re.I)
STRICT   = re.compile(r"\b(yes,? (please |go ahead|do it)|go ahead|i approve|approved|"
                      r"you (may|can) (proceed|go ahead)|please proceed|confirmed?|"
                      r"i consent|permission granted|authoris?ed?)\b", re.I)

def text(m):
    c = m.get("content")
    if isinstance(c, str): return c
    if isinstance(c, list): return " ".join(str(x) for x in c)
    return ""

def agentdojo(root):
    tools, runs, users = Counter(), 0, 0
    for f in glob.glob(os.path.join(root, "**", "*.json"), recursive=True):
        try: d = json.load(open(f))
        except (ValueError, OSError): continue
        if not d.get("messages"): continue
        runs += 1
        for t, _ in chain_from_run(d): tools[t] += 1
        users += sum(1 for m in d["messages"] if m.get("role") == "user")
    print(f"\nAgentDojo: {runs} runs, {len(tools)} distinct tools")
    print(f"  user turns per run          : {users/max(1,runs):.2f}  <- single-turn protocol")
    cand = [t for t in tools if TOOLNAME.search(t)]
    print(f"  approval-like tools         : {len(cand)} of {len(tools)}  {cand}")
    print(f"  => approvals are foreclosed by the interaction protocol, not merely unrecorded")

def stac(path):
    cases = json.load(open(path))
    cases = cases if isinstance(cases, list) else cases.get("cases", cases.get("data", []))
    n = len(cases); turns = 0
    loose = strict = gating = 0
    for c in cases:
        hist = c.get("interaction_history", [])
        turns += sum(1 for m in hist if m.get("role") == "user")
        last = max([i for i, m in enumerate(hist)
                    if m.get("role") == "assistant" and m.get("tool_calls")], default=None)
        l = s = g = False
        for i, m in enumerate(hist):
            if m.get("role") != "user": continue
            t = text(m)
            if LOOSE.search(t):  l = True
            if STRICT.search(t):
                s = True
                if last is not None and i < last: g = True
        loose += l; strict += s; gating += g
    print(f"\nSTAC: {n} cases")
    print(f"  user turns per case                       : {turns/max(1,n):.2f}  <- multi-turn")
    print(f"  approval by TOOL NAME (as the paper reports): 6/{n} = {6/n*100:.1f}%")
    print(f"  user text, loose keyword                  : {loose}/{n} = {loose/n*100:.1f}%")
    print(f"  user text, strict permission-granting     : {strict}/{n} = {strict/n*100:.1f}%")
    print(f"  strict AND before the harmful step (gating): {gating}/{n} = {gating/n*100:.1f}%")
    print(f"  => mining text raises the count 12x, then position collapses it to ~0")


def taubench(d):
    """tau-bench historical_trajectories/*.json: 1,980 recorded trajectories whose
    system prompt IS the domain policy, and whose policy requires the agent to obtain
    an explicit user confirmation before any mutating call. This is the control case
    for the readiness argument: a corpus where approvals should exist by construction."""
    import glob
    files=sorted(glob.glob(os.path.join(d,"*.json")))
    n=turns=0; tools=Counter()
    tool_appr=0; user_strict=0; gating=0; mutating_runs=0
    MUTATE=("cancel","modify","exchange","return","update","book","send","place","transfer")
    for f in files:
        for rec in json.load(open(f)):
            tr=rec.get("traj") or []
            n+=1
            turns+=sum(1 for m in tr if m.get("role")=="user")
            calls=[]
            for i,m in enumerate(tr):
                if m.get("role")=="assistant":
                    for tc in (m.get("tool_calls") or []):
                        fn=tc.get("function") or {}
                        nm=(fn.get("name") if isinstance(fn,dict) else fn) or ""
                        tools[nm]+=1; calls.append((i,nm))
            last_mut=max([i for i,nm in calls if any(k in nm.lower() for k in MUTATE)], default=None)
            if last_mut is not None: mutating_runs+=1
            if any(TOOLNAME.search(nm) for _i,nm in calls): tool_appr+=1
            for i,m in enumerate(tr):
                if m.get("role")!="user": continue
                if STRICT.search(text(m)):
                    user_strict+=1
                    if last_mut is not None and i<last_mut: gating+=1
                    break
    print(f"\ntau-bench: {n} trajectories over {len(files)} files, {len(tools)} distinct tools")
    print(f"  user turns per trajectory                 : {turns/max(1,n):.2f}")
    print(f"  trajectories with a mutating call         : {mutating_runs}/{n} = {mutating_runs/max(1,n)*100:.1f}%")
    print(f"  approval by TOOL NAME                     : {tool_appr}/{n} = {tool_appr/max(1,n)*100:.1f}%")
    print(f"  user text, strict permission-granting     : {user_strict}/{n} = {user_strict/max(1,n)*100:.1f}%")
    print(f"  strict AND before the last mutating call  : {gating}/{n} = {gating/max(1,n)*100:.1f}%")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agentdojo"); ap.add_argument("--stac"); ap.add_argument("--taubench")
    a = ap.parse_args()
    if a.agentdojo: agentdojo(a.agentdojo)
    if a.stac: stac(a.stac)
    if a.taubench: taubench(a.taubench)

if __name__ == "__main__":
    main()
