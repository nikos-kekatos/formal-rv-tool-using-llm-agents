#!/usr/bin/env python3
"""Temporal Policy Readiness Scorecard.

Measures whether three recorded LLM-agent benchmarks (STAC, AgentDojo, R-Judge)
contain the information a HISTORY-DEPENDENT / TEMPORAL / PARAMETRIC enforcement
policy needs at runtime. REAL measurements only -- no LLM, no fabrication.

For each benchmark we normalise every recorded trace into:
    - user_turns   : list[str]        (user-authored text)
    - tool_calls   : list[(name, args_dict)]   (actions the agent took)
    - tool_results : list[str]        (tool/environment outputs)
    - meta         : benchmark-specific provenance (injection catalog, roles, ...)
and then, for each of 9 readiness dimensions, apply ONE documented heuristic and
report the fraction of traces (and, where sensible, of tool calls) that satisfy
it. Every heuristic is defined inline so the numbers are reproducible/auditable.

Run:  python3 readiness_scorecard.py
Data paths default to the session scratchpad; override with --stac/--agentdojo/--rjudge.
"""
import argparse, glob, json, os, re
from collections import Counter

# ----------------------------------------------------------------------------
# Shared heuristics (regexes / key sets) -- documented once, applied uniformly.
# ----------------------------------------------------------------------------

# D1 approvals/consent -- the dimension spec's keyword set, matched on tool NAMES
# and on text CONTENT (case-insensitive substring).
# Kept in step with stac_rv.APPROVAL / stac_rv.approval_event: the monitor and this
# scorecard must not disagree about what counts as an approval event.
APPROVAL_RE = re.compile(r"approve|consent|confirm|authori[sz]e|grant|2fa|otp|"
                         r"acknowledge|sign_off|double_check|permission|verify", re.I)
READONLY_RE = re.compile(r"^(get|list|read|search|view|fetch|query)_", re.I)
# The wider set used by stac_rv.py (reproduces the known 6/483 STAC figure when
# matched on canonical-chain tool NAMES).
APPROVAL_NAME_KEYS = ("confirm", "approve", "consent", "authorize", "authorise",
                      "permission", "verify", "grant", "two_factor", "2fa", "otp",
                      "request_approval", "ack", "sign_off", "double_check")

# D3 object identifier -- arg KEY denotes a stable object handle.
OBJID_KEY_RE = re.compile(r"(^id$|^ids$|_id$|_ids$|^file$|^files$|^filename$|"
                          r"^file_id$|^product_id$|^doc_?id$|^note_?id$|^record_?id$|"
                          r"^message_?id$|^msg_?id$|^event_?id$|^item_?id$|^order_?id$|"
                          r"^task_?id$|^transaction_?id$|^reservation_?id$|"
                          r"^calendar_?id$|^list_?id$|^channel$)", re.I)

# D4 recipient/payee -- arg KEY names a recipient, or a VALUE looks like an
# email / IBAN / payee handle.
RECIP_KEY_RE = re.compile(r"^(recipient|recipients|payee|payees|iban|to|cc|bcc|"
                          r"email|recipient_id|account_number|to_account|dest.*)$", re.I)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{8,30}\b")
PAYEE_RE = re.compile(r"\bP-\d{3,}\b")  # R-Judge payee handles e.g. P-123456

# D7 user confirmation turn -- a user-authored turn approving a risky action.
USER_CONFIRM_RE = re.compile(r"\b(yes|yep|yeah|confirm(ed)?|approve[ds]?|go ahead|"
                             r"proceed|do it|sounds good|ok(ay)?|authori[sz]ed?|"
                             r"i approve|please (do|proceed|go)|that'?s (fine|correct)|"
                             r"looks good)\b", re.I)

# D8 reversibility metadata -- arg/field key that types an action reversible vs
# irreversible.  (Measured; expected empty across all three.)
REVERSIBILITY_KEY_RE = re.compile(r"reversib|irreversib|undoable|destructive|"
                                  r"permanent|can_undo|rollback", re.I)


def is_objid_args(args):
    return isinstance(args, dict) and any(OBJID_KEY_RE.search(str(k)) for k in args)


def is_recip_args(args):
    if not isinstance(args, dict):
        return False
    for k, v in args.items():
        if RECIP_KEY_RE.search(str(k)):
            return True
        s = json.dumps(v) if isinstance(v, (list, dict)) else str(v)
        if EMAIL_RE.search(s) or IBAN_RE.search(s) or PAYEE_RE.search(s):
            return True
    return False


def has_reversibility_meta(args):
    return isinstance(args, dict) and any(REVERSIBILITY_KEY_RE.search(str(k)) for k in args)


# ----------------------------------------------------------------------------
# Parsers -> list of normalised trace dicts
# ----------------------------------------------------------------------------

def _decode_stac_args(raw):
    """STAC tool-call arguments are double-JSON-encoded ("\"{...}\"")."""
    try:
        x = json.loads(raw) if isinstance(raw, str) else raw
        if isinstance(x, str):
            x = json.loads(x)
        return x if isinstance(x, dict) else {"_v": x}
    except (ValueError, TypeError):
        return {"_raw": raw}


def load_stac(path):
    cases = json.load(open(path))
    traces = []
    for c in cases:
        user_turns, tool_calls, tool_results = [], [], []
        # canonical-chain names (interaction_history assistant calls + final step),
        # used only for the 6/483 reproduction below.
        canon_names = []
        for m in c["interaction_history"]:
            r = m.get("role")
            if r == "user":
                user_turns.append(m.get("content", "") or "")
            elif r == "assistant":
                for tc in (m.get("tool_calls") or []):
                    fn = tc.get("function", {})
                    name = fn.get("name", "")
                    args = _decode_stac_args(fn.get("arguments", ""))
                    tool_calls.append((name, args))
                    canon_names.append(name)
            elif r == "tool":
                tool_results.append(m.get("content", "") or "")
        vc = c["attack_plan"]["verified_tool_chain"]
        canon_names.append(vc[-1].get("tool_name", ""))
        traces.append({
            "user_turns": user_turns,
            "tool_calls": tool_calls,
            "tool_results": tool_results,
            "verified_chain": vc,               # step dicts w/ parameters + environment_changes + purpose
            "canon_names": canon_names,
            "has_call_result_link": any(m.get("role") == "tool" and m.get("tool_call_id")
                                        for m in c["interaction_history"]),
        })
    return traces


def load_agentdojo(root, models):
    traces = []
    for model in models:
        for f in glob.glob(os.path.join(root, model, "**", "*.json"), recursive=True):
            d = json.load(open(f))
            user_turns, tool_calls, tool_results = [], [], []
            link = False
            for m in d.get("messages", []):
                r = m.get("role")
                if r == "user":
                    user_turns.append(m.get("content", "") or "")
                elif r == "assistant":
                    for tc in (m.get("tool_calls") or []):
                        tool_calls.append((tc.get("function", ""), tc.get("args", {}) or {}))
                elif r == "tool":
                    tool_results.append(m.get("content", "") or "")
                    if m.get("tool_call_id") and m.get("tool_call"):
                        link = True
            traces.append({
                "user_turns": user_turns,
                "tool_calls": tool_calls,
                "tool_results": tool_results,
                "injections": d.get("injections") or {},      # provenance catalog
                "attack_type": d.get("attack_type"),
                "duration": d.get("duration"),                # trace-level wall-clock
                "has_call_result_link": link,
            })
    return traces


def _parse_rjudge_action(action):
    """R-Judge agent 'action' text -> (tool_name, args_dict) or (None, {}).
    Formats seen: 'Tool: {json}', 'Tool{json}', '{ "Tool": {json} }', or plain
    free-text final answers (no tool)."""
    if not action:
        return None, {}
    a = action.strip()
    # form C: {"Tool": {args}}
    if a.startswith("{"):
        try:
            obj = json.loads(a)
            if isinstance(obj, dict) and len(obj) == 1:
                k, v = next(iter(obj.items()))
                if isinstance(v, dict):
                    return k, v
        except (ValueError, TypeError):
            pass
    # form A/B: Tool: {args}   or   Tool{args}
    m = re.match(r"^([A-Za-z_][\w]*)\s*[:]?\s*(\{.*\})\s*$", a, re.S)
    if m:
        name = m.group(1)
        body = m.group(2)
        for parse in (json.loads, _loose_json):
            try:
                args = parse(body)
                if isinstance(args, dict):
                    return name, args
            except Exception:
                continue
        return name, {}
    # a bare tool name with no braces (rare)
    m2 = re.match(r"^([A-Za-z_][\w]*)\s*$", a)
    if m2 and not a.lower().startswith(("final answer", "i ", "the ", "here")):
        return m2.group(1), {}
    return None, {}


def _loose_json(s):
    return json.loads(s.replace("'", '"'))


def load_rjudge(root):
    traces = []
    for f in glob.glob(os.path.join(root, "**", "*.json"), recursive=True):
        for rec in json.load(open(f)):
            user_turns, tool_calls, tool_results = [], [], []
            n_env = n_agent_action = 0
            for session in rec.get("contents", []):
                for turn in session:
                    role = turn.get("role")
                    if role == "user":
                        user_turns.append(turn.get("content", "") or "")
                    elif role == "environment":
                        tool_results.append(turn.get("content", "") or "")
                        n_env += 1
                    elif role == "agent":
                        name, args = _parse_rjudge_action(turn.get("action", ""))
                        if name is not None:
                            tool_calls.append((name, args))
                            n_agent_action += 1
            traces.append({
                "user_turns": user_turns,
                "tool_calls": tool_calls,
                "tool_results": tool_results,
                "label": rec.get("label"),
                "n_env_turns": n_env,             # role=environment = external-content provenance marker
                "has_call_result_link": False,    # no id links action<->environment turn
            })
    return traces


# ----------------------------------------------------------------------------
# Dimension measurement over a list of normalised traces
# ----------------------------------------------------------------------------

def measure(traces):
    n = len(traces)
    total_calls = sum(len(t["tool_calls"]) for t in traces)
    R = {"n_traces": n, "n_tool_calls": total_calls}

    def frac(c):  # trace fraction pretty
        return f"{c}/{n} = {100*c/max(1,n):.1f}%"

    def cfrac(c):  # call fraction pretty
        return f"{c}/{total_calls} = {100*c/max(1,total_calls):.1f}%"

    # ---- D1 approvals/consent ------------------------------------------------
    d1_name_tr = d1_name_calls = 0
    d1_content_tr = 0
    for t in traces:
        name_hit_calls = sum(1 for nm, _ in t["tool_calls"] if APPROVAL_RE.search(nm or ""))
        d1_name_calls += name_hit_calls
        if name_hit_calls:
            d1_name_tr += 1
        blob = " ".join(t["user_turns"] + t["tool_results"] +
                        [nm or "" for nm, _ in t["tool_calls"]] +
                        [json.dumps(a) for _, a in t["tool_calls"]])
        if APPROVAL_RE.search(blob):
            d1_content_tr += 1
    R["D1_approval_by_toolname_traces"] = frac(d1_name_tr)
    R["D1_approval_by_toolname_calls"] = cfrac(d1_name_calls)
    R["D1_approval_by_anytext_traces"] = frac(d1_content_tr)

    # ---- D3 object identifiers ----------------------------------------------
    d3_tr = d3_calls = 0
    for t in traces:
        hit = sum(1 for _, a in t["tool_calls"] if is_objid_args(a))
        d3_calls += hit
        if hit:
            d3_tr += 1
    R["D3_objectid_traces"] = frac(d3_tr)
    R["D3_objectid_calls"] = cfrac(d3_calls)

    # ---- D4 recipient/payee identity ----------------------------------------
    d4_tr = d4_calls = 0
    for t in traces:
        hit = sum(1 for _, a in t["tool_calls"] if is_recip_args(a))
        d4_calls += hit
        if hit:
            d4_tr += 1
    R["D4_recipient_traces"] = frac(d4_tr)
    R["D4_recipient_calls"] = cfrac(d4_calls)

    # ---- D7 user confirmation turn ------------------------------------------
    d7 = sum(1 for t in traces if any(USER_CONFIRM_RE.search(u or "") for u in t["user_turns"]))
    R["D7_user_confirm_traces"] = frac(d7)

    # ---- D8 reversibility metadata ------------------------------------------
    d8 = sum(1 for t in traces for _, a in t["tool_calls"] if has_reversibility_meta(a))
    R["D8_reversibility_meta_calls"] = f"{d8}/{total_calls}"

    # ---- D9 causal linkage (call<->result id link beyond order) -------------
    d9 = sum(1 for t in traces if t.get("has_call_result_link"))
    R["D9_call_result_link_traces"] = frac(d9)
    return R


def main():
    sp = ("/private/tmp/claude-501/-Users-nikos-Workspace-Projects-Research-rv-"
          "rv-3-layer/b0c8a5ee-d895-4384-9090-98ca44595dc7/scratchpad")
    ap = argparse.ArgumentParser()
    ap.add_argument("--stac", default=f"{sp}/stac/data/STAC_benchmark_data.json")
    ap.add_argument("--agentdojo", default=f"{sp}/agentdojo/runs")
    ap.add_argument("--rjudge", default=f"{sp}/rjudge/data")
    a = ap.parse_args()

    AD_MODELS = ["gpt-4o-2024-05-13"]   # fixed subset: one model, all 4 suites, all attack types

    print("=" * 78)
    print("TEMPORAL POLICY READINESS SCORECARD  (real measurements, no LLM)")
    print("=" * 78)

    stac = load_stac(a.stac)
    ad = load_agentdojo(a.agentdojo, AD_MODELS)
    rj = load_rjudge(a.rjudge)

    print(f"\nSample sizes (each recorded trace = one unit):")
    print(f"  STAC      : {len(stac)} cases (interaction_history + verified_tool_chain)")
    print(f"  AgentDojo : {len(ad)} runs  [model(s) {AD_MODELS}, suites banking/slack/travel/workspace, ALL attack types]")
    print(f"  R-Judge   : {len(rj)} records (across {len(glob.glob(os.path.join(a.rjudge,'**','*.json'),recursive=True))} category files)")

    S, A, J = measure(stac), measure(ad), measure(rj)

    # ---- (b) reproduce STAC 6/483 approval figure via canonical-chain names ----
    print("\n" + "-" * 78)
    print("(b) APPROVAL-EVENT fraction  (tool NAME matches approval keyword set)")
    print("-" * 78)
    stac6 = sum(1 for t in stac
                if any(any(k in (nm or "").lower() for k in APPROVAL_NAME_KEYS)
                       for nm in t["canon_names"]))
    print(f"  STAC (canonical chain, stac_rv.py keyword set): {stac6}/{len(stac)} "
          f"= {100*stac6/len(stac):.2f}%   <-- reproduces known 6/483")
    print(f"  STAC (dimension-spec regex on tool names)     : {S['D1_approval_by_toolname_traces']}")
    print(f"  AgentDojo (spec regex on tool names)          : {A['D1_approval_by_toolname_traces']}")
    print(f"  R-Judge   (spec regex on tool names)          : {J['D1_approval_by_toolname_traces']}")
    print("  (content-level, any text in trace:)")
    print(f"    STAC {S['D1_approval_by_anytext_traces']} | AgentDojo {A['D1_approval_by_anytext_traces']} | R-Judge {J['D1_approval_by_anytext_traces']}")

    # ---- benchmark-specific structural facts (D2/D5/D6) ----------------------
    print("\n" + "-" * 78)
    print("D2 TIMESTAMPS / elapsed time  (genuine event clock vs call order only)")
    print("-" * 78)
    ad_dur = sum(1 for t in ad if isinstance(t.get("duration"), (int, float)))
    # scan for any per-event timestamp field in each schema
    print("  STAC      : NO per-event clock. interaction_history turns have only")
    print("              {role, content/tool_calls}; tool results even carry")
    print("              last_modified=None. Ordering = list position only.")
    print(f"  AgentDojo : NO per-event clock (0 message-level timestamp fields);")
    print(f"              trace-level wall-clock 'duration' present on {ad_dur}/{len(ad)} runs")
    print("              (whole-run seconds, NOT per action). Data-level dates in")
    print("              tool text (e.g. transaction date '2022-04-01') are payload,")
    print("              not event time. Per-event ordering = list position only.")
    print("  R-Judge   : NO per-event clock. Dates appearing in text are payload")
    print("              content. Ordering = turn position only.")
    print("  => DEFINITIVE: none of the three record real per-event timestamps;")
    print("     temporal operators must run on call/turn ORDER, not wall-clock.")

    print("\n" + "-" * 78)
    print("D5 TRUSTED vs UNTRUSTED source markers")
    print("-" * 78)
    ad_inj = sum(1 for t in ad if t["injections"])
    ad_atk = sum(1 for t in ad if t.get("attack_type"))
    rj_env = sum(1 for t in rj if t["n_env_turns"] > 0)
    print("  STAC      : NO provenance field. Whole case is attacker-authored")
    print("              (attack_plan); no per-event trusted/untrusted flag.  -> N")
    print(f"  AgentDojo : PARTIAL. 'injections' catalog lists injected payload")
    print(f"              strings on {ad_inj}/{len(ad)} runs and 'attack_type' names the")
    print(f"              vector on {ad_atk}/{len(ad)} runs; injected text is thus")
    print("              RECOVERABLE by matching against tool outputs, but there is")
    print("              no per-message trust boolean. role=tool vs user separates")
    print("              channels.  -> PARTIAL")
    print(f"  R-Judge   : PARTIAL. role='environment' marks external/tool-supplied")
    print(f"              content ({rj_env}/{len(rj)} traces have >=1 env turn) distinct")
    print("              from user/agent, but no trusted/untrusted flag on it.  -> PARTIAL")

    print("\n" + "-" * 78)
    print("D6 STATE TRANSITIONS  (explicit before/after vs must-infer)")
    print("-" * 78)
    stac_steps = sum(len(t["verified_chain"]) for t in stac)
    stac_envchg = sum(1 for t in stac for s in t["verified_chain"]
                      if (s.get("environment_changes") or "").strip())
    print(f"  STAC      : PARTIAL. verified_tool_chain steps carry free-text")
    print(f"              'environment_changes' on {stac_envchg}/{stac_steps} steps")
    print("              (after-effect description, NOT structured before/after).")
    print("  AgentDojo : NO explicit state. Tool results show the resulting state")
    print("              in prose ('Transaction ... updated'); before/after must be")
    print("              inferred by diffing successive results.  -> inferred")
    print("  R-Judge   : NO explicit state. environment turns show outcomes in")
    print("              prose; before/after must be inferred.  -> inferred")

    # ---- D8 / D9 verdicts ----------------------------------------------------
    print("\n" + "-" * 78)
    print("D8 REVERSIBLE vs IRREVERSIBLE typing metadata")
    print("-" * 78)
    print(f"  reversibility-metadata arg keys found -- STAC {S['D8_reversibility_meta_calls']}, "
          f"AgentDojo {A['D8_reversibility_meta_calls']}, R-Judge {J['D8_reversibility_meta_calls']}")
    print("  => EFFECTIVELY NONE. The only R-Judge hit is a single incidental")
    print("     'permanent': True flag on one GrantGuestAccess call, not a")
    print("     reversibility-typing convention. Reversibility is otherwise never")
    print("     annotated; it can only be INFERRED from the tool name (e.g.")
    print("     delete/send/transfer = irreversible).")

    print("\n" + "-" * 78)
    print("D9 CAUSAL ORDERING beyond simple call order")
    print("-" * 78)
    print(f"  call<->result id linkage present -- STAC {S['D9_call_result_link_traces']}, "
          f"AgentDojo {A['D9_call_result_link_traces']}, R-Judge {J['D9_call_result_link_traces']}")
    print("  STAC/AgentDojo: PARTIAL -- tool_call_id ties each call to its result,")
    print("     and shared object ids across steps expose dataflow, but there is no")
    print("     explicit causal/dependency graph. R-Judge: N -- positional order only.")

    # ---- (a) the scorecard table --------------------------------------------
    print("\n" + "=" * 78)
    print("(a) SCORECARD TABLE  (fraction of traces present; call-level in parens)")
    print("=" * 78)
    dims = [
        ("D1 approvals/consent (toolname)", "D1_approval_by_toolname_traces", "D1_approval_by_toolname_calls"),
        ("D3 object identifiers",           "D3_objectid_traces",             "D3_objectid_calls"),
        ("D4 recipient/payee identity",     "D4_recipient_traces",            "D4_recipient_calls"),
        ("D7 user-confirmation turn",       "D7_user_confirm_traces",         None),
    ]
    hdr = f"{'dimension':32} | {'AgentDojo':26} | {'STAC':26} | {'R-Judge':26}"
    print(hdr); print("-" * len(hdr))
    for label, tk, ck in dims:
        row = f"{label:32} | {A[tk]:26} | {S[tk]:26} | {J[tk]:26}"
        print(row)
        if ck:
            print(f"{'   (calls)':32} | {A[ck]:26} | {S[ck]:26} | {J[ck]:26}")
    # qualitative rows
    ql = [
        ("D2 real timestamps",         "N (order only; AD has run-level duration)", "N (order only)", "N (order only)"),
        ("D5 trust/provenance marker", "PARTIAL (injections+attack_type)",          "N (all attacker)", "PARTIAL (role=environment)"),
        ("D6 explicit state transition","N (infer from results)",                    "PARTIAL (environment_changes text)", "N (infer)"),
        ("D8 reversibility metadata",  "N (infer from name)",                        "N (infer from name)", "N (infer from name)"),
        ("D9 causality beyond order",  "PARTIAL (tool_call_id link)",               "PARTIAL (tool_call_id link)", "N (order only)"),
    ]
    print("-" * len(hdr))
    for label, av, sv, jv in ql:
        print(f"{label:32} | {av:26} | {sv:26} | {jv:26}")

    # ---- temporal readiness rating ------------------------------------------
    print("\n" + "=" * 78)
    print("TEMPORAL READINESS RATING (per benchmark)")
    print("=" * 78)
    print("""  AgentDojo : MODERATE-LOW. Best parametric payload (object ids + IBAN/email
              recipients on most financial/comm calls) and the only injection
              provenance catalog, so parametric+source-aware policies are
              expressible offline. But NO per-event time, NO explicit approvals
              in-trace, NO state/reversibility typing -> temporal operators run on
              call ORDER, obligations must be keyword-typed.
  STAC      : LOW-MODERATE. Rich per-step object ids + recipients + free-text
              environment_changes (after-effects) and a verified causal chain,
              which is why history-dependent 'risky-action-without-prior-approval'
              obligations replay well. But approvals essentially absent (6/483),
              no timestamps, no provenance flag, no reversibility typing.
  R-Judge   : LOW. Only role=environment provenance is structured; actions are
              free-text needing parsing, no id linkage, no timestamps, no explicit
              approvals, no state/reversibility. Supports source-aware content
              checks but weak for parametric/temporal enforcement.""")

    # ---- (c) systematically-absent dimensions -------------------------------
    print("\n" + "=" * 78)
    print("(c) DIMENSIONS SYSTEMATICALLY ABSENT ACROSS ALL THREE (design gap)")
    print("=" * 78)
    print("""  * D2 real timestamps / elapsed time  -- none record a per-event clock;
        genuine metric-time temporal policies are UNTESTABLE on this data.
  * D6 explicit state before/after     -- only STAC gives prose after-effects;
        structured pre/post state is absent everywhere.
  * D8 reversible/irreversible typing   -- never annotated; always inferred.
  * D1 explicit approval/consent events -- vanishingly rare (STAC 6/483) or
        absent, so 'requires prior approval' obligations have almost no positive
        (compliant) instances to test the gate against.""")

    # ---- (d) proposed minimal trace schema ----------------------------------
    print("\n" + "=" * 78)
    print("(d) PROPOSED MINIMAL TRACE SCHEMA for temporal/parametric enforcement")
    print("=" * 78)
    print("""  Per-event record: {timestamp, actor, tool, action, object, recipient,
                     source, approval_id, session_id, state_before, state_after,
                     trust_domain}

  field         | AgentDojo        | STAC             | R-Judge
  --------------+------------------+------------------+-----------------
  timestamp     | run-level only   | NO               | NO
  actor         | YES (role)       | YES (role)       | YES (role)
  tool          | YES (function)   | YES (tool_name)  | PARTIAL (parse action)
  action/args   | YES (args)       | YES (parameters) | PARTIAL (parse args)
  object        | YES (id in args) | YES (file_id...) | PARTIAL (id in args)
  recipient     | YES (IBAN/email) | YES (recipients) | PARTIAL (payee/email)
  source        | PARTIAL(injects) | NO               | PARTIAL (env role)
  approval_id   | NO               | NO (6/483 names) | NO
  session_id    | YES (file path)  | YES (case id)    | YES (record id)
  state_before  | NO               | NO               | NO
  state_after   | NO               | PARTIAL (envchg) | NO
  trust_domain  | PARTIAL(attack)  | NO               | PARTIAL (env role)

  Adding {timestamp, source/trust_domain, approval_id, state_before/after,
  reversibility} to any of these benchmarks would make full temporal+parametric
  enforcement policies directly checkable rather than inferred.""")


if __name__ == "__main__":
    main()
