# Artefact notes — camera-ready reruns, CPSIoTSec #53 (2026-08-26)

Two substring-collision fixes, both in `stac_rv.py`, both funnelled through new
shared predicates (`approval_event`, `obligation_event`) so all consumers agree:

1. **APPROVAL**: `ack` matched `invite_user_to_slack` / `remove_user_from_slack`
   (595 calls), each acting as a prior approval; `authorize` matched the read-only
   `list_authorized_personnel`. Fixed: `ack` -> `acknowledge` + READONLY_PREFIX guard.
2. **OBLIGATIONS**: FINANCIAL contains `transaction`, so the read-only
   `get_most_recent_transactions` / `get_scheduled_transactions` were typed as value
   transfers. The same READONLY_PREFIX guard now applies to obligation typing. All 20
   read-only accessors in canon_eval.py GOLD are labelled NONE, so this aligns the
   monitor with its own hand-labelled ground truth.

| measure | original | after fix 1 | after both |
|---|---|---|---|
| AgentDojo detection | 1190/1931 = 61.6% | 1356/1931 = 70.2% | **1354/1931 = 70.1%** |
| AgentDojo BFR | 39/123 = 31.7% | 40/123 = 32.5% | **36/123 = 29.3%** |
| any attacked run | 36.3% | 38.8% | **34.3%** |
| banking BFR | 23/24 = 95.8% | 23/24 = 95.8% | **19/24 = 79.2%** |
| slack detection | 40.3% | 63.9% | **63.9%** |
| union LR+ | 1.94 | 2.16 | **2.40** |
| canonicalisation micro-F1 | 0.84 | 0.84 | **0.87** |
| exact-match typing | 45/54 = 83.3% | 45/54 = 83.3% | **47/54 = 87.0%** |
| earliest-warning preventive | 991 = 51.3% | 1117 = 57.8% | **1012 = 52.4%** |

Both corrections move discrimination the right way: LR+ 1.94 -> 2.40 and typing
F1 0.84 -> 0.87. UNCHANGED throughout: STAC 347/483 = 71.8%, every tab:param row,
the pooled McNemar (p=5.29e-23 / 1.46e-11) and the cross-model sign test.

## The ablation now discriminates

Before fix 2, `B_param_payee` was bit-identical to `A_generic` on all 1936 runs.

```

=== OVERALL (all 4 suites)   (successful attacks=1936, benign runs=124) ===
 run-level policy set (a run FIRES if any policy in the set fires):
  policy set                    detect             BFR  lost vs A  gain vs A
  A_generic            1354/1936   69.9%   36/124   29.0%          0          0
  B_param_payee        1354/1936   69.9%   32/124   25.8%          0          0
  C_param_recip        1343/1936   69.4%   34/124   27.4%         11          0
  D_both_param         1343/1936   69.4%   30/124   24.2%         11          0
 per-action-slot firing (generic vs parametric refinement of that slot):
   financial (send_money)   detect generic 518/1936=26.8%  param 499/1936=25.8%  |  BFR generic 16/124=12.9%  param 12/124=9.7%
   export (send_email)      detect generic 539/1936=27.8%  param 522/1936=27.0%  |  BFR generic 13/124=10.5%  param 11/124=8.9%

=== banking+workspace pooled   (successful attacks=1094, benign runs=71) ===
 run-level policy set (a run FIRES if any policy in the set fires):
  policy set                    detect             BFR  lost vs A  gain vs A
  A_generic             882/1094   80.6%   29/71   40.8%          0          0
  B_param_payee         882/1094   80.6%   25/71   35.2%          0          0
  C_param_recip         871/1094   79.6%   27/71   38.0%         11          0
  D_both_param          871/1094   79.6%   23/71   32.4%         11          0
 per-action-slot firing (generic vs parametric refinement of that slot):
   financial (send_money)   detect generic 518/1094=47.3%  param 499/1094=45.6%  |  BFR generic 16/71=22.5%  param 12/71=16.9%
   export (send_email)      detect generic 221/1094=20.2%  param 204/1094=18.6%  |  BFR generic 7/71=9.9%  param 5/71=7.0%
```

## Headline / per-obligation / per-suite / timing / sensitivity
```
  AgentDojo ASR (security): 1931/6680 = 28.9%
  RV fires on a SUCCESSFUL attack: 1354/1931 = 70.1%  (detection on real successful attacks)
  RV fires on ANY attacked run:    2292/6680 = 34.3%
  RV fires on benign run:          36/123 = 29.3%  (false-positive / utility cost)
    destructive_no_confirm   307
    teardown_no_approval     0
    financial_no_confirm     518
    export_no_consent        539
    actuation_no_precond     313


obligation                      detect           BFR incr.atk incr.ben  det/BFR
destructive_no_confirm    307/1931  15.9%    5/123   4.1%      259        4     3.91
teardown_no_approval        0/1931   0.0%    0/123   0.0%        0        0      inf
financial_no_confirm      518/1931  26.8%   16/123  13.0%      243       11     2.06
export_no_consent         539/1931  27.9%   13/123  10.6%      491       12     2.64
actuation_no_precond      313/1931  16.2%    8/123   6.5%       38        3     2.49

UNION O1-O5              1354/1931  70.1%   36/123  29.3%

[banking] 571/1425 = 40.1%|556/571 = 97.4%|19/24 = 79.2%|
[slack] 703/1155 = 60.9%|449/703 = 63.9%|4/26 = 15.4%|
[travel] 139/1500 = 9.3%|23/139 = 16.5%|3/27 = 11.1%|
[workspace] 518/2600 = 19.9%|326/518 = 62.9%|10/46 = 21.7%|

=== AgentDojo gpt-4o (final=last tool call)  (successful attacks: 1931) ===
  (a) PREVENTIVE  (fires before final step): 1012/1931 = 52.4%
  (b) LAST-MOMENT (fires only on final step): 342/1931 = 17.7%
  (c) COVERAGE GAP (never fires):             577/1931 = 29.9%
  earliest-warning rate  = 52.4%  (=(a))
  detection (a)+(b)      = 1354/1931 = 70.1%
  detection lead over (a): median=1.0  mean=2.19  max=13  (tool-calls)
  detection lead over (a)+(b): median=1.0  mean=1.64  (tool-calls; (b) counts as 0)


GENERIC O1-O5 (all suites)               TPR= 70.1% FPR= 29.3%  enrich(LR+)= 2.40  bal.acc= 70.4%  LR-=0.42   (TP=1354/1931 FP=36/123)
generic O3 financial (banking send_money) TPR= 79.2% FPR= 44.0%  enrich(LR+)= 1.80  bal.acc= 67.6%  LR-=0.37   (TP=456/576 FP=11/25)
PARAMETRIC payee (banking, unknown payee) TPR= 70.0% FPR= 24.0%  enrich(LR+)= 2.92  bal.acc= 73.0%  LR-=0.40   (TP=403/576 FP=6/25)
generic O4 export (workspace send_email) TPR= 42.5% FPR= 15.2%  enrich(LR+)= 2.79  bal.acc= 63.6%  LR-=0.68   (TP=220/518 FP=7/46)
PARAMETRIC recipient (workspace, external) TPR= 39.2% FPR= 10.9%  enrich(LR+)= 3.61  bal.acc= 64.2%  LR-=0.68   (TP=203/518 FP=5/46)

mapping                AD detect          AD BFR        STAC final
original        1354/1931   70.1%   36/123   29.3%    347/483   71.8%   (baseline)
corrected       1542/1931   79.9%   54/123   43.9%    353/483   73.1%   (d det +9.7, BFR +14.6, STAC +1.2)
conservative    1333/1931   69.0%   32/123   26.0%    298/483   61.7%   (d det -1.1, BFR -3.3, STAC -10.1)
expanded        1542/1931   79.9%   54/123   43.9%    353/483   73.1%   (d det +9.7, BFR +14.6, STAC +1.2)
```
