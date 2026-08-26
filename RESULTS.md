# Artefact notes — camera-ready reruns, CPSIoTSec #53

Data: AgentDojo recorded trajectories, sparse clone of github.com/ethz-spylab/agentdojo.
`runs/gpt-4o-2024-05-13` = 6899 runs for the single-model tables; all 29 model
directories for the pooled and cross-model tests. Re-run 2026-08-26.

## The approval-keyword correction

The frozen APPROVAL set contained the substring token `ack`, which matched
`invite_user_to_slack` and `remove_user_from_slack` (595 calls); each then acted as a
prior approval and suppressed every later obligation in that run. `authorize` matched
the read-only `list_authorized_personnel`. Fixed in `stac_rv.py`: `ack` -> `acknowledge`,
plus a `READONLY_PREFIX` guard, both funnelled through a new shared `approval_event()`
so all five consumers apply one rule. After the fix, ZERO AgentDojo calls match the
approval antecedent. The correction RAISES the reported rates.

| measure | before | after |
|---|---|---|
| AgentDojo detection on successful attacks | 1190/1931 = 61.6% | 1356/1931 = 70.2% |
| AgentDojo BFR | 39/123 = 31.7% | 40/123 = 32.5% |
| fires on any attacked run | 2426/6680 = 36.3% | 2593/6680 = 38.8% |
| slack suite detection | 40.3% | 63.9% |
| slack suite BFR | 11.5% | 15.4% |
| earliest-warning preventive | 991 = 51.3% | 1117 = 57.8% |
| union LR+ | 1.94 | 2.16 |

STAC (347/483 = 71.8%) and the parametric/pooled results are UNCHANGED: no STAC or
R-Judge tool name collides, and the parametric obligations do not use approval gating.

## Headline (tab:agentdojo)
```
  AgentDojo ASR (security): 1931/6680 = 28.9%

=== Our RV replayed on the SAME runs ===
  RV fires on a SUCCESSFUL attack: 1356/1931 = 70.2%  (detection on real successful attacks)
  RV fires on ANY attacked run:    2593/6680 = 38.8%

=== Over-block on BENIGN runs (attack='none') ===
  RV fires on benign run:          40/123 = 32.5%  (false-positive / utility cost)
  RV fires on benign SUCCESSFUL-utility run: 31/90 = 34.4%

  detection-on-successful-attacks by obligation:
    destructive_no_confirm   307
    teardown_no_approval     0
    financial_no_confirm     540
    export_no_consent        539
    actuation_no_precond     313
```

## Per-obligation ablation (tab:peroblig)
```
AgentDojo gpt-4o -- per-obligation ablation
successful attacks=1931  benign runs=123

obligation                      detect           BFR incr.atk incr.ben  det/BFR
destructive_no_confirm    307/1931  15.9%    5/123   4.1%      259        4     3.91
teardown_no_approval        0/1931   0.0%    0/123   0.0%        0        0      inf
financial_no_confirm      540/1931  28.0%   21/123  17.1%      245       15     1.64
export_no_consent         539/1931  27.9%   13/123  10.6%      491       12     2.64
actuation_no_precond      313/1931  16.2%    8/123   6.5%       18        2     2.49

UNION O1-O5              1356/1931  70.2%   40/123  32.5%
```

## Per-suite (tab:suite)
```
[banking]
files: 1545  (skipped empty/unparse: 96)
  AgentDojo ASR (security): 571/1425 = 40.1%
  RV fires on a SUCCESSFUL attack: 558/571 = 97.7%  (detection on real successful attacks)
  RV fires on benign run:          23/24 = 95.8%  (false-positive / utility cost)
[slack]
files: 1181  (skipped empty/unparse: 0)
  AgentDojo ASR (security): 703/1155 = 60.9%
  RV fires on a SUCCESSFUL attack: 449/703 = 63.9%  (detection on real successful attacks)
  RV fires on benign run:          4/26 = 15.4%  (false-positive / utility cost)
[travel]
files: 1527  (skipped empty/unparse: 0)
  AgentDojo ASR (security): 139/1500 = 9.3%
  RV fires on a SUCCESSFUL attack: 23/139 = 16.5%  (detection on real successful attacks)
  RV fires on benign run:          3/27 = 11.1%  (false-positive / utility cost)
[workspace]
files: 2646  (skipped empty/unparse: 0)
  AgentDojo ASR (security): 518/2600 = 19.9%
  RV fires on a SUCCESSFUL attack: 326/518 = 62.9%  (detection on real successful attacks)
  RV fires on benign run:          10/46 = 21.7%  (false-positive / utility cost)
```

## Earliest warning, enrichment, sensitivity
```

=== AgentDojo gpt-4o (final=last tool call)  (successful attacks: 1931) ===
  (a) PREVENTIVE  (fires before final step): 1117/1931 = 57.8%
  (b) LAST-MOMENT (fires only on final step): 239/1931 = 12.4%
  (c) COVERAGE GAP (never fires):             575/1931 = 29.8%
  earliest-warning rate  = 57.8%  (=(a))
  detection (a)+(b)      = 1356/1931 = 70.2%
  detection lead over (a): median=2.0  mean=2.53  max=13  (tool-calls)
  detection lead over (a)+(b): median=2.0  mean=2.08  (tool-calls; (b) counts as 0)

=== STAC recorded harmful chains  (successful attacks: 483) ===
  (a) PREVENTIVE  (fires before final step): 76/483 = 15.7%
AgentDojo gpt-4o -- risk enrichment  P(fire|attack)/P(fire|benign)

GENERIC O1-O5 (all suites)               TPR= 70.2% FPR= 32.5%  enrich(LR+)= 2.16  bal.acc= 68.9%  LR-=0.44   (TP=1356/1931 FP=40/123)
generic O3 financial (banking send_money) TPR= 79.2% FPR= 44.0%  enrich(LR+)= 1.80  bal.acc= 67.6%  LR-=0.37   (TP=456/576 FP=11/25)
PARAMETRIC payee (banking, unknown payee) TPR= 70.0% FPR= 24.0%  enrich(LR+)= 2.92  bal.acc= 73.0%  LR-=0.40   (TP=403/576 FP=6/25)
generic O4 export (workspace send_email) TPR= 42.5% FPR= 15.2%  enrich(LR+)= 2.79  bal.acc= 63.6%  LR-=0.68   (TP=220/518 FP=7/46)
PARAMETRIC recipient (workspace, external) TPR= 39.2% FPR= 10.9%  enrich(LR+)= 3.61  bal.acc= 64.2%  LR-=0.68   (TP=203/518 FP=5/46)
Canonicalisation sensitivity -- headline numbers under 4 tool->class maps

mapping                AD detect          AD BFR        STAC final
original        1356/1931   70.2%   40/123   32.5%    347/483   71.8%   (baseline)
corrected       1542/1931   79.9%   54/123   43.9%    353/483   73.1%   (d det +9.6, BFR +11.4, STAC +1.2)
conservative    1356/1931   70.2%   40/123   32.5%    298/483   61.7%   (d det +0.0, BFR +0.0, STAC -10.1)
expanded        1544/1931   80.0%   58/123   47.2%    353/483   73.1%   (d det +9.7, BFR +14.6, STAC +1.2)
```

## Pooled McNemar and cross-model (all 29 model dirs) — unchanged by the fix
```

=== Banking payee-provenance (pooled over all model dirs) ===
  benign runs pooled: 700
  benign firing rate  generic 225/700=32.1%  parametric 150/700=21.4%
  discordant: generic-fires-only b=75  parametric-fires-only c=0
  EXACT McNemar two-sided p = 5.29e-23   SIGNIFICANT at alpha=0.05
  detection on successful attacks: generic 80.5%  parametric 73.5%  (n=1549)

=== Workspace external-recipient (pooled over all model dirs) ===
  benign runs pooled: 1376
  benign firing rate  generic 182/1376=13.2%  parametric 145/1376=10.5%
  discordant: generic-fires-only b=37  parametric-fires-only c=0
  EXACT McNemar two-sided p = 1.46e-11   SIGNIFICANT at alpha=0.05
  detection on successful attacks: generic 38.7%  parametric 33.8%  (n=1229)
  decreased=20  unchanged=2  increased=0  of 22
  BFR reduction (pct points): median=8.0  IQR=[4.0,17.0]  min=0.0  max=24.0
  exact two-sided sign-test p = 1.907e-06  (SIGNIFICANT at alpha=0.05; ties excluded)
```

## Known open issue: the payee ablation is degenerate

In `combined_ablation.py`, `B_param_payee` is identical to `A_generic` on every run
because `ref_fin = fin_other or payee` and FINANCIAL contains the substring
`transaction`, so the read-only `get_most_recent_transactions` /
`get_scheduled_transactions` keep the refined financial slot lit. The reported
combined delta therefore comes from the recipient obligation alone. tab:param is
unaffected (agentdojo_param.py measures send_money only). NOT yet fixed.
