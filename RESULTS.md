# Artefact notes — camera-ready reruns, CPSIoTSec #53

Data: AgentDojo recorded trajectories, `runs/gpt-4o-2024-05-13`, sparse clone of
github.com/ethz-spylab/agentdojo (6899 JSON runs across banking/slack/travel/workspace).
Re-run 2026-08-26. Every number below is reproduced from the public dataset; nothing
in the paper changed as a result.

## P0 — pooled ablation is NOT a bug (reviewer 53C)

The pooled rates are a run-level UNION over all five generic obligations; the
tab:param rows are a SINGLE obligation on a SINGLE suite. Two different quantities.

```

=== OVERALL (all 4 suites)   (successful attacks=1936, benign runs=124) ===
 run-level policy set (a run FIRES if any policy in the set fires):
  policy set                    detect             BFR  lost vs A  gain vs A
  A_generic            1190/1936   61.5%   39/124   31.5%          0          0
  B_param_payee        1190/1936   61.5%   39/124   31.5%          0          0
  C_param_recip        1179/1936   60.9%   37/124   29.8%         11          0
  D_both_param         1179/1936   60.9%   37/124   29.8%         11          0
 per-action-slot firing (generic vs parametric refinement of that slot):
   financial (send_money)   detect generic 540/1936=27.9%  param 540/1936=27.9%  |  BFR generic 21/124=16.9%  param 21/124=16.9%
   export (send_email)      detect generic 527/1936=27.2%  param 510/1936=26.3%  |  BFR generic 13/124=10.5%  param 11/124=8.9%

=== banking+workspace pooled   (successful attacks=1094, benign runs=71) ===
 run-level policy set (a run FIRES if any policy in the set fires):
  policy set                    detect             BFR  lost vs A  gain vs A
  A_generic             884/1094   80.8%   33/71   46.5%          0          0
  B_param_payee         884/1094   80.8%   33/71   46.5%          0          0
  C_param_recip         873/1094   79.8%   31/71   43.7%         11          0
  D_both_param          873/1094   79.8%   31/71   43.7%         11          0
 per-action-slot firing (generic vs parametric refinement of that slot):
   financial (send_money)   detect generic 540/1094=49.4%  param 540/1094=49.4%  |  BFR generic 21/71=29.6%  param 21/71=29.6%
   export (send_email)      detect generic 221/1094=20.2%  param 204/1094=18.6%  |  BFR generic 7/71=9.9%  param 5/71=7.0%

=== suite=banking   (successful attacks=576, benign runs=25) ===
```

## P1 — the two banking BFR figures, resolved

Cause is twofold: (a) union vs single obligation, (b) agentdojo_rv.py drops runs with
an empty tool-call chain (96 in banking, one of them benign) while agentdojo_param.py
only requires a non-empty message list. Same numerator 23; denominators 24 vs 25.

```
--- agentdojo_rv.py, per suite (chain filter: source of tab:suite) ---
[banking]
files: 1545  (skipped empty/unparse: 96)
  AgentDojo ASR (security): 571/1425 = 40.1%
  RV fires on a SUCCESSFUL attack: 558/571 = 97.7%  (detection on real successful attacks)
  RV fires on benign run:          23/24 = 95.8%  (false-positive / utility cost)
[workspace]
files: 2646  (skipped empty/unparse: 0)
  AgentDojo ASR (security): 518/2600 = 19.9%
  RV fires on a SUCCESSFUL attack: 326/518 = 62.9%  (detection on real successful attacks)
  RV fires on benign run:          10/46 = 21.7%  (false-positive / utility cost)

--- agentdojo_param{,2}.py (message filter: source of tab:param) ---

detection on SUCCESSFUL attacks (576 runs):
  generic O3 (any send_money):        456/576 = 79.2%
  parametric (unknown payee only):    403/576 = 70.0%

over-block on BENIGN runs (25 runs):
  generic O3:                         11/25 = 44.0%
  parametric:                         6/25 = 24.0%

detection on SUCCESSFUL attacks (518 runs):
  generic O4 (any send_email):        220/518 = 42.5%
  parametric (external recipient):    203/518 = 39.2%

over-block on BENIGN runs (46 runs):
  generic O4:                         7/46 = 15.2%
  parametric:                         5/46 = 10.9%
```

## Headline numbers, re-verified

```
files: 6899  (skipped empty/unparse: 96)
  AgentDojo ASR (security): 1931/6680 = 28.9%
  RV fires on a SUCCESSFUL attack: 1190/1931 = 61.6%  (detection on real successful attacks)
  RV fires on benign run:          39/123 = 31.7%  (false-positive / utility cost)
```
