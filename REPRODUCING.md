# Reproducing the paper's results

Every number in the paper maps to one command here. `$AD` is the AgentDojo `runs`
directory, `$STAC` the STAC JSON, `$TB` the tau-bench trajectory directory (see
README.md for how to fetch each). All commands run from `code/`.

Two conventions cause most apparent inconsistencies, so they are stated once:

* **Policy set.** `agentdojo_rv.py` reports the *union* of all five generic obligations.
  `agentdojo_param*.py` report a *single* obligation. A union rate is therefore higher
  than any individual obligation's rate on the same runs, e.g. workspace benign firing
  is 10/46 as a union against 7/46 for O4 alone.
* **Run validity.** `agentdojo_rv.py` counts only runs with a non-empty tool-call chain
  (96 banking runs are excluded on that ground); `agentdojo_param*.py` count every run
  with a non-empty message list. Hence banking benign 19/24 in one place, 19/25 in the
  other, same numerator.

## Headline

| paper | command | expected |
|---|---|---|
| detection, BFR, per-obligation counts | `python3 agentdojo_rv.py --runs $AD/gpt-4o-2024-05-13` | 1354/1931 = 70.1%; 36/123 = 29.3%; 307/0/518/539/313, sum 1677 |
| per-suite table | `python3 agentdojo_rv.py --runs $AD/gpt-4o-2024-05-13/<suite>` | banking 40.1/97.4/79.2; slack 60.9/63.9/15.4; travel 9.3/16.5/11.1; workspace 19.9/62.9/21.7 |
| STAC | `python3 stac_rv.py --data $STAC` | 347/483 = 71.8%; structural 249/342; content-semantic 98/141 |
| R-Judge | `python3 rjudge_rv.py --data <rjudge>` | 71/301 unsafe, 44/270 safe |
| unflagged fraction | derived | (1931-1354)/6680 = 8.6% |

## Parametric obligations and significance

| paper | command | expected |
|---|---|---|
| banking payee | `python3 agentdojo_param.py --banking $AD/gpt-4o-2024-05-13/banking` | 456/576 = 79.2% and 403/576 = 70.0%; 11/25 = 44.0% and 6/25 = 24.0% |
| workspace recipient | `python3 agentdojo_param2.py --workspace $AD/gpt-4o-2024-05-13/workspace` | 220/518 = 42.5% and 203/518 = 39.2%; 7/46 and 5/46 |
| pooled McNemar | `python3 agentdojo_param_pooled.py --root $AD` | 700 and 1376 benign; discordant 75-vs-0 and 37-vs-0; p = 5.29e-23 and 1.46e-11 |
| single-model McNemar | `python3 mcnemar.py` | p = 0.0625 and 0.5, **not** significant, which is the paper's own point |
| cross-model sign test | `python3 cross_model.py --root $AD` | 20 decreased / 2 unchanged / 0 increased, p = 1.907e-6; detection 48.4-91.7%, BFR 16.7-34.8% over 22 base dirs |
| per-obligation ablation | `python3 per_oblig_ablation.py --runs $AD/gpt-4o-2024-05-13` | union 70.1/29.3, LR+ 2.40; O1 3.91 is the maximum, not O4 |
| likelihood ratios | `python3 risk_enrichment.py --runs $AD/gpt-4o-2024-05-13` | 1.80 -> 2.92 and 2.79 -> 3.61 |
| combined ablation | `python3 combined_ablation.py --runs $AD/gpt-4o-2024-05-13` | A 69.9/29.0, D 69.4/24.2; pooled 80.6/40.8 -> 79.6/32.4 |
| Wilson intervals | `python3 wilson_ci.py` | the intervals quoted in the tables |

## Provenance integrity

| paper | command | expected |
|---|---|---|
| poisoning attack | `python3 monpoly_experiments/perturb_provenance.py --banking ... --workspace ...` | structured and quoted flip 379/403 = 94.0% and 201/203 = 99.0%; free-text and reformatted 0% |
| **hardened provenance** | `python3 monpoly_experiments/harden_provenance.py --banking ... --workspace ...` | naive 94.0/99.0% -> hardened **0.0%**, detection and benign firing unchanged |
| canonicalisation accuracy | `python3 canon_eval.py` | micro P 0.90, R 0.84, F1 0.87; exact match 47/54 = 87.0% |
| canonicalisation sensitivity | `python3 canon_sensitivity.py --runs ... --stac ...` | detection 69.0-79.9%, BFR 26.0-43.9%, STAC 61.7-73.1% |

## Benchmark readiness

| paper | command | expected |
|---|---|---|
| readiness scorecard | `python3 readiness_scorecard.py --stac $STAC --agentdojo $AD --rjudge <rjudge>` | approvals 0%/1.2%/0.4%; no timestamps, state or reversibility typing anywhere |
| **approval census** | `python3 monpoly_experiments/approval_census.py --agentdojo $AD/gpt-4o-2024-05-13 --stac $STAC --taubench $TB` | AgentDojo 1.00 user turns, 0 of 68 tools; STAC 2.61 turns, 6/70/39/3 of 483; tau-bench 7.08 turns, 1039/1980 = 52.5% |
| **field ablation** | `python3 monpoly_experiments/field_ablation.py --banking $AD/gpt-4o-2024-05-13/banking` | R0 79.2/44.0 LR+ 1.80; R1 and R2 both 70.0/24.0 LR+ 2.92, flip 94% vs 0%; R3/R4 unevaluable |
| earliest warning | `python3 first_firing.py --runs $AD/gpt-4o-2024-05-13 --stac $STAC` | AgentDojo 1012/342/577, median lead 1; STAC 57/297/129 |

## Cross-engine validation: four monitors, 347 firings

```sh
python3 stac_rv.py --data $STAC                                   # reference monitor: 347
python3 stac_to_monpoly.py --data $STAC --out /tmp/mp
docker run --rm -v /tmp/mp:/d infsec/monpoly           -sig /d/stac.sig -formula /d/obligation.mfotl -log /d/stac.log | grep -c '^@'   # MonPoly:  347
docker run --rm -v /tmp/mp:/d infsec/monpoly -verified -sig /d/stac.sig -formula /d/obligation.mfotl -log /d/stac.log | grep -c '^@'   # VeriMon:  347
python3 monpoly_experiments/stac_to_dejavu.py                     # DejaVu:  347
```

VeriMon is MonPoly's Isabelle/HOL-verified kernel (`-verified`). DejaVu is an
independently developed engine with a different decision procedure (BDDs over quantified
past-time LTL), so its agreement is not a re-run of the same code.

## Authored-log studies (expressiveness, not field performance)

These need MonPoly. The corpora carry no timestamps, so the metric operators cannot be
exercised on recorded data at all; that is the paper's readiness argument, not a
convenience.

```sh
cd monpoly_experiments
python3 corpus_gen.py && python3 run_corpus.py   # AgentTrace-T, 1400 traces, 100%
python3 metamorphic.py                           # 780/780
python3 mp_time.py                               # throughput: 52k-179k at x1, 0.43-0.45M at x10-x50
cd ../../specs && ./run_monpoly.sh               # timed, building and IoT-lock policies
```
