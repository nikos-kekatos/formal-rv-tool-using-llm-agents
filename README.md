# Formal Runtime Verification for Tool-Using LLM Agents

An offline same-benchmark study on AgentDojo and STAC.

**Authors.** Nikolaos Kekatos, Marinelio Chintri, Panagiotis Katsaros, Alexios Lekidis,
Tom Nianios, Ioannis Seitoglou, Anastasios Temperekidis, Stylianos Basagiannis.
Submitted to the **CPSIoTSec** workshop.

Evaluates formal obligations against two existing agent-security benchmarks offline on the same
traces, so the monitor is measured against published attacks rather than a bespoke scenario. It
reports how early each obligation fires and ablates obligations individually.

**Properties.** Metric first-order temporal obligations in MFOTL, monitored by MonPoly in violation
form, with per-obligation ablation, plus coverage and threshold obligations over tool-call traces.

## Layout

```
paper/   manuscript and source
code/    the 18 scripts the paper names, plus 4 MonPoly experiments
  agentdojo_rv.py, stac_rv.py, rjudge_rv.py      per-benchmark monitoring
  stac_to_monpoly.py                             obligation compilation to MFOTL
  per_oblig_ablation.py, combined_ablation.py    the ablations
  first_firing.py                                prevention-timing (how early an obligation fires)
  agentdojo_param{,2,_pooled}.py                 parameter studies
  canon_eval.py, canon_sensitivity.py            canonicalisation and its sensitivity
  cross_model.py, risk_enrichment.py             cross-model and enrichment studies
  mcnemar.py, wilson_ci.py                       significance tests and intervals
  readiness_scorecard.py                         the summary scorecard
  monpoly_experiments/                           corpus_gen, metamorphic, mp_time, perturb_provenance
data/    empty — the benchmarks are not bundled (see below)
```

## Benchmark data

**The benchmarks are not redistributed here.** AgentDojo, STAC and R-Judge are published
separately under their own licences. Fetch them and place them under `data/`:

```
data/stac/data/STAC_benchmark_data.json
data/agentdojo/runs/
data/rjudge/data/
```

Every script takes an explicit override, e.g. `python3 code/stac_rv.py --data <path>`.

## Run

Python standard library only; `monpoly_experiments/` additionally needs a MonPoly binary on PATH.

```sh
cd code
python3 stac_rv.py                 # defaults to ../data/STAC_benchmark_data.json
python3 per_oblig_ablation.py
python3 readiness_scorecard.py
```
