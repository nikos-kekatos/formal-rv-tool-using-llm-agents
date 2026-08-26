# Formal Runtime Verification for Tool-Using LLM Agents

An offline same-benchmark study on AgentDojo and STAC.

**Authors.** Nikolaos Kekatos, Stylianos Basagiannis, Marinelio Chintri,
Panagiotis Katsaros, Alexios Lekidis, Tom Nianios, Ioannis Seitoglou,
Anastasios Temperekidis.

**Venue.** Accepted at the 8th Joint Workshop on CPS & IoT Security and Privacy
(CPSIoTSec 2026), co-located with ACM CCS 2026, The Hague, 15 November 2026.

We express five generic obligations plus two parametric ones in metric first-order
temporal logic (MFOTL) and replay three benchmarks of **recorded** agent
trajectories — AgentDojo, STAC and R-Judge — through the **unmodified MonPoly**
engine. Everything runs offline: no LLM, no API key, no live agent. The paper is
deliberately explicit that on these corpora the *generic* obligations reduce to
typed-action detection, because the recorded traces carry almost no approvals and
no timestamps; the claims that rest on the formalism are the parametric
obligations, the timed policies, and the benchmark readiness scorecard.

## Layout

```
paper/    camera-ready manuscript, LaTeX source and bibliography
code/     the analysis scripts (pure Python 3 standard library)
  monpoly_experiments/   the studies that additionally need a MonPoly binary
specs/    the MFOTL specifications, signatures and logs
data/     you populate this — the benchmarks are NOT redistributed here
RESULTS.md  every number in the paper, with the command that produces it
```

## Requirements

* **Python 3.9+.** Standard library only. No `pip install` step, no virtualenv.
* **MonPoly** — only for `code/monpoly_experiments/` and `specs/`. Everything
  else runs without it. Build from
  [github.com/monpoly/monpoly](https://github.com/monpoly/monpoly) and put the
  binary on `PATH`. The reference monitor in `code/` is an independent
  implementation; the point of MonPoly is that our headline STAC firings come
  from an engine we did not write.

## Step 1 — get the benchmark data

None of the three benchmarks is redistributed here; each has its own licence.

### AgentDojo (required for most scripts)

AgentDojo ships ~36k **recorded run trajectories** in its own repository, which is
what makes this study possible offline. A full clone is large, so fetch only the
runs:

```sh
git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/ethz-spylab/agentdojo.git
cd agentdojo
git sparse-checkout set runs                    # all 29 model dirs, ~477 MB
# or, for the single-model results only (~75 MB):
git sparse-checkout set runs/gpt-4o-2024-05-13
```

The paper's headline table uses `runs/gpt-4o-2024-05-13`. The pooled McNemar
tests and the cross-model sign test need **all** model directories.

Point `data/` at it, or pass the path explicitly to every script:

```sh
ln -s /path/to/agentdojo/runs data/agentdojo_runs
```

### STAC

From [github.com/amazon-science/MultiTurnAgentAttack](https://github.com/amazon-science/MultiTurnAgentAttack)
(483 recorded attack chains). Place the benchmark JSON at:

```
data/STAC_benchmark_data.json
```

That is the default path `stac_rv.py` looks for, so STAC scripts then need no
arguments.

### R-Judge

From [github.com/Lordog/R-Judge](https://github.com/Lordog/R-Judge). Pass its
data file to `rjudge_rv.py --data`. Only the R-Judge row of the readiness
scorecard depends on it.

## Step 2 — reproduce the results

All commands are run from `code/`. `$AD` is your AgentDojo `runs` directory.

```sh
cd code
AD=../data/agentdojo_runs
```

### No data or extra tools needed

```sh
python3 wilson_ci.py          # the Wilson intervals quoted in the tables
python3 mcnemar.py            # single-model McNemar — reports NOT significant, by design
python3 canon_eval.py         # canonicalisation precision/recall/F1 over 54 tools
```

`mcnemar.py` deliberately reports the *single-model* comparison, which is **not**
significant (banking p=0.0625 on 25 benign runs). This is the paper's own point:
single-model denominators are too small, which is why the headline p-values come
from the pooled test below. The two scripts are not in conflict.

### STAC

```sh
python3 stac_rv.py                                    # 347/483 = 71.8% final-step detection
python3 stac_to_monpoly.py --data ../data/STAC_benchmark_data.json --out /tmp/stac
monpoly -sig /tmp/stac/stac.sig -formula /tmp/stac/obligation.mfotl \
        -log /tmp/stac/stac.log                       # fires on exactly the same 347
```

### AgentDojo, single model (GPT-4o)

```sh
python3 agentdojo_rv.py       --runs $AD/gpt-4o-2024-05-13     # 61.6% detection, 31.7% BFR
python3 agentdojo_param.py    --banking $AD/gpt-4o-2024-05-13/banking
python3 agentdojo_param2.py   --workspace $AD/gpt-4o-2024-05-13/workspace
python3 combined_ablation.py  --runs $AD/gpt-4o-2024-05-13
python3 per_oblig_ablation.py --runs $AD/gpt-4o-2024-05-13
python3 first_firing.py       --runs $AD/gpt-4o-2024-05-13 --stac ../data/STAC_benchmark_data.json
python3 risk_enrichment.py    --runs $AD/gpt-4o-2024-05-13
python3 canon_sensitivity.py  --runs $AD/gpt-4o-2024-05-13 --stac ../data/STAC_benchmark_data.json
```

Per-suite numbers come from pointing `agentdojo_rv.py` at one suite:

```sh
python3 agentdojo_rv.py --runs $AD/gpt-4o-2024-05-13/banking
```

### AgentDojo, pooled across models — the headline significance results

These need every model directory, not just GPT-4o:

```sh
python3 agentdojo_param_pooled.py --root $AD    # McNemar p=5.29e-23 / 1.46e-11
python3 cross_model.py            --root $AD    # cross-model sign test
python3 agentdojo_scenarios.py    --root $AD
```

### Readiness scorecard

```sh
python3 readiness_scorecard.py --stac ../data/STAC_benchmark_data.json \
                               --agentdojo $AD --rjudge /path/to/rjudge/data
```

### Studies needing MonPoly

```sh
cd monpoly_experiments
python3 corpus_gen.py          # generate the AgentTrace-T synthetic corpus
python3 run_corpus.py          # verdict / parameter-binding accuracy
python3 metamorphic.py         # the 780 metamorphic transformations
python3 mp_time.py             # MonPoly throughput
python3 gen_stac_scale.py      # scaled STAC logs for the throughput study
python3 agentdojo_to_monpoly.py
python3 perturb_provenance.py --banking $AD/gpt-4o-2024-05-13/banking \
                              --workspace $AD/gpt-4o-2024-05-13/workspace
```

`corpus_gen.py`, `run_corpus.py` and `metamorphic.py` operate on traces authored
**against** the specifications they then check. Their perfect scores measure
whether the metric and first-order operators behave as specified — an
implementation check — not field accuracy. The paper says so next to the numbers.

## Step 3 — the specifications

`specs/` holds the MFOTL formulas, MonPoly signatures and logs for the studies the
paper reports:

```
specs/stac/       obligation.mfotl, stac.sig, stac.log      the 347-firing export
specs/timed/      consent, rate, prec  (.mfotl/.sig/.log)   the timed policies
specs/building/   p1-p3.mfotl, building_x.{sig,log}         multi-instance actuation
specs/iot/        lock.{mfotl,sig,log}                      the R-Judge IoT lock case
specs/run_monpoly.sh
```

Run one directly:

```sh
monpoly -sig specs/timed/consent.sig -formula specs/timed/consent.mfotl \
        -log specs/timed/consent.log
```

## Verified numbers

`RESULTS.md` records the reruns behind the camera-ready, including the two
reviewer questions about apparently inconsistent rates and why both figures are
correct. Two denominator conventions coexist deliberately and are documented
there: `agentdojo_rv.py` counts only runs with a non-empty tool-call chain, while
`agentdojo_param*.py` counts every run with a non-empty message list.

## Licence

Code and specifications: see `LICENSE`. The paper is under the ACM copyright
recorded in the proceedings. The benchmark datasets remain under their own
licences and are not redistributed here.
