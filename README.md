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

## Status

**Manuscript only.** The evaluation scripts named in the paper are not in this repository yet; they
will be added before camera-ready.
