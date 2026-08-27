#!/usr/bin/env sh
# Reproduce the results that need no benchmark download and no external engine.
# Everything else is documented in README.md, which lists the exact command per table.
set -e
cd "$(dirname "$0")/code"
echo "== Wilson intervals quoted in the tables =="       ; python3 wilson_ci.py
echo; echo "== single-model McNemar (reports NOT significant, by design) ==" ; python3 mcnemar.py
echo; echo "== canonicalisation precision/recall/F1 over 54 tools =="        ; python3 canon_eval.py
if [ -f ../data/STAC_benchmark_data.json ]; then
  echo; echo "== STAC replay (expects 347/483 = 71.8%) =="; python3 stac_rv.py
else
  echo; echo "-- STAC data absent: place STAC_benchmark_data.json in data/ (see README) --"
fi
