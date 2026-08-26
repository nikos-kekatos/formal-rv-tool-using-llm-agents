#!/usr/bin/env bash
# Reproduce every real-MonPoly result in the paper. Requires the Docker image
# rv-fabric-impl-backend, which ships MonPoly ("development build") at
# /usr/local/bin/monpoly. Each run mounts the study dir at /w and invokes the
# unmodified binary; the printed lines "@t. (time point ...): (...)" are firings.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
IMG=rv-fabric-impl-backend
mp() { # dir sig formula log
  docker run --rm -v "$HERE/$1":/w --entrypoint monpoly "$IMG" \
    -sig "/w/$2" -formula "/w/$3" -log "/w/$4" 2>&1
}
echo "== MonPoly version =="; docker run --rm --entrypoint monpoly "$IMG" -version

echo; echo "== TIMED: (T1) bounded consent W=24h (fires only @48, consent stale) =="
mp timed consent.sig consent.mfotl consent.log
echo "== TIMED: (T2) rate limit >=3 in W=6h (fires @5 count 3; spaced calls silent) =="
mp timed rate.sig rate.mfotl rate.log
echo "== TIMED: (T3) precedence W=8h (fires only @40, auth 40h old) =="
mp timed prec.sig prec.mfotl prec.log

echo; echo "== BUILDING (multi-instance): P1/P2/P3, fires {4,5},{9,14},{19,22} =="
for p in p1 p2 p3; do echo "-- $p --"; mp building building_x.sig "$p.mfotl" building_x.log; done

echo; echo "== IoT lock consent (fires @0 grant-before-consent) =="
mp iot lock.sig lock.mfotl lock.log

echo; echo "== STAC obligation disjunction (347 firings, matches reference monitor) =="
mp stac stac.sig obligation.mfotl stac.log | wc -l
