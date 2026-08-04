#!/usr/bin/env python3
"""In-container timing wrapper for the REAL MonPoly binary.

Runs /usr/local/bin/monpoly as a child process, measures its wall-clock with
time.perf_counter and its peak resident set with resource.getrusage(RUSAGE_CHILDREN).
Emits one JSON line so the host can collect real numbers. No fabrication: every
figure comes from the actual monpoly process this script forks.

Usage (inside the rv-fabric-impl-backend container):
  python3 mp_time.py <sig> <formula> <log> [reps]
"""
import sys, time, resource, subprocess, json

sig, formula, log = sys.argv[1], sys.argv[2], sys.argv[3]
reps = int(sys.argv[4]) if len(sys.argv) > 4 else 1

walls = []
firings = None
for _ in range(reps):
    t0 = time.perf_counter()
    p = subprocess.run(
        ["/usr/local/bin/monpoly", "-sig", sig, "-formula", formula, "-log", log],
        capture_output=True, text=True)
    t1 = time.perf_counter()
    walls.append(t1 - t0)
    firings = sum(1 for ln in p.stdout.splitlines() if ln.strip())

# ru_maxrss is KB on Linux; reflects the largest child (monpoly) seen so far
maxrss_kb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
best = min(walls)
print(json.dumps({
    "log": log, "reps": reps,
    "wall_best_s": round(best, 4),
    "wall_mean_s": round(sum(walls) / len(walls), 4),
    "maxrss_kb": maxrss_kb,
    "firings": firings,
    "exit": p.returncode,
}))
