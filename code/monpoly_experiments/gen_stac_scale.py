#!/usr/bin/env python3
"""Build an N-times replicated STAC log with DISTINCT case ids and offset
timestamps, so ONCE[0,W] provenance stays sound (no approval from replica i can
satisfy an obligation in replica j; timestamps stay monotone non-decreasing).

Replica k adds k*ID_OFF to every case id and k*TS_OFF to every timestamp.
ID_OFF > max_id and TS_OFF > max_ts guarantee no id / no time-window overlap.
"""
import re, sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "../stac/stac.log"
OUT = sys.argv[2] if len(sys.argv) > 2 else "logs/stac_x10.log"
N = int(sys.argv[3]) if len(sys.argv) > 3 else 10

rows = []
mx_id = mx_t = 0
for ln in open(SRC):
    m = re.match(r"@(\d+)\s+(\w+)\((\d+)\)", ln.strip())
    if not m:
        continue
    t, p, c = int(m.group(1)), m.group(2), int(m.group(3))
    rows.append((t, p, c))
    mx_id = max(mx_id, c); mx_t = max(mx_t, t)

ID_OFF = mx_id + 1000          # 1481: disjoint id namespaces per replica
TS_OFF = mx_t + 1000           # 1356: window ONCE[0,1000000] would still see prior
# NOTE: the paper obligation uses ONCE[0,1000000]; to keep replicas independent we
# also renumber ids per replica (disjoint), which alone makes ONCE sound because
# approval(c) only matches the SAME c. Timestamp offset keeps the stream monotone.
n = 0
with open(OUT, "w") as f:
    for k in range(N):
        for (t, p, c) in rows:
            f.write(f"@{t + k*TS_OFF} {p}({c + k*ID_OFF})\n")
            n += 1
print(f"wrote {OUT}: {n} events, {N} replicas, id_off={ID_OFF}, ts_off={TS_OFF}")
