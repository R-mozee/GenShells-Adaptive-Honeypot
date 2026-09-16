"""RQ1 benchmark v2 — repeated trials with variance + confidence intervals.

Improvements over benchmark_models.py:
  * One untimed WARM-UP call per model (removes cold-load outlier cleanly).
  * Each command run N times (default 5) -> latency mean/std/median + 95% CI.
  * break rate and fidelity reported as proportions with Wilson 95% CIs.
  * Writes raw per-run CSV (models/rq1_runs.csv) AND a summary CSV
    (models/rq1_summary.csv) you can hand straight to the figure step.

Run:
  python -m ml.benchmark_v2 --models qwen2.5:3b phi3 tinyllama --repeats 5
"""
from __future__ import annotations

import argparse
import csv
import math
import os
import statistics as st
import time

from src.deception.llm_client import LLMClient
from src.deception.session_state import SessionState

# 15-command battery; (command, ground_truth_substring or None)
BATTERY = [
    ("uname -a", "Linux srv-prod-01"), ("whoami", "root"), ("id", "uid=0(root)"),
    ("pwd", "/root"), ("cat /etc/os-release", "Ubuntu 24.04"),
    ("ls -la /root", None), ("ps aux | head", None), ("free -m", None),
    ("cat /proc/cpuinfo | grep model", None), ("netstat -tulpn", None),
    ("crontab -l", None), ("find / -name '*.pem' 2>/dev/null", None),
    ("nvidia-smi", None), ("docker ps", None), ("cat ~/.bash_history", None),
]


def wilson(k, n, z=1.96):
    """Wilson 95% CI for a proportion (better than normal approx for small n)."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1 + z*z/n
    centre = (p + z*z/(2*n)) / denom
    half = (z * math.sqrt(p*(1-p)/n + z*z/(4*n*n))) / denom
    return (round(100*p, 1), round(100*max(0, centre-half), 1), round(100*min(1, centre+half), 1))


def mean_ci(xs, z=1.96):
    if len(xs) < 2:
        return (xs[0] if xs else 0, 0, 0, 0)
    m = st.mean(xs); sd = st.pstdev(xs)
    half = z * sd / math.sqrt(len(xs))
    return (round(m), round(sd), round(m-half), round(m+half))


def run(models, repeats, out_dir):
    state = SessionState(hostname="srv-prod-01", emulated_os="Ubuntu 24.04 LTS")
    os.makedirs(out_dir, exist_ok=True)
    raw_rows, sum_rows = [], []

    for model in models:
        client = LLMClient({"enabled": True, "model": model,
                            "base_url": "http://127.0.0.1:11434", "timeout_sec": 60})
        if not client.available():
            print(f"[skip] Ollama not reachable for {model}")
            continue
        # WARM-UP (untimed) so the first measured call isn't a cold load
        print(f"[{model}] warming up...")
        client.generate("echo warmup", state)

        lat_all, breaks, fid_hits, fid_n = [], 0, 0, 0
        for cmd, truth in BATTERY:
            for rep in range(repeats):
                t0 = time.perf_counter()
                out, cbreak = client.generate(cmd, state)
                dt = int((time.perf_counter()-t0)*1000)
                text = out if out is not None else ""
                hit = (truth is not None and truth.lower() in text.lower())
                lat_all.append(dt)
                breaks += int(cbreak)
                if truth is not None:
                    fid_n += 1; fid_hits += int(hit)
                raw_rows.append({"model": model, "command": cmd, "rep": rep,
                                 "latency_ms": dt, "char_break": int(cbreak),
                                 "has_ground_truth": int(truth is not None),
                                 "fidelity_hit": int(hit) if truth is not None else "",
                                 "output_len": len(text)})
            print(f"  {model:12} {cmd[:34]:34} x{repeats} done")

        n = repeats * len(BATTERY)
        m, sd, lo, hi = mean_ci(lat_all)
        fp = wilson(fid_hits, fid_n); bp = wilson(breaks, n)
        sum_rows.append({
            "model": model, "n_runs": n,
            "fidelity_pct": fp[0], "fidelity_ci": f"[{fp[1]}, {fp[2]}]", "fidelity_n": fid_n,
            "break_pct": bp[0], "break_ci": f"[{bp[1]}, {bp[2]}]",
            "latency_mean_ms": m, "latency_std_ms": sd,
            "latency_ci_ms": f"[{lo}, {hi}]", "latency_median_ms": round(st.median(lat_all)),
        })

    with open(os.path.join(out_dir, "rq1_runs.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(raw_rows[0].keys()))
        w.writeheader(); w.writerows(raw_rows)
    with open(os.path.join(out_dir, "rq1_summary.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(sum_rows[0].keys()))
        w.writeheader(); w.writerows(sum_rows)

    print("\n=== SUMMARY (mean [95% CI]) ===")
    for r in sum_rows:
        print(f"{r['model']:12}  fidelity {r['fidelity_pct']}% {r['fidelity_ci']}  "
              f"break {r['break_pct']}% {r['break_ci']}  "
              f"latency {r['latency_mean_ms']}ms {r['latency_ci_ms']}")
    print(f"\nWrote {len(raw_rows)} runs -> {out_dir}/rq1_runs.csv")
    print(f"Wrote summary -> {out_dir}/rq1_summary.csv")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=["qwen2.5:3b", "phi3", "tinyllama"])
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--out", default="models")
    args = ap.parse_args()
    run(args.models, args.repeats, args.out)
