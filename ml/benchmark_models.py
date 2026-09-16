"""RQ1 harness: fidelity, hallucination, character-break & latency of local
models on a fixed command battery, on YOUR Mac M2.

Run with Ollama up:
  ollama pull phi3; ollama pull qwen2.5:3b; ollama pull tinyllama
  python -m ml.benchmark_models --models phi3 qwen2.5:3b tinyllama

For each (model, command) it records latency and whether the output broke
character (reused from llm_client's filter). Ground-truth for a subset of
commands is provided so you can score exact/near-match fidelity. Writes
models/rq1_benchmark.csv for the paper's Table 1.

Zero real attacker data needed — this is a controlled lab benchmark, so you can
run it on day one and already have one paper table.
"""
from __future__ import annotations

import argparse
import csv
import os
import time

from src.deception.llm_client import LLMClient, _BREAK_RE
from src.deception.session_state import SessionState

# Command battery: mix of easy (deterministic ground truth) + hard (long tail).
BATTERY = [
    ("uname -a", "Linux srv-prod-01"),
    ("whoami", "root"),
    ("id", "uid=0(root)"),
    ("pwd", "/root"),
    ("cat /etc/os-release", "Ubuntu 24.04"),
    ("ls -la /root", None),
    ("ps aux | head", None),
    ("free -m", None),
    ("cat /proc/cpuinfo | grep model", None),
    ("netstat -tulpn", None),
    ("crontab -l", None),
    ("find / -name '*.pem' 2>/dev/null", None),
    ("nvidia-smi", None),
    ("docker ps", None),
    ("cat ~/.bash_history", None),
]


def run(models, out_csv):
    rows = []
    state = SessionState(hostname="srv-prod-01", emulated_os="Ubuntu 24.04 LTS")
    for model in models:
        client = LLMClient({"enabled": True, "model": model,
                            "base_url": "http://127.0.0.1:11434", "timeout_sec": 60})
        if not client.available():
            print(f"[skip] Ollama not reachable for {model}")
            continue
        for cmd, truth in BATTERY:
            t0 = time.perf_counter()
            out, char_break = client.generate(cmd, state)
            dt = int((time.perf_counter() - t0) * 1000)
            text = out if out is not None else ""
            hit = (truth is not None and truth.lower() in (text or "").lower())
            rows.append({
                "model": model, "command": cmd, "latency_ms": dt,
                "char_break": int(char_break),
                "has_ground_truth": int(truth is not None),
                "fidelity_hit": int(hit) if truth is not None else "",
                "output_len": len(text or ""),
            })
            print(f"{model:14} {dt:6d}ms break={int(char_break)} :: {cmd[:32]}")
    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    with open(out_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else
                           ["model", "command", "latency_ms", "char_break",
                            "has_ground_truth", "fidelity_hit", "output_len"])
        w.writeheader()
        w.writerows(rows)
    print(f"\nWrote {len(rows)} rows -> {out_csv}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=["phi3"])
    ap.add_argument("--out", default="models/rq1_benchmark.csv")
    args = ap.parse_args()
    run(args.models, args.out)
