"""Analysis for the 3-arm field experiment (RQ3).

Compares arms A (static), B (generative), C (adaptive) on the engagement and
detection metrics defined in docs/PREREGISTRATION.md, with the RIGHT tests:
  * proportions (follow-up rate, 2nd-stage URL rate, return rate) -> chi-square
    / two-proportion z, with 95% CIs.
  * counts (commands per session) -> Kruskal-Wallis across arms + pairwise
    Mann-Whitney U (non-parametric; command counts are skewed), with a
    rank-biserial effect size.
  * latency distribution per arm (the fingerprint metric) -> medians + IQR.

Runs on logs/sessions.jsonl. Generates a synthetic 3-arm set if absent, so the
analysis and figures are runnable before real capture.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
from collections import defaultdict
from typing import List

import numpy as np
from scipy import stats


def load(path) -> List[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                out.append(json.loads(line))
    return out


def _synth(path, n=1500, seed=11):
    random.seed(seed)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    # planted effect: C keeps attackers slightly longer & more 2nd-stage attempts
    eff = {"A": (2.0, 0.10, 0.08), "B": (2.6, 0.16, 0.12), "C": (3.3, 0.24, 0.18)}
    with open(path, "w") as fh:
        for i in range(n):
            arm = random.choice("ABC")
            mean_cmds, follow_p, url_p = eff[arm]
            k = max(1, int(np.random.poisson(mean_cmds)))
            cmds = [{"seq": j, "raw": "cmd", "normalized": "cmd",
                     "delta_ms": random.randint(20, 300),
                     "response_latency_ms": random.randint(2, 40) if arm == "A"
                     else random.randint(300, 2200),
                     "response_source": "static" if arm == "A" else "llm"}
                    for j in range(k)]
            rec = {"session_id": f"s{i}", "ip_token": f"ip{random.randint(0,400)}",
                   "arm": arm, "channel_type": "exec" if k == 1 else "shell",
                   "n_commands": k, "duration_ms": k * random.randint(200, 900),
                   "has_followup": int(random.random() < follow_p),
                   "has_second_stage_url": int(random.random() < url_p),
                   "returned_7d": int(random.random() < (0.05 if arm == "A" else 0.11)),
                   "commands": cmds}
            fh.write(json.dumps(rec) + "\n")


def _prop_ci(k, n):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    se = math.sqrt(p * (1 - p) / n)
    return (round(p, 3), round(max(0, p - 1.96 * se), 3), round(min(1, p + 1.96 * se), 3))


def analyze(sessions):
    by_arm = defaultdict(list)
    for s in sessions:
        by_arm[s.get("arm", "?")].append(s)

    report = {"arms": {}, "tests": {}}
    for arm, ss in sorted(by_arm.items()):
        n = len(ss)
        cmds = [s.get("n_commands", len(s.get("commands", []))) for s in ss]
        lat = [c.get("response_latency_ms", 0) for s in ss for c in s.get("commands", [])]
        follow = sum(s.get("has_followup", 0) for s in ss)
        url = sum(s.get("has_second_stage_url", 0) for s in ss)
        ret = sum(s.get("returned_7d", 0) for s in ss)
        report["arms"][arm] = {
            "n_sessions": n,
            "median_cmds": float(np.median(cmds)) if cmds else 0,
            "mean_cmds": round(float(np.mean(cmds)), 2) if cmds else 0,
            "followup_rate": _prop_ci(follow, n),
            "second_stage_url_rate": _prop_ci(url, n),
            "return_7d_rate": _prop_ci(ret, n),
            "latency_ms_median": float(np.median(lat)) if lat else 0,
            "latency_ms_iqr": [float(np.percentile(lat, 25)), float(np.percentile(lat, 75))] if lat else [0, 0],
        }

    arms = sorted(by_arm)
    # commands per session: Kruskal-Wallis + pairwise Mann-Whitney
    groups = [[s.get("n_commands", len(s.get("commands", []))) for s in by_arm[a]] for a in arms]
    if all(len(g) > 1 for g in groups) and len(groups) > 1:
        H, p = stats.kruskal(*groups)
        report["tests"]["cmds_kruskal"] = {"H": round(float(H), 3), "p": round(float(p), 5)}
        report["tests"]["cmds_pairwise_mannwhitney"] = {}
        for i in range(len(arms)):
            for j in range(i + 1, len(arms)):
                u, pu = stats.mannwhitneyu(groups[i], groups[j], alternative="two-sided")
                n1, n2 = len(groups[i]), len(groups[j])
                rbc = 1 - (2 * u) / (n1 * n2)   # rank-biserial effect size
                report["tests"]["cmds_pairwise_mannwhitney"][f"{arms[i]}_vs_{arms[j]}"] = {
                    "U": float(u), "p": round(float(pu), 5), "rank_biserial": round(float(rbc), 3)}

    # follow-up rate: chi-square across arms
    table = [[sum(s.get("has_followup", 0) for s in by_arm[a]),
              len(by_arm[a]) - sum(s.get("has_followup", 0) for s in by_arm[a])] for a in arms]
    if len(arms) > 1:
        chi2, pc, _, _ = stats.chi2_contingency(table)
        report["tests"]["followup_chi2"] = {"chi2": round(float(chi2), 3), "p": round(float(pc), 5)}
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="logs/sessions.jsonl")
    ap.add_argument("--out", default="analysis/experiment_report.json")
    args = ap.parse_args()
    if not (os.path.exists(args.data) and os.path.getsize(args.data) > 0):
        print("[stats] no data -> generating SYNTHETIC 3-arm sessions (demo only)")
        _synth(args.data)
    rep = analyze(load(args.data))
    with open(args.out, "w") as fh:
        json.dump(rep, fh, indent=2)
    print(json.dumps(rep, indent=2))


if __name__ == "__main__":
    main()
