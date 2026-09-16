"""Feature engineering: session JSONL -> feature matrix.

Two feature views, so RQ2 (early vs full intent) is answerable:
  * build_features(session, mode="early") : uses only the FIRST command +
    pre-auth signals (client banner, username/password tried, first timing).
  * build_features(session, mode="full")  : whole-session aggregates.

Design choice for leakage control (see labeling.py): behavioural features are
primary. Lexical/keyword features are grouped under keys prefixed 'lex_' so an
ablation can drop them and report the behaviour-only score.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from typing import Dict, List

# A small, fixed command vocabulary keeps the feature space stable across runs.
_VOCAB = ["ls", "cd", "cat", "whoami", "id", "uname", "ps", "wget", "curl",
          "chmod", "echo", "rm", "crontab", "ssh", "sh", "bash", "python",
          "history", "sudo", "apt", "systemctl", "kill", "nohup", "grep"]


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _first_token(cmd: str) -> str:
    cmd = (cmd or "").strip()
    return cmd.split()[0] if cmd else ""


def _cmd_features(cmds: List[str], prefix: str) -> Dict[str, float]:
    f: Dict[str, float] = {}
    joined = " ; ".join(cmds)
    f[f"{prefix}_n_cmds"] = len(cmds)
    f[f"{prefix}_total_len"] = len(joined)
    f[f"{prefix}_mean_len"] = (sum(len(c) for c in cmds) / len(cmds)) if cmds else 0
    f[f"{prefix}_entropy"] = _shannon(joined)
    f[f"{prefix}_uniq_first_tok"] = len(set(_first_token(c) for c in cmds))
    f[f"{prefix}_has_pipe"] = float(any("|" in c for c in cmds))
    f[f"{prefix}_has_redirect"] = float(any(">" in c for c in cmds))
    f[f"{prefix}_has_url"] = float(any(re.search(r"https?://", c) for c in cmds))
    f[f"{prefix}_has_semicolon_chain"] = float(any(";" in c or "&&" in c for c in cmds))
    # lexical bag (kept separable via lex_ prefix for the ablation)
    toks = Counter(_first_token(c) for c in cmds)
    for v in _VOCAB:
        f[f"{prefix}_lex_{v}"] = float(toks.get(v, 0))
    return f


def build_features(session: dict, mode: str = "full") -> Dict[str, float]:
    cmds_raw = [c.get("normalized") or c.get("raw") or "" for c in session.get("commands", [])]
    deltas = [c.get("delta_ms", 0) for c in session.get("commands", [])]

    f: Dict[str, float] = {}
    # pre-auth / session-level signals (available even for a 1-command session)
    f["pre_channel_exec"] = float(session.get("channel_type") == "exec")
    f["pre_banner_len"] = len(session.get("client_banner", ""))
    f["pre_user_root"] = float(session.get("username", "") == "root")
    f["pre_pw_len"] = len(session.get("password_tried", ""))
    f["pre_auth_pubkey"] = float(session.get("auth_method") == "publickey")

    if mode == "early":
        early = cmds_raw[:1]
        f.update(_cmd_features(early, "early"))
        f["early_first_delta_ms"] = deltas[0] if deltas else 0
    else:
        f.update(_cmd_features(cmds_raw, "full"))
        f["full_mean_delta_ms"] = (sum(deltas) / len(deltas)) if deltas else 0
        f["full_min_delta_ms"] = min(deltas) if deltas else 0
        f["full_fast_ratio"] = (sum(1 for d in deltas if d < 200) / len(deltas)) if deltas else 0
        f["full_duration_ms"] = session.get("duration_ms", 0) or 0
    return f


def load_sessions(jsonl_path: str) -> List[dict]:
    out = []
    with open(jsonl_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out
