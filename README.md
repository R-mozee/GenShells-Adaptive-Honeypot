# GenShells: LLM-Driven Adaptive Cyber Deception

> **Paper title (working):** *Generative Shells: Local Large Language Models for
> Adaptive Cyber Deception and Attacker Intent Classification*
> **Target:** IEEE conference/journal. Built for a Mac M2 (16 GB), zero budget.

GenShells is a from-scratch SSH honeypot that (1) uses a **small local LLM** to
hallucinate a coherent Ubuntu shell, (2) **predicts attacker intent** (MITRE
ATT&CK tactic) in real time — including from a single non-interactive command,
and (3) **conditions its deception on that prediction**, then measures whether
adaptation changes attacker behaviour in a controlled 3-arm field experiment.

## Why this is novel (the gap it fills)
Prior LLM honeypots (shelLM 2023, HoneyLLM 2024, AdvancedShelLM 2026) make the
shell realistic but do **not** classify intent or adapt to it. Log-analysis work
(LogPrécis 2024) labels sessions but doesn't drive deception. GenShells closes
the loop — predict → adapt → measure — on consumer hardware. See
`docs/` and the research plan for the full literature positioning.

## Architecture
```
 SSH client ─▶ paramiko server (exec + interactive)  src/honeypot.py
                     │  (accepts any creds, logs timing/backspaces/latency)
                     ▼
             DeceptionEngine  src/deception/engine.py
              ├─ deterministic layer  (fast, correct, coherent)   deterministic.py
              ├─ local LLM (Ollama/Phi-3) for the long tail       llm_client.py
              │     └─ character-break filter + safe fallback
              └─ arm A/B/C selection (HMAC of IP)                 arms.py
                     │
        EarlyIntentPredictor (MITRE tactic, live)  ml/online_intent.py
                     ▼
        JSONL logs (hashed IPs)  ──▶  ml/ (features, labels, train)  ──▶
                                      analysis/ (3-arm stats)
```

## Key design decisions (and the research reason for each)
- **Handles `exec` requests, not just shells** — ~99% of real post-login SSH
  activity is a single non-interactive command (Ghost Without Shell, 2026).
- **Deterministic-first, LLM for the tail** — removes model-attributable risk
  and latency for common commands (Magazov et al., 2026).
- **Per-session state** (cwd, fs, planted keys) — prior LLM honeypots were
  caught on state inconsistency (AdvancedShelLM, 2026).
- **Latency logged per response** — latency is a known honeypot fingerprint.
- **MITRE ATT&CK tactic labels + leakage-controlled features** — comparable to
  LogPrécis; avoids the "classifier just relearns the keyword rule" trap.
- **Never executes/downloads anything; egress kernel-blocked** — see `docs/ETHICS.md`.

## Quickstart (Mac M2)
```bash
brew install ollama && brew services start ollama
ollama pull phi3
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 1) run the honeypot locally (safe, port 2222)
python -m src.honeypot
#   in another tab:
ssh root@127.0.0.1 -p 2222            # interactive
ssh root@127.0.0.1 -p 2222 "uname -a" # exec (the common case)

# 2) RQ1 lab benchmark (fidelity/latency across local models) -> Table 1
python -m ml.benchmark_models --models phi3 qwen2.5:3b tinyllama

# 3) RQ2 intent classifier (runs on synthetic data until you capture real logs)
python -m ml.train --data logs/sessions.jsonl --out models

# 4) RQ3 field-experiment stats (synthetic demo until deployment)
python -m analysis.experiment_stats --data logs/sessions.jsonl
```
Everything in steps 2–4 runs on synthetic data before you have real captures, so
the pipeline is provably working from day one.

## Repository layout
```
src/            honeypot server + deception engine (exec & interactive)
ml/             features, MITRE labeling, early-intent predictor, training, RQ1 benchmark
analysis/       3-arm experiment statistics
docs/           DEPLOYMENT (VPS+tunnel+egress), PREREGISTRATION, ETHICS, LABELING_GUIDE
tests/          smoke tests (run: python tests/test_deterministic.py)
config.yaml     all knobs (arm mode, salt, model, timeouts)
```

## Research questions
- **RQ1** How close do small local models get to larger ones on shell fidelity,
  character-break rate, and latency, on an M2?
- **RQ2** How accurately can tactic be predicted from the first command + pre-auth
  signals vs the full session? (leakage-controlled)
- **RQ3** Does intent-conditioned deception change attacker behaviour vs static
  and non-adaptive generative baselines?

## Status
Phase 1–2 complete (server + engine + pipeline). Next: RQ1 benchmark on your
Mac, then pilot deployment. See the research plan and `docs/PREREGISTRATION.md`.

## Safety
Read `docs/DEPLOYMENT.md` and `docs/ETHICS.md` **before** exposing anything to
the internet. Never run the internet-facing node on your Mac.
