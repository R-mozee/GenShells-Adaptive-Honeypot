# Pre-registration — GenShells field experiment

> Commit this file to git **before** the main deployment starts and never edit
> the hypotheses afterward. Reviewers treat a pre-registered honeypot study far
> more favourably, and it protects you from the "you fished for a p-value"
> critique. Record the git commit hash + date here once frozen.

**Frozen on:** __________  **Commit:** __________

## Research questions & hypotheses
- **RQ1 (fidelity/cost):** Small local models (Phi-3-class, ≤4B, quantised) on
  an M2 reach shell-fidelity within X% of a larger reference model at Y× lower
  latency.
  - H1: median character-break rate of Phi-3 ≤ 10% on the command battery.
- **RQ2 (early intent):** Session tactic is predictable from the first command
  + pre-auth features.
  - H2: macro-F1(early) ≥ 0.60, and macro-F1(full) > macro-F1(early).
  - H2b (leakage): behaviour-only ablation retains ≥ 80% of full macro-F1.
- **RQ3 (adaptation effect):** Intent-conditioned deception (arm C) increases
  engagement vs generative (B) and static (A).
  - H3a: mean commands/session C > B > A (Kruskal-Wallis p < 0.05).
  - H3b: second-stage payload-retrieval rate C > A (two-proportion, p < 0.05).
  - H3c: 7-day return rate C ≥ A.

## Design
- Three arms A/B/C; assignment = `HMAC(salt, IP) mod 3` (see `arms.py`), so a
  returning IP is always in the same arm. Unit of analysis = **session**;
  unit of independence = **IP token** (cluster-robust where needed).
- Duration: **28 days** continuous, after a 7-day pilot (arm B only) used to
  finalise the labeling guide. Stop only for safety, never for a result.

## Primary metrics (locked)
| Metric | Definition | Test |
|---|---|---|
| commands/session | count of accepted commands | Kruskal-Wallis + pairwise MWU, rank-biserial |
| follow-up rate | ≥1 command after the first stage | chi-square + two-proportion z, 95% CI |
| 2nd-stage URL rate | session logs ≥1 new payload URL (never fetched) | chi-square |
| 7-day return rate | same IP token seen ≥24h later | chi-square |
| char-break rate | LLM outputs filtered by `llm_client` | descriptive, per arm/model |
| response latency | ms per response | median + IQR, per arm |

## Analysis rules
- Non-parametric tests for counts (skewed). Report effect sizes + 95% CIs, not
  just p-values. Bonferroni-correct the pairwise arm comparisons.
- Exclude sessions from your own probes/monitoring IP (allowlist file).
- Pre-declared subgroup: bot (exec, sub-second) vs interactive (pty) sessions.

## What would falsify the thesis
If arm C shows **no** improvement over B on any primary metric, that is a
publishable negative result ("intent-conditioning does not change bot
behaviour") — write it up as such rather than hunting for significance.
