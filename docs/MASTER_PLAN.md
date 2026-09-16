# GenShells → IEEE: Complete Plan from Today to Publication

**For:** Veera · **Hardware:** Mac M2, 16 GB · **Budget:** ₹0 · **Level:** university
**Start:** 12 Sep 2026 · **Target submission:** ~end of Jan 2027 (~20 weeks)
**Tools you already have:** NotebookLM (157 sources), Zotero.

---

## 0. Read this first — the honest budget reality

"Zero budget" and "IEEE" are in mild tension, so plan for it now:

- **IEEE conferences** charge *registration* (₹15k–40k+) to publish, even after
  acceptance. **IEEE Access** (journal) has an APC of ~USD 1,850. Neither is free.
- **What IS free and still counts:**
  1. Post an **arXiv preprint** the day you submit — free, citable, timestamps
     your novelty. Do this regardless of venue.
  2. Apply for **student registration + travel/registration grants** (most IEEE
     conferences and your university have these; ask your department/HOD).
  3. Aim first at an **IEEE-sponsored workshop or a student-friendly IEEE
     conference** with lower fees, rather than a flagship.
- **Decision to make with your advisor:** if registration truly can't be funded,
  a strong free path is arXiv + a no-APC venue (e.g., a USENIX/ACM workshop with
  fee waivers, or a Scopus-indexed open conference), then upgrade to IEEE later.
  I'll assume **IEEE conference + arXiv preprint** as the target; adjust once you
  know what funding your university offers.

**Compute:** everything trains on your M2. The only thing you can't run locally
is *internet exposure* — use **Oracle Cloud Always Free** (ARM, 24 GB, ₹0
forever) as the VPS. That keeps the whole project at ₹0 except possible
registration.

---

## 1. The one-sentence thesis (memorise it)

> *A small local LLM can run a coherent SSH honeypot on consumer hardware,
> predict attacker intent (MITRE tactic) from as little as the first command,
> and condition its deception on that prediction — and we measure whether that
> adaptation changes attacker behaviour.*

Everything you build must serve that sentence. The novelty is the **closed loop
(predict → adapt → measure)** on **consumer hardware**, which no prior LLM
honeypot does.

---

## 2. What already exists (built today)

A working, tested codebase (`GenShells-Adaptive-Honeypot/`):
- `src/honeypot.py` — paramiko SSH server handling **exec + interactive**, per-command
  timing/backspace/latency logging, hashed IPs.
- `src/deception/` — deterministic-first engine, Ollama/Phi-3 client with a
  **character-break filter + safe fallback**, per-session state (cwd/fs/planted keys),
  and A/B/C arm selection.
- `ml/` — MITRE-tactic labeling, early-intent predictor (live), leakage-controlled
  features, XGBoost/RF training with **time+IP split**, and an RQ1 model benchmark.
- `analysis/` — 3-arm experiment stats (Kruskal-Wallis, Mann-Whitney, chi-square, CIs).
- `docs/` — DEPLOYMENT, PREREGISTRATION, ETHICS, LABELING_GUIDE.
- `tests/` — all passing. The ML + stats pipelines run on synthetic data **now**.

So you begin week 1 with a running system, not a blank page.

---

## 3. Phase timeline (20 weeks)

### Phase 0 — Setup & positioning (Week 1: Sep 12–19)
- [ ] Install: `brew install ollama`, `ollama pull phi3 qwen2.5:3b tinyllama`,
      `pip install -r requirements.txt`. Run the honeypot locally, SSH into it.
- [ ] **Zotero + NotebookLM:** from your 157 sources, pull the 20 most relevant
      into a Zotero collection "GenShells-core". For each, note in one line: what
      they did + their stated *future work*. That list becomes your Related Work.
- [ ] Write the **1-page problem statement + gap table** (use the research plan's
      literature table as the seed). Get your advisor to sign off on the gap.
- [ ] Freeze RQs and the 6 MITRE tactic classes.
- **Deliverable:** problem statement + related-work matrix (Zotero + a table).

### Phase 1 — RQ1 lab benchmark (Weeks 2–3)
- [ ] Run `python -m ml.benchmark_models --models phi3 qwen2.5:3b tinyllama`.
- [ ] Score fidelity (exact/near-match on ground-truth commands), char-break rate,
      latency median/IQR per model. → **Table 1** of the paper.
- [ ] Pick your production model (likely phi3 or qwen2.5:3b) on the fidelity/latency
      trade-off. Tune the system prompt to minimise character breaks.
- **Deliverable:** RQ1 results table + chosen model. *This alone is a
  publishable mini-result and d-risks everything downstream.*

### Phase 2 — Harden & deploy pilot (Weeks 4–5)
- [ ] Stand up **Oracle Always Free** VPS. Follow `docs/DEPLOYMENT.md` exactly:
      real sshd → 62222 key-only, GenShells on :22, `IPAddressDeny=any` egress
      kill-switch, WireGuard tunnel to Ollama on your Mac (or run Ollama on the
      VPS's 24 GB and skip the tunnel — simpler, still free).
- [ ] Run the **pre-flight checklist**. Confirm the honeypot cannot reach 8.8.8.8.
- [ ] **7-day pilot, arm B only.** Watch logs daily. Sanity-check that exec
      sessions dominate (validates the design choice).
- **Deliverable:** live, safe deployment + first real data + labeling guide v1.

### Phase 3 — Labeling + RQ2 classifier (Weeks 6–7)
- [ ] Draw a stratified sample; you + one friend/labmate label per `LABELING_GUIDE.md`.
      Compute **Cohen's kappa** (target ≥ 0.7). Adjudicate disagreements → gold set.
- [ ] Retrain: `python -m ml.train --data logs/sessions.jsonl`. Report
      **early vs full** macro-F1 and the **behaviour-only ablation** (RQ2 + leakage).
- [ ] Add SHAP summary for interpretability (the "why").
- **Deliverable:** RQ2 results + κ + SHAP figure.

### Phase 4 — Main 3-arm field experiment (Weeks 8–11)
- [ ] **Freeze `docs/PREREGISTRATION.md`**, commit it, record the hash. Do NOT edit
      hypotheses after this.
- [ ] Switch `arm_mode: auto`. Run **28 days** continuous. Monitor only for safety.
- [ ] Daily: back up `logs/sessions.jsonl`, check disk, check the tunnel/fallback.
- **Deliverable:** the full raw dataset (hashed IPs).

### Phase 5 — Analysis (Weeks 12–14)
- [ ] `python -m analysis.experiment_stats` → RQ3: commands/session, follow-up
      rate, 2nd-stage URL rate, 7-day return, per-arm latency. Effect sizes + CIs,
      Bonferroni-corrected pairwise arm tests.
- [ ] Build the paper's figures (matplotlib): arm comparison bars w/ CIs, latency
      distributions, RQ2 early-vs-full, SHAP, an architecture diagram.
- [ ] **Even a negative result is publishable** — if C ≯ B, write "intent
      conditioning does not change bot behaviour" honestly.
- **Deliverable:** all results + figures locked.

### Phase 6 — Write & submit (Weeks 15–20)
- [ ] Draft in **IEEE conference LaTeX template** on Overleaf (free). Section
      plan below. Advisor as co-author/reviewer of drafts.
- [ ] Internal review pass (I can review each section). Grammar/clarity pass.
- [ ] Pick venue (below), format to its page limit, prepare the artifact repo.
- [ ] **Submit + post arXiv preprint the same day.** Release code + scrubbed dataset.
- **Deliverable:** submitted paper + arXiv + public repo.

---

## 4. Paper structure (IEEE, ~6–8 pages)

1. **Abstract** — problem, the predict→adapt→measure loop on consumer HW, headline numbers.
2. **Introduction** — static honeypots get fingerprinted; LLMs help but don't adapt; contributions (C1–C4).
3. **Related Work** — from your Zotero matrix; the gap table.
4. **Threat Model & Design** — architecture, exec handling, deterministic+LLM hybrid, per-session state.
5. **Intent Classification** — MITRE tactics, features, leakage control, early vs full.
6. **Adaptive Deception** — the 3 arms, how C conditions on predicted intent.
7. **Experimental Setup** — deployment, pre-registration, metrics, ethics.
8. **Results** — RQ1 (Table 1), RQ2, RQ3 with stats.
9. **Discussion & Limitations** — what adaptation did/didn't do; latency; single-vantage.
10. **Ethics statement** — from `docs/ETHICS.md`.
11. **Conclusion & Future Work.**

## 5. Candidate IEEE venues (confirm deadlines when you get there)
- IEEE **CSR** (Cyber Security and Resilience) — applied, workshop-friendly.
- IEEE **DSC** (Dependable and Secure Computing).
- IEEE **TrustCom**, IEEE **CNS**, IEEE **ISI**, IEEE **COMPSAC** (student track).
- IEEE **Access** (journal, fast, open-access **but APC** — only if funded).
- Always pair with a **free arXiv preprint**.

## 6. Risks & mitigations
| Risk | Mitigation (already in the design) |
|---|---|
| Low attacker volume | Port 22 on a fresh cloud IP fills fast; 28 days is plenty; report exec-heavy reality either way |
| LLM too slow on M2 | Deterministic-first handles most commands; benchmark picks the fast model; cache frequent outputs |
| Reviewer: "labels are circular" | Leakage-controlled features + behaviour-only ablation + κ-validated gold set |
| Reviewer: "not novel" | Closed loop + consumer HW + field experiment; the gap table shows no prior work does all three |
| Reviewer: "ethics?" | Pre-registration + ETHICS.md + IRB determination + no-execution guarantee |
| Registration cost | arXiv now; apply for student grants; pick a lower-fee venue |
| Mac exposed by mistake | Internet node is the VPS only; egress kill-switch; never bind 22 on the Mac |

## 7. What I (Claude) will do at each phase
- Phase 0: turn your Zotero notes into the related-work matrix + gap table.
- Phase 1–5: help interpret results, generate every figure, catch stats mistakes.
- Phase 6: draft each paper section, do adversarial internal review, format to the
  venue template, and prep the artifact release.

## 8. Your move this week (the only 5 things that matter now)
1. `ollama pull phi3 qwen2.5:3b tinyllama` and run the honeypot locally once.
2. Create the Oracle Always Free account (so the VPS is ready for Phase 2).
3. Build the Zotero "GenShells-core" collection (20 papers, one-line notes each).
4. Confirm with your advisor: (a) is this the thesis, (b) what funding exists for
   IEEE registration, (c) does the university need an IRB determination.
5. Tell me your advisor's answer + your chosen production model after the RQ1 run,
   and I'll produce the related-work matrix and start the paper skeleton.
```
