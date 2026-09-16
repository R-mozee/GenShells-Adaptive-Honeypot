# Labeling Guide — Attacker Intent (MITRE ATT&CK tactics)

Used to (a) validate the weak labels from `ml/labeling.py` and (b) produce the
gold test set. Two annotators label the same stratified sample independently;
report Cohen's kappa. Aim for kappa ≥ 0.7 before trusting the weak labels.

## Unit
Label a **session** (all commands from one connection). Multi-label allowed.

## Tactics (assign every tactic that clearly applies)
| Tactic | Assign when the session… | Example commands |
|---|---|---|
| **Discovery** | enumerates host, users, network, files | `uname -a`, `whoami`, `cat /etc/passwd`, `ps aux`, `ip a` |
| **Execution** | tries to run or fetch-and-run code | `wget …|sh`, `chmod +x x`, `./x`, `python -c`, `curl …` |
| **Persistence** | tries to survive reboot / re-entry | `>> authorized_keys`, `crontab`, `useradd`, `systemctl enable` |
| **DefenseEvasion** | hides tracks / disables logging | `history -c`, `unset HISTFILE`, `rm /var/log/*`, `chattr` |
| **Impact** | destroys / denies service | `rm -rf /`, `mkfs`, fork bomb, `shutdown` |
| **Harmless** | benign, admin, empty, or only login | `ls`, `exit`, blank |

## Rules to keep labeling consistent
1. **Intent, not success.** A failed `wget` is still Execution intent.
2. **Login alone = Harmless.** Auth with no command is Harmless.
3. **Recon before payload:** label BOTH Discovery and Execution if both occur.
4. **Ambiguous single tokens:** `ls` alone → Harmless; `ls` inside an enumeration
   burst → Discovery. Judge the burst, not the isolated command.
5. **Copy-paste bot bursts** (identical sub-second command block) → label by
   content; note "automated" in the annotator comment (feeds the bot/human
   subgroup analysis).
6. When two annotators disagree, a third adjudicates; record the final label.

## Procedure
1. Draw a stratified sample (≥ 300 sessions, over-sampling rare tactics).
2. Each annotator labels blind in a shared sheet (one column per tactic, 0/1).
3. Compute per-tactic and overall Cohen's kappa.
4. If kappa < 0.7, refine this guide's rules and re-label a fresh sample.
5. Freeze the guide; the adjudicated set becomes the gold test split.
