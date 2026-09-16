"""Label schema: MITRE ATT&CK tactics used as attacker-intent classes.

We deliberately use ATT&CK tactics (not ad-hoc labels) so results are
comparable with LogPrecis (Boffa et al., 2024) and the SSH-Shell-Attacks
dataset, and so reviewers recognise the taxonomy. A session is MULTI-LABEL:
one session can be Discovery + Execution + Persistence.
"""
from __future__ import annotations

# Canonical tactic set for SSH post-login behaviour (subset of ATT&CK that
# actually occurs on shell honeypots). "Harmless" covers benign/admin noise.
TACTICS = [
    "Discovery",        # whoami, uname, ls, cat /etc/*, ps, ip a
    "Execution",        # wget/curl + run, chmod +x, ./x, sh -c, python -c
    "Persistence",      # authorized_keys, crontab, systemd, new user
    "DefenseEvasion",   # history -c, rm logs, unset HISTFILE, chattr
    "Impact",           # rm -rf /, mkfs, kill, fork bombs, wiping
    "Harmless",         # benign / admin / empty
]

TACTIC_INDEX = {t: i for i, t in enumerate(TACTICS)}

# Map the README's original 4 classes onto tactics, for continuity.
LEGACY_MAP = {
    "Automated Reconnaissance": "Discovery",
    "Malware Dropping": "Execution",
    "Privilege Escalation": "Discovery",   # rare on root shells; folds in
    "Destructive": "Impact",
}
