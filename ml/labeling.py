"""Weak-supervision labeling functions (Snorkel-style, no dependency).

IMPORTANT METHODOLOGICAL NOTE (read before trusting any accuracy number):
These rules are LABEL sources for training. If you then train a classifier on
features that trivially contain the same tokens the rule fired on (e.g. label
Execution because 'wget' present, then feed 'contains_wget' as a feature), the
model just relearns the rule and the accuracy is meaningless.

So the pipeline separates them:
  * labeling.py  -> assigns weak tactic labels from keyword rules (this file).
  * A stratified human-labeled sample (see docs/LABELING_GUIDE.md) validates the
    weak labels; report Cohen's kappa between two annotators.
  * features.py  -> BEHAVIOURAL features (timing, entropy, sequence shape,
    n-gram embeddings) rather than the raw rule tokens, so the classifier has
    to generalise. Any lexical feature that duplicates a rule is reported
    separately as a "lexical baseline".

Each function returns a set of tactics it votes for (multi-label).
"""
from __future__ import annotations

import re
from typing import List, Set

from .schema import TACTICS

_RULES = [
    ("Discovery", re.compile(r"\b(whoami|id|uname|hostname|uptime|lscpu|lsb_release|"
                             r"cat\s+/etc/(os-release|passwd|issue)|ps\s|top\b|"
                             r"ip\s+a|ifconfig|netstat|ss\s|w\b|last\b|nproc|free\b|df\b)", re.I)),
    ("Execution", re.compile(r"\b(wget|curl|tftp|scp|fetch)\b|\bchmod\s+\+?x|\./|"
                             r"\bsh\s+-c|\bbash\s+-c|\bpython[23]?\s+-c|\bperl\s+-e|"
                             r"\bnohup\b|\bcrontab\b.*curl|\|\s*(sh|bash)\b", re.I)),
    ("Persistence", re.compile(r"authorized_keys|\.ssh/|\bcrontab\b|/etc/cron|"
                               r"systemctl\s+enable|/etc/rc\.local|useradd|adduser|"
                               r"echo.*>>.*\.ssh|update-rc\.d", re.I)),
    ("DefenseEvasion", re.compile(r"history\s+-c|unset\s+HISTFILE|HISTFILE=|"
                                  r"rm\s+-rf?\s+/var/log|>\s*/var/log|chattr|"
                                  r"shred\b|\btouch\s+-r|iptables\s+-F", re.I)),
    ("Impact", re.compile(r"rm\s+-rf?\s+/(\s|$|\*)|mkfs|dd\s+if=/dev/(zero|urandom)|"
                          r":\(\)\s*\{|shutdown|halt\b|reboot\b|kill\s+-9\s+1\b|"
                          r"\bwipefs\b", re.I)),
]


def label_command(cmd: str) -> Set[str]:
    votes = set()
    for tactic, rx in _RULES:
        if rx.search(cmd or ""):
            votes.add(tactic)
    return votes


def label_session(commands: List[str]) -> List[str]:
    """Return sorted multi-label tactic list for a whole session."""
    votes: Set[str] = set()
    for c in commands:
        votes |= label_command(c)
    if not votes:
        votes.add("Harmless")
    return sorted(votes, key=lambda t: TACTICS.index(t))
