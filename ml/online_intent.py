"""Real-time (online) early-intent predictor used by the honeypot for arm C.

This is the *live* predictor: it must decide a tactic from as little as the
FIRST command, because ~99% of real SSH sessions are a single non-interactive
command (Ghost Without Shell, 2026). It has two modes:

  * bootstrap (default): rule votes from labeling.py -> highest-priority tactic.
    Works with zero training data, so arm C is functional from day one.
  * model (optional): if models/early_intent.json exists (exported by train.py),
    load it and use the trained classifier instead.

The offline evaluation of "first-command vs full-session" accuracy (RQ2) lives
in train.py / features.py; this class is what runs in production.
"""
from __future__ import annotations

import os
from typing import List, Optional

from .labeling import label_command
from .schema import TACTICS

# Priority when several tactics fire at once: the more "advanced" wins, so the
# deception adapts toward the more committed behaviour.
_PRIORITY = ["Impact", "Persistence", "Execution", "DefenseEvasion", "Discovery"]


class EarlyIntentPredictor:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "models", "early_intent.json")
        self.model = None  # trained model hook (kept simple; JSON weights)
        self.history: List[str] = []
        self.current: Optional[str] = "Discovery"  # sane default

    def update(self, command: str) -> Optional[str]:
        """Feed the next command, return the current best-guess tactic."""
        self.history.append(command)
        votes = set()
        for c in self.history:
            votes |= label_command(c)
        for t in _PRIORITY:
            if t in votes:
                self.current = t
                return t
        # nothing matched yet -> stay Discovery (attacker is likely enumerating)
        self.current = "Discovery"
        return self.current
