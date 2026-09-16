"""Experiment arm assignment.

Three arms for the controlled field experiment (RQ3):
  A = static   : canned Cowrie-style responses, no LLM
  B = generative: LLM responses, no intent conditioning
  C = adaptive : LLM responses conditioned on predicted intent

Assignment is deterministic on a keyed hash of the source IP, so a returning
attacker always lands in the SAME arm. That keeps the arms independent and
makes 7-day return-rate a clean per-arm metric.
"""
from __future__ import annotations

import hashlib
import hmac

ARMS = ("A", "B", "C")


def assign_arm(ip: str, salt: str) -> str:
    digest = hmac.new(salt.encode(), ("arm:" + ip).encode(), hashlib.sha256).digest()
    return ARMS[digest[0] % len(ARMS)]


def resolve_arm(ip: str, salt: str, arm_mode: str) -> str:
    """arm_mode is 'auto' (hash the IP) or a forced single arm A/B/C
    (useful for a pilot run or lab benchmarking)."""
    arm_mode = (arm_mode or "auto").strip().upper()
    if arm_mode == "AUTO":
        return assign_arm(ip, salt)
    if arm_mode in ARMS:
        return arm_mode
    return assign_arm(ip, salt)
