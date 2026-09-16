"""Deception engine: routes a command to the right responder for the arm.

Arm A (static):     deterministic layer only; unknowns -> generic "command not found".
Arm B (generative): deterministic first, LLM for the long tail, no intent hint.
Arm C (adaptive):   like B, but the LLM (and generic responses) are conditioned
                    on the intent predicted so far this session.

Returns a dict the caller logs: text, source, latency_ms, char_break.
"""
from __future__ import annotations

import time
from typing import Optional

from . import deterministic
from .llm_client import LLMClient
from .session_state import SessionState

GENERIC_NOT_FOUND = "{prog}: command not found"


class DeceptionEngine:
    def __init__(self, arm: str, llm: Optional[LLMClient]):
        self.arm = arm
        self.llm = llm

    def respond(self, command: str, state: SessionState,
                predicted_intent: Optional[str] = None) -> dict:
        t0 = time.perf_counter()
        source = "deterministic"
        char_break = False

        handled, out = deterministic.handle(command, state)

        if not handled:
            if self.arm == "A":
                prog = command.strip().split()[0] if command.strip() else ""
                out = GENERIC_NOT_FOUND.format(prog=prog)
                source = "static"
            else:
                hint = predicted_intent if self.arm == "C" else None
                llm_out, char_break = (None, False)
                if self.llm is not None:
                    llm_out, char_break = self.llm.generate(command, state, intent_hint=hint)
                if llm_out is not None:
                    out, source = llm_out, "llm"
                else:
                    prog = command.strip().split()[0] if command.strip() else ""
                    out = GENERIC_NOT_FOUND.format(prog=prog)
                    source = "fallback"

        latency_ms = int((time.perf_counter() - t0) * 1000)
        return {"text": out, "source": source,
                "latency_ms": latency_ms, "char_break": char_break}
