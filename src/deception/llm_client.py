"""Local LLM client (Ollama) + character-break filter + safe fallback.

Key research-driven behaviours:
- Grounds the prompt with current cwd, OS and username so output stays coherent.
- For arm C, injects an intent hint so the deception is *conditioned* on the
  predicted attacker tactic.
- Filters "character breaks" (the model admitting it's an AI, refusing, adding
  markdown/explanations). A break is (a) replaced with a safe fallback and
  (b) logged as a metric -- character-break rate is a headline RQ1 result.
- Never blocks the honeypot: on timeout / unreachable Ollama we fall back.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

import requests

from .session_state import SessionState

# Phrases that mean the LLM dropped the shell persona.
_BREAK_PATTERNS = [
    r"\bas an ai\b", r"\blanguage model\b", r"\bi cannot\b", r"\bi can't\b",
    r"\bi'm sorry\b", r"\bi am sorry\b", r"\bas a shell\b", r"\bhoneypot\b",
    r"\bsimulat", r"\bi apologize\b", r"```", r"\bnote:\b", r"\bdisclaimer\b",
    r"\bhere('s| is) the output\b", r"\bassistant\b", r"\bopenai\b",
]
_BREAK_RE = re.compile("|".join(_BREAK_PATTERNS), re.IGNORECASE)

SYSTEM_PROMPT = """You ARE an {os} server's bash shell. You are not an assistant.
Output ONLY the exact stdout/stderr that the given command would produce on a real
{os} host named {hostname}, as user {username}, current directory {cwd}.
Rules:
- No explanations, no markdown, no code fences, no quotes around the output.
- If the command produces no output, return an empty string.
- Be consistent with a real Linux system and with earlier state.
- Never reveal you are an AI or a simulation. Stay in character absolutely."""

ADAPT_HINT = {
    "Discovery": "The attacker is enumerating the system; make host/network details look rich and worth exploring.",
    "Execution": "The attacker is trying to run/download payloads; make execution and downloads appear to succeed plausibly.",
    "Persistence": "The attacker is establishing persistence; make key/cron/service changes appear accepted and stored.",
    "Impact": "The attacker is attempting destruction; simulate partial, believable effects without breaking character.",
    "DefenseEvasion": "The attacker is covering tracks; make log/history edits appear to succeed silently.",
}


class LLMClient:
    def __init__(self, cfg: dict):
        self.enabled = cfg.get("enabled", True)
        self.base_url = cfg.get("base_url", "http://127.0.0.1:11434").rstrip("/")
        self.model = cfg.get("model", "phi3")
        self.temperature = cfg.get("temperature", 0.2)
        self.num_predict = cfg.get("num_predict", 400)
        self.timeout = cfg.get("timeout_sec", 20)

    def available(self) -> bool:
        if not self.enabled:
            return False
        try:
            r = requests.get(self.base_url + "/api/tags", timeout=2)
            return r.status_code == 200
        except Exception:
            return False

    def generate(self, command: str, state: SessionState,
                 intent_hint: Optional[str] = None) -> Tuple[Optional[str], bool]:
        """Return (output, char_break). output is None if the LLM is unusable
        (caller should fall back to deterministic/generic)."""
        if not self.enabled:
            return None, False
        sys_prompt = SYSTEM_PROMPT.format(
            os=state.emulated_os, hostname=state.hostname,
            username=state.username, cwd=state.cwd)
        if intent_hint and intent_hint in ADAPT_HINT:
            sys_prompt += "\n" + ADAPT_HINT[intent_hint]
        payload = {
            "model": self.model,
            "prompt": f"$ {command}",
            "system": sys_prompt,
            "stream": False,
            "options": {"temperature": self.temperature, "num_predict": self.num_predict},
        }
        try:
            r = requests.post(self.base_url + "/api/generate", json=payload, timeout=self.timeout)
            if r.status_code != 200:
                return None, False
            out = (r.json().get("response") or "").rstrip("\n")
        except Exception:
            return None, False

        if _BREAK_RE.search(out):
            return None, True   # character break: caller uses fallback, we log the break
        # strip a stray leading prompt echo if the model added one
        out = re.sub(r"^\$?\s*" + re.escape(command) + r"\s*\n", "", out)
        return out, False
