"""Structured, append-only JSONL logging for GenShells.

Every attacker interaction is a JSON line. We log the granular behavioural
signals the ML stage needs (raw syntax, timing deltas, backspaces) and, when
configured, we store an HMAC of the source IP rather than the raw IP so the
shipped dataset carries no directly identifying data.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

_LOCK = threading.Lock()


def hash_ip(ip: str, salt: str) -> str:
    """Keyed hash of an IP. Same IP -> same token (for return-rate analysis),
    but the raw IP cannot be recovered from the token."""
    return hmac.new(salt.encode(), ip.encode(), hashlib.sha256).hexdigest()[:16]


@dataclass
class CommandRecord:
    seq: int
    raw: str                     # exact bytes the attacker sent (as text)
    normalized: str              # trimmed / decoded
    t_offset_ms: int             # ms since session start when command completed
    delta_ms: int                # ms since previous command
    backspaces: int              # editing signal (interactive only)
    response_source: str         # "deterministic" | "llm" | "fallback" | "static"
    response_latency_ms: int     # how long WE took to answer (fingerprint metric)
    char_break: bool             # LLM broke character and was filtered
    response_preview: str        # first 200 chars of what we returned


@dataclass
class SessionRecord:
    session_id: str
    ip_token: str
    src_port: int
    arm: str                     # A / B / C
    channel_type: str            # "exec" | "shell"
    client_banner: str
    username: str
    password_tried: str
    auth_method: str
    ts_start: float
    ts_end: Optional[float] = None
    duration_ms: Optional[int] = None
    exec_command: Optional[str] = None   # for non-interactive exec sessions
    n_commands: int = 0
    commands: list = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


class SessionLogger:
    def __init__(self, path: str, salt: str, hash_ips: bool = True):
        self.path = path
        self.salt = salt
        self.hash_ips = hash_ips
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def new_session(self, ip, src_port, arm, channel_type,
                    client_banner, username, password, auth_method) -> SessionRecord:
        token = hash_ip(ip, self.salt) if self.hash_ips else ip
        return SessionRecord(
            session_id=uuid.uuid4().hex[:12],
            ip_token=token,
            src_port=src_port,
            arm=arm,
            channel_type=channel_type,
            client_banner=client_banner,
            username=username,
            password_tried=password,
            auth_method=auth_method,
            ts_start=time.time(),
        )

    def close(self, rec: SessionRecord) -> None:
        rec.ts_end = time.time()
        rec.duration_ms = int((rec.ts_end - rec.ts_start) * 1000)
        rec.n_commands = len(rec.commands)
        with _LOCK:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(rec.to_json() + "\n")
