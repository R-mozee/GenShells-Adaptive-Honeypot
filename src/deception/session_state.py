"""Per-session fake environment.

Human evaluators in prior work (AdvancedShelLM) caught LLM honeypots because
state was inconsistent: `cd` then `pwd` disagreed, files written with `touch`
vanished on `ls`. We keep a lightweight, per-session mutable state so the
deterministic layer stays coherent and the LLM prompt can be grounded with the
current directory, environment and a small virtual filesystem.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


DEFAULT_FS = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "opt", "root",
          "run", "sbin", "srv", "tmp", "usr", "var"],
    "/root": [".bashrc", ".profile", ".ssh", ".cache"],
    "/root/.ssh": ["authorized_keys", "known_hosts"],
    "/home": ["ubuntu"],
    "/home/ubuntu": [".bashrc", ".profile", ".ssh"],
    "/etc": ["passwd", "shadow", "hostname", "hosts", "os-release",
             "crontab", "ssh", "resolv.conf"],
    "/var": ["log", "www", "tmp", "cache", "lib"],
    "/tmp": [],
}


@dataclass
class SessionState:
    hostname: str
    emulated_os: str
    username: str = "root"
    cwd: str = "/root"
    env: Dict[str, str] = field(default_factory=lambda: {
        "USER": "root", "HOME": "/root", "SHELL": "/bin/bash",
        "PWD": "/root", "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "en_US.UTF-8", "TERM": "xterm-256color",
    })
    # copy the default FS so mutations don't leak across sessions
    fs: Dict[str, List[str]] = field(default_factory=lambda: {k: list(v) for k, v in DEFAULT_FS.items()})
    # files an attacker planted (name -> fake contents), used for persistence realism
    planted_keys: List[str] = field(default_factory=list)

    @property
    def prompt(self) -> str:
        cwd = "~" if self.cwd == f"/home/{self.username}" or self.cwd == "/root" else self.cwd
        suffix = "#" if self.username == "root" else "$"
        return f"{self.username}@{self.hostname}:{cwd}{suffix} "

    def chdir(self, target: str) -> bool:
        if not target or target == "~":
            self.cwd = "/root" if self.username == "root" else f"/home/{self.username}"
        elif target.startswith("/"):
            self.cwd = target.rstrip("/") or "/"
        elif target == "..":
            self.cwd = "/".join(self.cwd.rstrip("/").split("/")[:-1]) or "/"
        else:
            base = self.cwd.rstrip("/")
            self.cwd = f"{base}/{target}"
        self.env["PWD"] = self.cwd
        return True
