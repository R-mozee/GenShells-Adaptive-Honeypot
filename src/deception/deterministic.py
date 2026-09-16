"""Deterministic response layer.

Rationale (from Magazov et al. 2026): the large majority of attacker commands
are handled identically regardless of model, so answering them with fixed,
correct output (a) removes model-attributable risk, (b) is instant (no LLM
latency fingerprint), and (c) keeps state coherent. Only the "long tail" of
unusual commands is escalated to the LLM.

Returns (handled: bool, output: str). handled=False means "let the LLM try".
"""
from __future__ import annotations

import re
import shlex
from typing import Tuple

from .session_state import SessionState


def _fake_uname(state: SessionState, args: str) -> str:
    full = "Linux srv-prod-01 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC x86_64 x86_64 x86_64 GNU/Linux"
    if "-a" in args:
        return full
    if "-r" in args:
        return "6.8.0-45-generic"
    if "-s" in args or not args.strip():
        return "Linux"
    return full


def _fake_ls(state: SessionState, args: str) -> str:
    long_fmt = "-l" in args
    show_all = "-a" in args
    entries = list(state.fs.get(state.cwd, []))
    if show_all:
        entries = [".", ".."] + entries
    entries = [e for e in entries if show_all or not e.startswith(".")]
    if not entries:
        return ""
    if long_fmt:
        lines = ["total %d" % (len(entries) * 4)]
        for e in entries:
            is_dir = state.cwd + "/" + e in state.fs or e in ("bin", "etc", "var", "usr", ".ssh")
            perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
            lines.append(f"{perm} 1 root root 4096 Sep 10 14:22 {e}")
        return "\n".join(lines)
    return "  ".join(entries)


ETC_OS_RELEASE = (
    'PRETTY_NAME="Ubuntu 24.04.1 LTS"\n'
    'NAME="Ubuntu"\nVERSION_ID="24.04"\nVERSION="24.04.1 LTS (Noble Numbat)"\n'
    'VERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\n'
    'HOME_URL="https://www.ubuntu.com/"\nUBUNTU_CODENAME=noble'
)

ETC_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n"
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"
)


def handle(cmd: str, state: SessionState) -> Tuple[bool, str]:
    """Try to answer `cmd` deterministically. Also mutates state for cd/touch."""
    cmd = cmd.strip()
    if not cmd:
        return True, ""
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = cmd.split()
    if not parts:
        return True, ""
    prog = parts[0]
    args = cmd[len(prog):].strip()

    if prog in ("exit", "logout"):
        return True, "__EXIT__"
    if prog == "whoami":
        return True, state.username
    if prog == "id":
        if state.username == "root":
            return True, "uid=0(root) gid=0(root) groups=0(root)"
        return True, "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),27(sudo)"
    if prog == "pwd":
        return True, state.cwd
    if prog == "hostname":
        return True, state.hostname
    if prog == "uname":
        return True, _fake_uname(state, args)
    if prog == "uptime":
        return True, " 14:22:41 up 37 days,  3:11,  1 user,  load average: 0.08, 0.03, 0.01"
    if prog == "cd":
        state.chdir(args.strip())
        return True, ""
    if prog == "ls" or prog == "dir":
        return True, _fake_ls(state, args)
    if prog == "echo":
        # Handle redirection: `echo KEY >> /root/.ssh/authorized_keys` is a
        # persistence action -> record it, emit nothing (like a real shell).
        redir = re.search(r"\s>>?\s*(\S+)", args)
        val = re.split(r"\s>>?\s*\S+", args)[0]
        for k, v in state.env.items():
            val = val.replace(f"${k}", v).replace(f"${{{k}}}", v)
        val = val.strip().strip('"').strip("'")
        if redir:
            target = redir.group(1)
            if "authorized_keys" in target:
                state.planted_keys.append(val)
            return True, ""   # redirection consumes stdout
        return True, val
    if prog in ("chmod", "chown", "chgrp", "touch", "mkdir", "export", "unset",
                "kill", "pkill", "killall", "sync", "ln", "mv", "cp"):
        # benign/among-attacker commands that normally print nothing on success
        if prog == "mkdir":
            new = args.split()[-1] if args.split() else ""
            if new and not new.startswith("-"):
                state.fs.setdefault(state.cwd, [])
        if prog == "touch":
            new = args.split()[-1] if args.split() else ""
            if new and not new.startswith("-"):
                state.fs.setdefault(state.cwd, []).append(new)
        return True, ""
    if prog == "rm":
        # NEVER act. Destructive intent is logged upstream; emulate silence,
        # except an obviously catastrophic target which real systems refuse fast.
        if re.search(r"-rf?\s+/(\s|$)", cmd):
            return True, "rm: it is dangerous to operate recursively on '/'"
        return True, ""
    if prog == "history":
        if "-c" in args:
            return True, ""     # defense evasion: silent, but logged upstream
        return True, ""
    if prog == "cat":
        if "/etc/os-release" in cmd:
            return True, ETC_OS_RELEASE
        if "/etc/passwd" in cmd:
            return True, ETC_PASSWD
        if "/etc/shadow" in cmd:
            return True, "cat: /etc/shadow: Permission denied" if state.username != "root" else \
                "root:$6$xy%s:19800:0:99999:7:::" % ("z" * 20)
        # unknown file -> let the LLM hallucinate plausible contents
        return False, ""
    if prog in ("wget", "curl"):
        # SAFETY: we never fetch anything. Emulate a plausible transfer, log upstream.
        url = ""
        m = re.search(r"https?://[^\s'\"]+", cmd)
        if m:
            url = m.group(0)
        if prog == "wget":
            fname = url.rstrip("/").split("/")[-1] or "index.html"
            return True, (f"--2025-09-10 14:22:41--  {url}\n"
                          f"Resolving host... 93.184.216.34\nConnecting... connected.\n"
                          f"HTTP request sent, awaiting response... 200 OK\n"
                          f"Length: 512000 (500K) [application/octet-stream]\n"
                          f"Saving to: '{fname}'\n\n{fname}  100%[===================>] 500K  1.2MB/s in 0.4s\n\n"
                          f"2025-09-10 14:22:42 (1.2 MB/s) - '{fname}' saved [512000/512000]")
        return True, ""  # curl silent success
    if prog in ("ps",):
        return True, ("  PID TTY          TIME CMD\n 2891 pts/0    00:00:00 bash\n"
                      " 2902 pts/0    00:00:00 ps")
    if prog == "free":
        return True, ("               total        used        free      shared  buff/cache   available\n"
                      "Mem:         8123456     1203456     5233456       23456     1686544     6598765\n"
                      "Swap:        2097148           0     2097148")
    if prog == "df":
        return True, ("Filesystem     1K-blocks    Used Available Use% Mounted on\n"
                      "/dev/vda1       41251136 8123456  31021840  21% /")
    if cmd.startswith("crontab -l"):
        return True, "no crontab for %s" % state.username
    # not handled deterministically
    return False, ""
