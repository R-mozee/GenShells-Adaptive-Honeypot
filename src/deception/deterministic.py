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
    if prog == "top":
        return True, "\n".join([
            "top - 14:22:41 up 37 days,  3:11,  1 user,  load average: 0.08, 0.03, 0.01",
            "Tasks: 112 total,   1 running, 111 sleeping,   0 stopped,   0 zombie",
            "%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.4 id,  0.1 wa,  0.0 hi,  0.0 si,  0.0 st",
            "MiB Mem :   7943.2 total,   1204.5 free,   2310.8 used,   4427.9 buff/cache",
            "MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   5321.4 avail Mem",
            "",
            "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND",
            "      1 root      20   0  167936  13212   8348 S   0.0   0.2   0:11.52 systemd",
            "      2 root      20   0       0      0      0 S   0.0   0.0   0:00.08 kthreadd",
            "    612 root      20   0   15424   9020   7612 S   0.0   0.1   0:02.31 sshd",
            "    734 root      20   0   55284   5124   4388 S   0.0   0.1   0:00.74 nginx",
            "    735 www-data  20   0   55960   5316   3712 S   0.0   0.1   0:01.12 nginx",
            "    801 root      20   0   29492  11248   6424 S   0.0   0.1   0:00.55 cron",
            "    844 syslog    20   0  222404   5900   4340 S   0.0   0.1   0:03.07 rsyslogd",
        ])
    if prog == "free":
        if "-h" in args:
            return True, "\n".join([
                "               total        used        free      shared  buff/cache   available",
                "Mem:           7.8Gi       2.3Gi       1.2Gi       1.1Mi       4.3Gi       5.2Gi",
                "Swap:          2.0Gi          0B       2.0Gi",
            ])
        return True, "\n".join([
            "               total        used        free      shared  buff/cache   available",
            "Mem:         8133837     2366259     1233408        1126     4534170     5449114",
            "Swap:        2097148           0     2097148",
        ])
    if prog == "df":
        return True, "\n".join([
            "Filesystem      Size  Used Avail Use% Mounted on",
            "tmpfs           795M  1.2M  794M   1% /run",
            "/dev/sda1        29G  6.8G   22G  24% /",
            "tmpfs           3.9G     0  3.9G   0% /dev/shm",
            "tmpfs           5.0M     0  5.0M   0% /run/lock",
            "/dev/sda15      105M  6.1M   99M   6% /boot/efi",
            "tmpfs           795M   12K  795M   1% /run/user/0",
        ])
    if prog == "nginx" and args.strip() == "-v":
        return True, "nginx version: nginx/1.24.0 (Ubuntu)"
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
