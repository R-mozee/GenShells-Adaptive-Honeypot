#!/usr/bin/env python3
"""GenShells — LLM-driven adaptive SSH honeypot (from scratch, paramiko).

Handles BOTH:
  * exec requests  -> `ssh host "cmd"`  (Ghost Without Shell, 2026: ~99% of real
                      post-login SSH activity is a single non-interactive command)
  * interactive shells -> full pty session with per-command logging

Safety invariants:
  * Never binds 22 locally; default port 2222.
  * Never executes or downloads anything an attacker sends. wget/curl are faked.
  * Records only. Outbound network from this process should be firewalled to the
    Ollama tunnel (see docs/DEPLOYMENT.md).
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time

import paramiko
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.arms import resolve_arm
from src.logging_util import SessionLogger, CommandRecord
from src.deception import DeceptionEngine, LLMClient, SessionState
from ml.online_intent import EarlyIntentPredictor

CFG = {}


def load_config(path="config.yaml"):
    global CFG
    with open(path) as fh:
        CFG = yaml.safe_load(fh)
    return CFG


def ensure_host_key(path: str) -> paramiko.RSAKey:
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key


class GenShellsServer(paramiko.ServerInterface):
    """Accepts any auth (maximise engagement), captures channel type + command."""

    def __init__(self):
        self.event = threading.Event()
        self.username = ""
        self.password = ""
        self.auth_method = ""
        self.exec_command = None
        self.channel_type = "shell"
        self.want_pty = False

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username, self.password, self.auth_method = username, password, "password"
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.username = username
        self.password = key.get_base64()[:32]  # store a prefix as a fingerprint
        self.auth_method = "publickey"
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        self.want_pty = True
        return True

    def check_channel_shell_request(self, channel):
        self.channel_type = "shell"
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        # THE critical addition: single-shot non-interactive commands.
        self.channel_type = "exec"
        self.exec_command = command.decode("utf-8", "replace") if isinstance(command, bytes) else command
        self.event.set()
        return True


def _make_engine_and_state(ip):
    arm = resolve_arm(ip, CFG["salt"], CFG.get("arm_mode", "auto"))
    llm = LLMClient(CFG["llm"]) if CFG["llm"].get("enabled") else None
    engine = DeceptionEngine(arm, llm)
    state = SessionState(hostname=CFG.get("hostname", "srv-prod-01"),
                         emulated_os=CFG.get("emulated_os", "Ubuntu 24.04 LTS"),
                         username="root")
    return arm, engine, state

def _crlf(text):
    return text.replace("\r\n", "\n").replace("\n", "\r\n")


def handle_exec(chan, server, ip, src_port, logger):
    arm, engine, state = _make_engine_and_state(ip)
    predictor = EarlyIntentPredictor()
    rec = logger.new_session(ip, src_port, arm, "exec",
                             getattr(chan.get_transport(), "remote_version", ""),
                             server.username, server.password, server.auth_method)
    rec.exec_command = server.exec_command
    t_start = time.time()

    # An exec payload may be a compound command ( a; b && c ). Split for logging,
    # answer the whole thing coherently.
    cmd = server.exec_command or ""
    predicted = predictor.update(cmd)
    result = engine.respond(cmd, state, predicted_intent=predicted)

    rec.commands.append(vars(CommandRecord(
        seq=0, raw=cmd, normalized=cmd.strip(), t_offset_ms=0, delta_ms=0,
        backspaces=0, response_source=result["source"],
        response_latency_ms=result["latency_ms"], char_break=result["char_break"],
        response_preview=result["text"][:200])))
    try:
        if result["text"] and result["text"] != "__EXIT__":
            chan.sendall((result["text"] + "\n").encode("utf-8", "replace"))
        chan.send_exit_status(0)
    except Exception:
        pass
    logger.close(rec)


def handle_shell(chan, server, ip, src_port, logger):
    arm, engine, state = _make_engine_and_state(ip)
    predictor = EarlyIntentPredictor()
    rec = logger.new_session(ip, src_port, arm, "shell",
                             getattr(chan.get_transport(), "remote_version", ""),
                             server.username, server.password, server.auth_method)
    t_start = time.time()
    chan.settimeout(CFG["session"].get("idle_timeout_sec", 120))

    banner = f"Welcome to {CFG.get('emulated_os')} (GNU/Linux 6.8.0-45-generic x86_64)\r\n\r\n"
    try:
        chan.sendall(banner.encode())
        chan.sendall(state.prompt.encode())
    except Exception:
        logger.close(rec)
        return

    buf = ""
    backspaces = 0
    seq = 0
    last_cmd_time = t_start
    max_cmds = CFG["session"].get("max_commands", 200)

    while True:
        try:
            data = chan.recv(1024)
        except socket.timeout:
            break
        except Exception:
            break
        if not data:
            break
        text = data.decode("utf-8", "replace")
        for ch in text:
            if ch in ("\r", "\n"):
                try:
                    chan.sendall(b"\r\n")
                except Exception:
                    break
                cmd = buf.strip()
                buf = ""
                if cmd == "":
                    chan.sendall(state.prompt.encode())
                    backspaces = 0
                    continue
                now = time.time()
                predicted = predictor.update(cmd)
                result = engine.respond(cmd, state, predicted_intent=predicted)
                rec.commands.append(vars(CommandRecord(
                    seq=seq, raw=cmd, normalized=cmd,
                    t_offset_ms=int((now - t_start) * 1000),
                    delta_ms=int((now - last_cmd_time) * 1000),
                    backspaces=backspaces, response_source=result["source"],
                    response_latency_ms=result["latency_ms"],
                    char_break=result["char_break"],
                    response_preview=result["text"][:200])))
                seq += 1
                last_cmd_time = now
                backspaces = 0
                if result["text"] == "__EXIT__":
                    try:
                        chan.sendall(b"logout\r\n")
                    except Exception:
                        pass
                    logger.close(rec)
                    chan.close()
                    return
                out = result["text"]
                if out:
                    try:
                        chan.sendall((_crlf(out) + "\r\n").encode("utf-8", "replace"))
                    except Exception:
                        break
                if seq >= max_cmds:
                    break
                try:
                    chan.sendall(state.prompt.encode())
                except Exception:
                    break
            elif ch in ("\x7f", "\b"):     # backspace: behavioural signal
                if buf:
                    buf = buf[:-1]
                    backspaces += 1
                    try:
                        chan.sendall(b"\b \b")
                    except Exception:
                        break
            elif ch == "\x03":             # Ctrl-C
                buf = ""
                try:
                    chan.sendall(b"^C\r\n" + state.prompt.encode())
                except Exception:
                    break
            else:
                buf += ch
                try:
                    chan.sendall(ch.encode())  # echo
                except Exception:
                    break

    logger.close(rec)
    try:
        chan.close()
    except Exception:
        pass


def handle_connection(client, addr, host_key, logger):
    ip, src_port = addr[0], addr[1]
    transport = paramiko.Transport(client)
    transport.local_version = CFG.get("server_banner", "SSH-2.0-OpenSSH_9.6p1")
    transport.add_server_key(host_key)
    server = GenShellsServer()
    try:
        transport.start_server(server=server)
    except Exception:
        transport.close()
        return
    chan = transport.accept(20)
    if chan is None:
        transport.close()
        return
    # wait for shell or exec request
    server.event.wait(10)
    try:
        if server.channel_type == "exec":
            handle_exec(chan, server, ip, src_port, logger)
        else:
            handle_shell(chan, server, ip, src_port, logger)
    finally:
        try:
            transport.close()
        except Exception:
            pass


def main():
    cfg = load_config(os.environ.get("GENSHELLS_CONFIG", "config.yaml"))
    host_key = ensure_host_key(cfg["host_key_path"])
    logger = SessionLogger(cfg["logging"]["path"], cfg["salt"],
                           cfg["logging"].get("hash_ips", True))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((cfg["listen"]["host"], cfg["listen"]["port"]))
    sock.listen(100)
    print(f"[GenShells] listening on {cfg['listen']['host']}:{cfg['listen']['port']} "
          f"(arm_mode={cfg.get('arm_mode')})")

    while True:
        try:
            client, addr = sock.accept()
        except KeyboardInterrupt:
            print("\n[GenShells] shutting down")
            break
        except Exception:
            continue
        t = threading.Thread(target=handle_connection,
                             args=(client, addr, host_key, logger), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
