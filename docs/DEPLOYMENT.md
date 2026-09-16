# Deployment & Safety Runbook

> Goal: expose GenShells to real internet attackers **without ever risking your
> Mac, and without ever executing attacker code**. Zero-budget path included.

## Golden rules
1. The Mac is **never** the internet-facing host. A cheap VPS faces the internet.
2. The honeypot process has **no outbound network** except the Ollama tunnel.
3. Nothing an attacker sends is ever executed, downloaded, or resolved.
4. Every dataset you release stores **hashed** IPs (see `logging.hash_ips`).

## Topology
```
   Attacker ──22──▶  VPS (cheap, disposable)              Your Mac M2 (home)
                     ├─ real sshd moved to port 62222     ┌─────────────┐
                     │  (key-only, firewalled to your IP) │  Ollama+phi3│
                     └─ GenShells on :22  ───WireGuard────▶│  :11434     │
                        (systemd service)   (private)      └─────────────┘
```
- If the Mac/tunnel is down, GenShells auto-falls back to arm-A responses
  (already implemented in `engine.py`), so the honeypot never hangs.

## Zero-budget options for the VPS
- **Oracle Cloud Always Free** (ARM Ampere, 24GB) — genuinely free, best pick.
  You could even run Ollama on the VPS itself and skip the tunnel.
- GCP / AWS / Azure free tier (12 months).
- A student credit (GitHub Student Pack → DigitalOcean/Azure credits).
Pick ONE. Oracle Always Free means the whole study can cost ₹0.

## VPS hardening (before opening port 22)
```bash
# 1. Move real SSH off 22, key-only, restrict to YOUR home IP
sudo sed -i 's/^#\?Port .*/Port 62222/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
# 2. Firewall: allow your IP to 62222; allow world to 22 (the trap); block the rest
sudo ufw default deny incoming
sudo ufw allow from <YOUR_HOME_IP> to any port 62222 proto tcp
sudo ufw allow 22/tcp
sudo ufw enable
# 3. Egress lockdown for the honeypot user (no outbound except the tunnel)
sudo useradd -r -s /usr/sbin/nologin genshells
# run GenShells as this user; add an egress deny rule for its uid except WG iface
```

## WireGuard tunnel (VPS ↔ Mac), so Ollama stays on the Mac
- Install WireGuard on both. VPS is the client, Mac is the peer.
- Point `config.yaml -> llm.base_url` at the Mac's WireGuard IP, e.g.
  `http://10.10.0.1:11434`. Bind Ollama to the WG interface only.

## systemd service (VPS)
```ini
# /etc/systemd/system/genshells.service
[Unit]
Description=GenShells honeypot
After=network-online.target
[Service]
User=genshells
WorkingDirectory=/opt/GenShells-Adaptive-Honeypot
ExecStart=/opt/GenShells-Adaptive-Honeypot/venv/bin/python -m src.honeypot
Restart=always
# hard egress kill-switch: only the WG subnet is reachable
IPAddressDeny=any
IPAddressAllow=10.10.0.0/24
[Install]
WantedBy=multi-user.target
```
> `IPAddressDeny=any` + a single `IPAddressAllow` is your safety net: even if a
> bug tried to fetch a payload, the kernel drops it.

## Binding port 22 as non-root
GenShells defaults to 2222. To face the internet on 22 without running as root:
```bash
sudo setcap 'cap_net_bind_service=+ep' $(readlink -f venv/bin/python)
# then set listen.port: 22 in config.yaml
```

## Pre-flight checklist (run before every deployment)
- [ ] `salt` in config.yaml changed to a fresh random value (and kept secret).
- [ ] `arm_mode: auto` for the main experiment.
- [ ] Real sshd confirmed on 62222 and you can still log in.
- [ ] `IPAddressDeny=any` active; verified honeypot cannot reach 8.8.8.8.
- [ ] Ollama reachable only via the tunnel.
- [ ] Log rotation set (`logrotate` on `logs/sessions.jsonl`).
- [ ] VPS provider ToS permits honeypots (most do; confirm — see ETHICS.md).
