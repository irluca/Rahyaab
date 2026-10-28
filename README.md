<div align="center">

# Rahyaab

**A server dashboard that finds, builds, and keeps alive the best tunnel between two servers.**

[![Tests](https://img.shields.io/badge/offline%20tests-219%20passing-brightgreen)](#testing)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)](#quick-start)
[![Release](https://img.shields.io/badge/release-v1.0-orange)](https://github.com/irluca/Rahyaab/releases/tag/v1.0)

</div>

Rahyaab is a tunnel dashboard for two servers. The dashboard runs on one server (the hub), the tunnel runs between both, and a resident healer on the Iran-side server restores it the moment it drops — switching protocols if it has to.

One rule above all: it only builds, monitors, and restores the tunnel. It never touches any PasarGuard panel, its configs, nodes, or users.

## What it does

- **Real benchmarks** — latency, jitter, loss, and throughput measured on real traffic, per protocol.
- **Evidence-based selection** — protocols are ranked on measured medians, never on made-up numbers.
- **One-command install** — the installer sets up the hub or a node, enables BBR, and issues the panel certificate.
- **Click-to-switch** — switch the live tunnel from the dashboard, with confirmation and automatic rollback if the new protocol fails its health check.
- **Automatic failover** — the healer retries the same tunnel first, then walks candidates until one is healthy. A failed switch never consumes the anti-flap quota.
- **Live dashboard** — pair cards, server gauges, real ping and throughput, and an event timeline. Charts draw only from real collected history — no data, no line, never faked.
- **Key-only access** — the hub reaches servers over SSH keys only; unknown hosts are rejected.

## Quick start

You need two fresh Debian/Ubuntu servers and root on both.

**1. Master.** Download the installer, run it, and pick Master setup:

```bash
curl -fsSL -o /tmp/install-rahyaab.sh https://raw.githubusercontent.com/irluca/Rahyaab/main/install.sh
bash /tmp/install-rahyaab.sh
```

It installs the hub, enables BBR, asks for a domain or IP certificate, registers itself, and prints a one-line join command.

**2. Node.** Pick Node setup on the node server and paste that one line there. The node installs itself, verifies the master's certificate fingerprint (carried in the command), and joins. The master then builds the pair, deploys the first tunnel (GRE), and installs the healer in the background. This takes a few minutes.

**3. Dashboard.** Open `https://YOUR-SERVER-IP:8890` (your master server's IP), create the operator account, and check that the pair is up with GRE and a healthy healer.

Notes: the join code is single-use — printing a new one invalidates the old one, and you can print a fresh one from Manage in the installer menu. The browser warns once about the self-signed IP certificate; compare its fingerprint with the one the installer printed. Re-running the installer is safe: it never overwrites the database or existing certificates.

**Alternative: full setup from the master, one command:**

```bash
bash /tmp/install-rahyaab.sh --full-setup <node-host> --bbr --ip-cert --yes
```

This installs the hub, the node (over the hub key — the node's root password is asked once and never stored), the pair, the first tunnel, and the healer. `--protocol` changes the first tunnel (default GRE); `--pair-name` names the pair.

## Protocols

| Type | Protocols |
|---|---|
| Carriers | `GRE`, `ESP` |
| Overlays | `backhaul-wss`, `rathole-noise`, `chisel-wss`, `frp-TLS`, `wstunnel-v10`, `xray-reverse`, `kcptun`, `hysteria2` |
| Quarantined | `sing-box` VLESS-REALITY, SS-2022 — disabled unless explicitly enabled |

## Safety

- The tool creates, restarts, and removes only its own tagged services and firewall rules. Pre-existing tunnels and services are never modified.
- A failed health check stops a switch before any traffic moves; a failed overlay leaves the live carrier untouched.
- No keys, passwords, or tokens live in this repository. The hub's own key is git-ignored and verified absent from every commit.

## Testing

```bash
python -m pytest orchestrator/ hub/ -q
# 219 tests — benchmarks, failover, safety gates, installer hygiene, wizard, join flow
```

## Layout

```
orchestrator/     engine: benchmark, deploy, healer, failover, alerts, offline suite
agent/            resident Rust agent (restart-only, reports only)
hub/              fleet registry, pairs, JSON API, healer control, jobs, login
dashboard/        single-page dashboard (RTL, Vazirmatn, dark theme)
install.sh        server installer (Master/Node setup, join flow, BBR, certificates, backup, web panel, optimize, update, uninstall)
docs/             runbooks (phases, panel survey)
```

## Status

- **Phases 1–4** — done Oct 26, 2026: engine, hub, dashboard, live install and live overlay-switch proof.
- **Phase 5** — done Oct 27, 2026: public repo, tag `v1.0`.
- **Installer 1.4.0** — done Oct 27, 2026: master/node join flow, no IP typing. BackPack-style menu, backup/restore, web panel, and optimize added Oct 28, 2026. Its live test happens on rebuild.

## Scope

This tool's job begins and ends with the tunnel itself: establish the best one, watch it, restore it. It deliberately has **no integration with any panel or user-management system**.
