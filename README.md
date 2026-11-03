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

**1. Master.** Two commands, in order. The first only downloads the installer and prints nothing — that is normal. The second is what opens the menu:

```bash
# 1. Download the installer (prints nothing — that is normal)
curl -fsSL -o /tmp/install-rahyaab.sh https://raw.githubusercontent.com/irluca/Rahyaab/main/install.sh
# 2. Run it — this opens the menu
bash /tmp/install-rahyaab.sh
```

Pick Master setup in the menu.

It installs the hub, enables BBR, asks for a domain or IP certificate, registers itself, and prints a one-line join command.

**2. Node.** Pick Node setup on the node server and paste that one line there. The node installs itself, verifies the master's certificate fingerprint (carried in the command), and joins. The master then builds the pair, deploys the first tunnel (GRE), and installs the healer in the background. This takes a few minutes.

**3. Dashboard.** Open `https://YOUR-SERVER-IP:8890` (your master server's IP), create the operator account, and check that the pair is up with GRE and a healthy healer.

Notes: the join code is single-use — printing a new one invalidates the old one, and you can print a fresh one from Manage in the installer menu. The browser warns once about the self-signed IP certificate; compare its fingerprint with the one the installer printed. Re-running the installer is safe: it never overwrites the database or existing certificates.

**Verified releases.** `bash scripts/build-release.sh` builds a versioned tarball plus its `SHA256SUMS`; publish both as assets of a GitHub release. Installers then run `bash install.sh --release vX.Y.Z`, which downloads the tarball and its checksums and refuses to install anything when a hash does not match. The default branch download additionally checks the archive is intact before extracting it.

**Desktop demo panel.** `python3 -m hub.main --demo` serves the dashboard on local-only HTTP with three simulated pairs (healthy carrier, healthy overlay, down) and a demo login, so visual changes can be previewed without touching a live server. Job buttons fail against the fake hosts by design — the demo previews layout, it does not run tunnels.

**A second master sharing the same nodes.** One foreign node can serve two masters at once (for example, an old and a new Iran server): each hub carries its own short tag and its own inner address base, so the second hub's units, interfaces and inners never overwrite or misroute the first hub's. The first hub uses base 10; a new hub installed from this installer gets base 20 by default, and `--inner-base 30` (any even number from 12 to 250) picks another. Before deploying, the wizard reads both hosts and refuses the join — naming the colliding interface, address or unit — instead of breaking the tunnel that already owns them.

**Alternative: full setup from the master, one command:**

```bash
bash /tmp/install-rahyaab.sh --full-setup <node-host> --bbr --ip-cert --yes
```

This installs the hub, the node (over the hub key — the node's root password is asked once and never stored), the pair, the first tunnel, and the healer. `--protocol` changes the first tunnel (default GRE); `--pair-name` names the pair.

## Protocols

| Type | Protocols |
|---|---|
| Carriers | `GRE`, `ESP`, `fou-gre` (GRE over UDP), `ipip`, `wireguard`, `wireguard-fec` (WireGuard behind a 2+1 XOR parity relay, for lossy paths) |
| Overlays | `backhaul-wss`, `rathole-noise`, `chisel-wss`, `frp-TLS`, `wstunnel-v10`, `xray-reverse`, `kcptun`, `hysteria2`, `tcp-lanes` (8 parallel TLS-record-shaped TCP streams, reverse mode), `tcp-lanes-v6` (same lanes, foreign client dials Iran's global IPv6; probe-gated, see below) |
| Sing-box | VLESS-REALITY, SS-2022 — first-class since Oct 24, 2026; `BEST_TUNNEL_DISABLE_SINGBOX=1` re-quarantines them |

6to4 is deliberately not a carrier: SIT encapsulates IPv6 only, and the bench/probe/DNAT path is IPv4-only.

## Safety

- The tool creates, restarts, and removes only its own tagged services and firewall rules. Pre-existing tunnels and services are never modified.
- A failed health check stops a switch before any traffic moves; a failed overlay leaves the live carrier untouched.
- No keys, passwords, or tokens live in this repository. The hub's own key is git-ignored and verified absent from every commit.

## Testing

```bash
python -m pytest orchestrator/ hub/ -q
# 424 tests + 13 subtests — benchmarks, failover, safety gates, installer hygiene, wizard, join flow
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
- **1.7.0** — done Nov 2, 2026: verified releases (`install.sh --release vX.Y.Z`, tarball checked against `SHA256SUMS` before anything is extracted, GitHub first with mirror fallback); persistent per-pair traffic totals; stability-aware scoring (latency + 2× jitter + 20× loss, with a stability penalty past 10 ms jitter / 2% loss); random private panel path (rotatable from the panel); one-click quick test and deploy-best; JSON backup and restore from the panel; a desktop demo panel (`hub.main --demo`, fake data, login `admin` / `demo-1234`); new protocols `fou-gre`, `ipip`, `wireguard`, `wireguard-fec`, `tcp-lanes`. Nothing in this release touches a live server: it is code and tests only, and deployment to a hub is a separate step.
- **1.8.0** — done Nov 2, 2026: IPv6 reverse mode. A per-pair IPv6 readiness probe (auto-enqueued after setup and on hub start, re-runnable from the panel) tests each direction with a real TCP connect and reports them separately, because live measurement showed foreign→Iran IPv6 passes while Iran→foreign is blocked. `tcp-lanes-v6` — the same 8 lanes, but the foreign client dials Iran's global IPv6 and the Iran server listens dual-stack — is benched by sweeps and quick tests only for pairs whose probe passed the reverse direction, and switches to it resolve the Iran address off the live host at switch time, refusing cleanly when it is gone. The inner path stays IPv4. Nothing in this release touches a live server: it is code and tests only, and deployment to a hub is a separate step.
- **1.8.1** — done Nov 3, 2026: stale-carrier DNAT purge. A live GRE -> ESP switch reported success while a stale GRE DNAT ahead of the ESP DNAT in PREROUTING sent every client packet to the dead GRE inner (the ESP inner ping stayed healthy, so nothing looked wrong). Carrier switches now purge the old carrier's DNAT until it is actually gone from PREROUTING — a single `iptables -D` removes only one copy, and repeated deploys can leave duplicates — and a carrier-to-carrier switch refuses to commit if the old destination is still in force after the purge, so it rolls back instead of stamping a shadowed tunnel ACTIVE. The same purge is used at overlay cutover. Nothing in this release touches a live server: it is code and tests only, and deployment to a hub is a separate step.
- **Installer 1.4.0** — done Oct 27, 2026: master/node join flow, no IP typing. BackPack-style menu, backup/restore, web panel, and optimize added Oct 28, 2026. Its live test happens on rebuild.

## Scope

This tool's job begins and ends with the tunnel itself: establish the best one, watch it, restore it. It deliberately has **no integration with any panel or user-management system**.
