<div align="center">

# 🚀 Rahyaab (رهیاب)

**A server-side control plane that finds, deploys, and keeps alive the best tunnel between any two servers — automatically.**

[![Tests](https://img.shields.io/badge/offline%20tests-176%20passing-brightgreen)](#-testing)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)](#-quick-start)
[![Release](https://img.shields.io/badge/release-v1.0-orange)](https://github.com/irluca/Rahyaab/releases/tag/v1.0)

[🇮🇷 فارسی](README.fa.md)

</div>

---

Rahyaab is a server-side tunnel control plane, derived from Tunnel Studio Pro. The dashboard, health checking and monitoring run on a server (the hub), and tunnels can be built between any two servers in the fleet — not only the dashboard host. Once a tunnel is up, a resident healer on the Iran-side server watches it and restores it the moment it drops, switching protocols if it has to. One rule above all others: **it only builds the best tunnel between servers, monitors it, and re-establishes it — it never touches a PasarGuard panel, its configs, nodes or users, by any path.**

## ✨ What it does

- 🔍 **Real benchmarks** — latency, jitter, loss and throughput measured on real traffic for every protocol, with per-protocol history.
- 🏆 **Evidence-based selection** — protocols are ranked on measured medians, never on simulated rows.
- 🚀 **One-command install** — `install.sh` sets up the hub or a node, enables BBR, and issues the panel certificate (domain or IP).
- 🔄 **Click-to-switch** — switch the live tunnel to another protocol from the dashboard, with a confirmation dialog and automatic rollback if the new protocol fails its health check.
- 🛡️ **Failover with a memory** — the healer retries the same tunnel, then walks candidates until one is healthy; an anti-flap circuit breaker stops rapid repeated switches, and a failed switch never consumes the quota.
- 👁️ **Live dashboard** — pair cards, server gauges (CPU, memory, disk, uptime), real ping and throughput, event timeline, and a protocol chip line where a blinking green light marks the active protocol. Charts draw only from real collected history — no point, no line, never faked.
- 🔐 **Key-only access** — the hub reaches servers over SSH with keys only; unknown hosts are rejected; operator passwords are PBKDF2-hashed and sessions are hashed too.

## 🌐 Protocols

| Type | Protocols |
|---|---|
| Carriers | `GRE`, `ESP` |
| Overlays | `backhaul-wss`, `rathole-noise`, `chisel-wss`, `frp-TLS`, `wstunnel-v10`, `xray-reverse`, `kcptun`, `hysteria2` |
| Quarantined | `sing-box` VLESS-REALITY, SS-2022 — disabled unless explicitly enabled, pending full live validation |

## 🧭 Safety principles

1. **Only its own units.** The tool creates, restarts and removes exclusively the services and firewall rules tagged as its own — pre-existing tunnels and services are never modified.
2. **Fail closed.** A failed health check stops the switch before any traffic moves; a failed overlay leaves the live carrier untouched.
3. **Automatic rollback.** If a new protocol fails verification, the previous one is restored automatically.
4. **No secrets in the tree.** Keys, passwords and tokens live outside the repository; the hub's own key is git-ignored and verified absent from every commit.
5. **No panel integration.** Deliberately no access to any user-management panel — the tool hands over a healthy tunnel, and what runs over it is the operator's own business.

## ⚡ Quick start

**Requirements:** Debian/Ubuntu servers, Python 3.11+, root on the target server.

```bash
# 1. Download the installer (fails loudly if the download fails)
curl -fsSL -o /tmp/install-rahyaab.sh https://raw.githubusercontent.com/irluca/Rahyaab/main/install.sh

# 2. Run it — interactive menu (install hub or node, BBR, panel certificate, update, status, uninstall)
bash /tmp/install-rahyaab.sh
```

Non-interactive:

```bash
bash /tmp/install-rahyaab.sh --role hub --bbr --ip-cert --yes                                    # hub + BBR + self-signed IP cert (auto-renewed)
bash /tmp/install-rahyaab.sh --role hub --bbr --domain panel.example.com --email you@example.com --yes  # hub + Let's Encrypt
bash /tmp/install-rahyaab.sh --role node --bbr --yes                                              # node (no dashboard)
```

**Full setup — two raw servers, one command, no Muse needed.** On the hub server, as root:

```bash
bash /tmp/install-rahyaab.sh --full-setup <node-host> --bbr --ip-cert --yes
```

This installs the hub, enables BBR, issues the panel certificate, installs the hub key on the node (the node's root password is asked once and never stored), installs the node remotely, registers the pair, measures and deploys the first tunnel (GRE), and installs the healer on top of it. After it finishes, open the dashboard and create the operator account — that step stays in the dashboard, and the installer never creates accounts or touches PasarGuard.

Then open **https://YOUR-SERVER-IP:8890**, create the operator account (setup form, shown only because no account exists yet), add servers, run a benchmark, create a pair, and enable the healer. Re-running the installer is safe: the database and existing certificates are never overwritten.

**Notes:** Let's Encrypt does not issue certificates for bare IPs, so the IP path is self-signed (the browser warns once; the fingerprint is printed by the installer for comparison) with a daily timer that renews it before expiry. A private fork needs `GITHUB_TOKEN` (a read-only fine-grained PAT) for the download path, or `--local` with an uploaded copy of the code.

## 🧪 Testing

The behaviour contract is an offline suite (no servers needed):

```bash
python -m pytest orchestrator/ -q
# 176 tests + 13 subtests — benchmarks, failover, safety gates, installer hygiene…
python -m pytest hub/ -q
# hub API, dashboard, benchmarks, switch
```

## 🗂️ Layout

```
orchestrator/     proven engine: benchmark, deploy, healer, failover, alerts, offline suite
agent/            resident Rust agent (restart-only, reports only)
hub/              fleet registry, pairs, JSON API, healer control, jobs, login
dashboard/        fresh single-page dashboard (RTL, Vazirmatn, dark theme)
install.sh        server installer (hub/node, BBR, certificates, update, uninstall)
*.sh              standalone installer pairs (iran-*.sh / foreign-*.sh)
docs/             runbooks (phases, panel survey)
```

## 🗺️ Status

- **Phase 1 (foundation)** — DONE 2026-10-26: engine + agent ported, suite green.
- **Phase 2 (hub)** — DONE 2026-10-26: stdlib JSON API, fleet/pair CRUD, healer control, jobs, events.
- **Phase 3 (dashboard)** — DONE 2026-10-26: fresh dashboard, served by the hub itself.
- **Phase 4 (live install + tests)** — DONE 2026-10-26: hub on the Iran host, live pair adopted, live API tests passed, overlay switching proven live (carrier↔carrier and carrier↔overlay).
- **Phase 5 (repo + tag)** — DONE 2026-10-27: public repo, tag `v1.0`.
- **Installer 1.0.2** — DONE 2026-10-27: live-tested on both servers (node + hub, BBR, IP certificate kept, healer and tunnel untouched).

## 📌 Scope

This tool's job begins and ends with the tunnel itself: establish the best one, watch it, restore it. It deliberately has **no integration with any panel or user-management system**.

---

<div align="center">
<sub>Public project — built and maintained with ❤️ for one operator.</sub>
</div>
