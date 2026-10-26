# Panel survey — live exploration notes (2026-10-26)

Goal: install Smite, BackPack, Kariz and several foreign tunnel panels on the
two live servers (Iran 94.184.23.90, foreign 217.11.164.209), build a real
tunnel with each, study the dashboard, and take layout/UX ideas into Rahyaab.
Ideas only — no copied code. Kariz: running official releases on own servers
is allowed by its licence; its core must not be copied or reused.

Guardrails for every install:
- PasarGuard node on the foreign server (xray on :443 and :8080) is NEVER
  touched. Experimental panels use their own ports only.
- Rahyaab hub (:8890, Iran) and the best-tunnel healer keep running.
- Test tunnels forward a harmless local HTTP service, never port 443/8080.

## Smite (zZedix/Smite, MIT, FastAPI + React)
- Panel API :8000, React frontend :3000 (compose profile `frontend`).
  Nginx profile is `https` only — skip it, no domain here.
- Install script is interactive (port, domain prompts) and pulls the panel
  image from GHCR, falling back to a local build. Plan: manual non-
  interactive install instead — clone to /opt/smite, write .env
  (PANEL_PORT=8000, PANEL_HOST=0.0.0.0, SECRET_KEY random, DB sqlite),
  `docker compose --profile frontend up -d`, then `smite admin create`.
- Iran server had no Docker; `apt-get install docker.io docker-compose`
  was started 2026-10-26 ~20:07 (still running at last check).
  Foreign server already has Docker 29.9.2 + Compose v5.6.1.
- Node install: scripts/smite-node.sh on the foreign server (needs the
  panel CA cert copied over).
- Dashboard pattern (from code, not copied): stat cards with coloured icon
  chips + 4px bottom accent bar; tunnel cards with status pill, core badge
  (uppercase, bordered, colour-coded), transmission badge
  (TCP green, UDP yellow, WS pink, gRPC teal, TCPMUX violet), ports in mono,
  Node/Server names in a small grey row, coloured action icon buttons
  (reapply green, edit blue, delete red).

## BackPack (AminMGMT/BackPack, AGPL-3.0, Go single binary)
- Install: `bash <(curl -fsSL .../BackPack/main/install.sh)` as root,
  SHA-256-verified release archive, interactive CLI menu (`sudo backpack`).
- Web panel :7777: live CPU/RAM/disk/traffic, per-tunnel status/ping/logs,
  metrics incl. retransmits, loss, FEC on KCP, kept across restarts;
  Telegram alerts; watchdog revives a dead tunnel in ~1 min; auto-rollback.
- Tunnels: reverse (foreign dials Iran, 12 transports) and direct
  (Iran dials foreign, full IP tunnel, GRE+Noise, 6 carriers).
  Managed-servers docs exist for fleet control from one panel.
- No Docker needed. Install on both servers; build one reverse tunnel
  (e.g. TCP or WS) forwarding a test HTTP service.

## Kariz (Erfan-XRay/Kariz, source-available, Rust)
- Install: `bash <(curl -fsSL .../Kariz/main/scripts/kariz.sh)` as root,
  menu → "Install the web panel here", prints panel address + one-time
  login link. Other servers join with one command + a panel code.
- Panel: live map (servers as wells, tunnels as channels), charts, logs,
  speed test, backups, private networks; per-tunnel/server usage
  today/week/month/total from kernel counters, split user data vs overhead;
  Telegram alerts + /status; wizard pre-checks both servers and rolls
  both back on failure.
- Transports: tcp, tcpmux, ws, wss, quic, kcp; reverse or direct.

## FRP standalone (fatedier/frp) — LIVE FINDINGS (2026-10-26 evening)
- Latest release v0.71.1 (2026-10-14), single static binaries, no
  Docker needed. frps on Iran (:17500, dashboard :17501 behind basic
  auth, both bound to loopback for the survey), frpc on foreign.
  Tunnel verified: Iran:18092 -> foreign 127.0.0.1:18081 test page.
- Dashboard is a thin SPA shell: real data comes from /api/serverinfo
  (version, bindPort, totalTrafficIn/Out, curConns, clientCounts,
  proxyTypeCount), /api/proxy/<type>/<name> (per-proxy conf,
  todayTrafficIn/Out, curConns, lastStartTime, status online) and
  /api/clients (hostname, clientIP, version, online). /api/proxies is
  405 in 0.71 — the UI queries per-proxy endpoints instead.
- Design notes: serverinfo + per-proxy traffic counters are exactly
  the honest, no-fake-numbers pattern Rahyaab already uses; the frps
  dashboard proves a tiny API surface is enough for a useful panel.
  No node/fleet concept, no history charts, no alerts — a forwarder,
  not a manager.

## NPS (ehang-io/nps) — LIVE FINDINGS (2026-10-26 evening)
- Latest release v0.26.10 is from 2021-04-08: effectively unmaintained
  for 5+ years (a risk note for anyone adopting it). Still installs
  cleanly: server binary + conf + web assets in one tarball (flat
  layout, no installer). Server on Iran (web :18095, bridge :18096),
  client (npc) on foreign, tunnel verified: Iran:18097 -> foreign
  127.0.0.1:18081 test page.
- Gotchas: nps.conf ships with http_proxy_port=80 and
  https_proxy_port=443 enabled by default — on a production host those
  would grab the well-known ports, so they were set to 0 for the
  survey. web_port uses "web_port = 8080" (spaces around =), so a
  naive sed for "web_port=" misses it.
- Web UI is server-rendered HTML + jQuery (c) 2018-2020 look. Login is
  AJAX POST /login/verify (not the form action). Clients are created
  via POST /client/add {remark, vkey, crypt, compress,
  config_conn_allow}; tunnels via POST /index/add {client_id, type,
  port, target, remark}. The client list page is JS-filled; the
  authoritative client record lives in conf/clients.json on the server.
- Design notes: the client/tunnel model (register a client once with
  a vkey, then attach many tunnels to it) is the cleanest fleet
  primitive seen in the survey; the UI itself is dated (Bootstrap-era
  tables, no live charts, no per-tunnel traffic on the list page).

## Smite — LIVE FINDINGS (2026-10-26 evening)
- Panel (FastAPI, :8000, docs enabled) runs in Docker on Iran
  (ghcr.io/zzedix/smite-panel:latest); the React frontend (:3000) could
  NOT be built on Iran: its build needs docker.io/library/nginx:alpine
  and node:18-alpine and Docker Hub answers 403 from the Iran server
  (GHCR works, Docker Hub does not). The dashboard was therefore studied
  from the live API + the frontend source, not from a rendered page.
- Admin created via the repo CLI (cli/smite.py, runs a script inside
  the panel container). API: JWT login, /api/status, /api/nodes,
  /api/tunnels (+/apply, /reapply-all), /api/panel/ca, /api/settings,
  /api/core-health, /api/logs.
- Nodes auto-register: the node agent POSTs {name, ip_address (auto
  detected), api_port 8888, fingerprint=sha256(hostname-node_name)[:16],
  metadata{role iran|foreign}} to /api/nodes; no token needed. Both
  nodes (iran-node on the panel host, foreign-node abroad) show active
  with connection_status connected.
- FRP communication is OFF by default and the tunnel flow silently
  depends on it: with it off, tunnel creates hang for ~30 s (records
  still created, status error "Foreign node error: Network error"),
  because nodes report "FRP communication not enabled, continuing with
  HTTP". Enabling it (PUT /api/settings frp.enabled=true, port 7000)
  makes the panel start its frps comm server on :7000 and nodes connect
  frp clients to it (visible as frp-status reports, remote_port per
  node). The frps binary must exist on the panel host.
- Tunnel FRP port trap: a tunnel's own frps must NOT reuse port 7000 —
  the first attempt failed with "FRP failed to start" because the comm
  server already holds 7000. Using bind_port 17000 fixed it.
- FRP port model: the form's ports are bare numbers and local_port is
  set to ports[0] — the SAME port on both sides. A forward of 18089
  means Iran:18089 -> foreign 127.0.0.1:18089, not an arbitrary target
  port. Verified live: with the test service also on foreign:18089,
  Iran:18089 returns the test page (200) through tunnel survey-frp
  (status active, frps on :17000 + :18089).
- Design notes (patterns only, from source + API): node-centric fleet
  (panel + nodes with roles), per-node frp-status reporting, settings
  as one JSON document (frp/telegram/tunnel sections), tunnel apply as
  an explicit step after create, per-tunnel quota fields (used_mb,
  quota_mb), core-health screens per core. From the React source
  (studied earlier): stat cards with coloured icon chips + 4px bottom
  accent bar; tunnel cards with status pill, colour-coded core badge,
  transmission badge (TCP green, UDP yellow, WS pink, gRPC teal,
  TCPMUX violet), mono ports, Node/Server row, coloured action icons.
- Panel 2.6.1 installed on Iran (:18090, self-signed cert, secret path
  prefix). Browser exploration was impossible from here: the browser
  environment refuses loopback addresses and cannot reach nonstandard
  ports on the Iran server (same block as BackPack :7777), although the
  panel is healthy and reachable from the foreign server (200).
- The panel was instead driven through its own JSON API (endpoints read
  from the served JS bundle): POST ./api/link with the one-time token
  (returns a CSRF token), GET session/servers, POST servers/join-code,
  POST tunnels (async, returns an op id polled via GET op), plus
  tunnels/check, tunnels/delete, tunnels/control, history, events, logs,
  networks, schedules, sessions, telegram, update.
- Join-code lesson: the `host` parameter is the PANEL address the agent
  must dial, not the new server's address. Passing the foreign server's
  address made its agent dial itself (connection refused every 30 s) and
  never appear; passing the panel address fixed it. A second agent on
  the panel host itself was also needed: the panel's built-in "local"
  server entry cannot run tunnel endpoints — tunnels need an agent on
  every participating server, panel host included.
- Tunnel creation took five attempts; the first four failed at the
  "connect" step and rolled back (undone=true). Root cause of the
  reverse-mode failures: a forward written as a bare port ("18082") is
  an invalid socket address for the kariz core — its endpoint unit
  (kariz@<name>.service) started, printed "control socket ready", then
  died with "failed to listen on forward port … invalid socket address"
  in a restart loop, so the connect dial got "Connection refused". The
  panel's pre-check passed the bare port and the op error hid the real
  cause; only the unit journal showed it. With a full address
  ("0.0.0.0:18088") the fifth tunnel (TCP, balanced profile, reverse,
  entry=iran-agent, exit=foreign) was created (op done) and VERIFIED live:
  Iran :18088 returns the foreign test page through the tunnel, kariz
  process listening on control + forward ports, unit active.
- Design notes (from the served bundle + API, patterns only): Persian
  RTL UI, "night" theme, tile radio selectors in the wizard (57 wizard
  strings, steps: pick servers, check, create), stat-cards, mono numbers
  for ports/values, small ghost/primary buttons, gauge + chart elements,
  "channel" wording for tunnels. Tunnel ops are stepwise and visible
  (look, check_entry, check_exit, write_entry, write_exit, start_entry,
  start_exit, connect) with rollback on failure — a good pattern to
  steal for Rahyaab: show the steps, roll back cleanly, and surface the
  endpoint's real error instead of a generic dial error.
- NPS (ehang-io/nps): intranet-penetration server + client, web management
  UI, tcp/udp/http(s)/socks5, traffic + system info + real-time bandwidth.
  Single binaries, no Docker needed.
- FRP (fatedier/frp): frps dashboard (port 7500) + frpc; classic reverse
  tunnel with a built-in dashboard page.
- wg-easy (wg-easy/wg-easy): WireGuard UI in Docker — tunnel panel with
  clients, traffic graphs, QR configs.

## BackPack — LIVE FINDINGS (2026-10-26 evening)
- Installed v1.8.5 on both servers (checksum verified). The interactive
  wizard was abandoned mid-run for a manual path: a fresh token, hand-written
  TOML configs (server on Iran, client on foreign, Reverse/TCP, tunnel port
  28443, forward 18080 -> foreign 127.0.0.1:18081, Turbo preset), systemd
  units `backpack-server-28443` / `backpack-client-28443`. Verified live:
  curl from Iran to :18080 returns the foreign test page ("backpack-test-ok").
  No wizard-generated setup data was used.
- Browser exploration FAILED for a network reason, not a panel problem: the
  browser environment cannot reach nonstandard ports on the Iran server
  (7777 refused, same as Kariz 18090), while the panel process is verifiably
  listening on *:7777 and reachable from the foreign server. The panel was
  instead explored directly through a secure SSH forward: login page loads,
  login works, dashboard + APIs answer.
- Panel structure (single-page app, server strip + fleet below):
  - Top strip = this machine right now: CPU %, cores, load, mem %, disk %,
    live up/down speed, total traffic, tunnel counts, version, congestion.
  - Dashboard = server strip, then tunnel cards (the "fleet"). Card data
    seen live: role, transport, direction, listen addr, forwarded ports,
    state (online), ping (39 ms), preset (Turbo), uptime, bytes in/out,
    per-30s rate series.
  - Our hand-written manual tunnel appears in the panel automatically
    (online, ping 39) — the panel discovers configs, it does not require
    the wizard.
  - Overview page: "trouble first" — totals since setup, per-tunnel
    traffic, current problems; deliberately repeats nothing from the strip.
  - Per-tunnel metrics: traffic, peer, limits, bot relay, certificate,
    failover, connection pool, KCP error-correction repairs. A section with
    no data behind it is removed, never shown with example values.
  - History: speed over the last day, per-day totals for the week, two
    uptime figures, config changes in the window.
  - Servers page (managed fleet): adding a server is a form — the panel
    logs into the other server over its own SSH, no install line to run.
  - Manage page: auto-refresh schedule (restart every tunnel on a timer),
    built-in proxy (SOCKS5/HTTP backend wired to a tunnel port), file
    locations with sizes. No dialogs: each tool is a panel with state,
    controls and result in one place.
  - Monitor: alerts + health-check screens sharing one stylesheet.
  - Connection test: two equal panes — left: form, countdown, the one
    line to run on kharej, verdict; right: transports filling as tried.
  - Terminal: in-page root shell, opened deliberately with a button,
    every session written to the audit record and sent to alerts, persists
    across navigation like a window behind another window.
  - Settings: panel access, security, Telegram bot, release channel.
  - Quota: per-tunnel traffic limit enforced by the engine, counted over
    every restart. Maintenance: update, restore points, backup.
- Design ideas worth stealing (patterns only): live-meter strip separated
  from the "everything else" overview; trouble-first ordering; empty
  sections deleted instead of faked; per-tunnel history with config changes
  in the same window; managed servers as a form, not a shell line; terminal
  as an audited, deliberate action.

## wg-easy (wg-easy/wg-easy, Docker) — LIVE FINDINGS (2026-10-26 evening)
- Panel fully explored: Vue SPA on :18099 (Iran, container), WireGuard
  server wg0 on :51822 (UDP) inside the container, client
  "survey-foreign" created via API (address 10.8.0.2, QR/config
  endpoint, transfer counters, handshake timestamps, apexcharts
  graphs). API surface: POST /api/session {password = sha256 hex},
  GET/POST /api/wireguard/client, GET .../client/{id}/configuration.
- v14 gotchas, each found the hard way: PASSWORD is a fatal error —
  only PASSWORD_HASH works; and PASSWORD_HASH must be bcrypt of the
  SHA256 hex of the password (the UI sends sha256, the server
  bcrypt-compares that hex), NOT bcrypt of the password itself.
  A second trap: WG_PORT is the port inside the container, so the
  Docker mapping must be 51822:51822, not 51822:51820.
- DATA PATH DID NOT COMPLETE on this pair — and the evidence says it
  is the path, not wg-easy: the foreign client's handshake packets
  never arrived at the Iran host (0 packets on eth0/tcpdump across
  many attempts, container transfer 0/0, no handshake), while plain
  UDP from the same foreign host to the same Iran host arrived 3/3
  and 4/4 in the same minutes, including right after wg bursts.
  Practical conclusion: on this Iran<->foreign path right now,
  WireGuard UDP handshakes do not get through while generic UDP does
  — a WireGuard-only panel is not a reliable link here, which is
  exactly why a multi-protocol healer (GRE/ESP/TCP fallbacks) matters.
- Design notes: client cards with avatar, per-client transfer Rx/Tx,
  latest-handshake timestamps, one-click config download + QR, traffic
  graphs per client. The host cannot reach the wg subnet directly:
  wg0 lives inside the container netns, so tests must run from inside
  the container (docker exec), not from the host.

## SYNTHESIS — FINAL (2026-10-26 night; all panels explored)
What each panel is best at:
- BackPack: best live-ops panel — live strip + fleet cards, trouble-first
  overview, audited in-page terminal, managed servers as a form.
- Kariz: best tunnel-creation UX — wizard with pre-checks, stepwise ops
  with rollback; weakest point is hiding the real endpoint error.
- Smite: best fleet model — nodes with roles, per-node health reports,
  settings as one JSON document, per-tunnel quota fields.
- FRP: best minimal API — serverinfo + per-proxy counters prove a tiny
  surface is enough for a useful panel; no fleet, no history, no alerts.
- NPS: best client primitive — register a client once with a key, attach
  many tunnels to it; and a cautionary tale (unmaintained since 2021,
  defaults grab ports 80/443).
- Nexora (patterns from public docs only): counter strip with
  click-to-filter, pinnable/draggable live tiles, theme colours, full RTL.

Ideas to apply to the Rahyaab dashboard (in priority order):
1. Per-pair byte counters + per-day history (FRP counters + BackPack
   history with config changes in the same window). Rahyaab already
   collects latency/throughput; add carrier-iface byte counters per
   pair and daily rollups from healer_history.
2. Trouble-first ordering (BackPack): pairs with problems sort to the
   top of the tunnel list, healthy ones below. DONE — deployed to the
   live hub 2026-10-26 night.
3. Stepwise job display with the REAL error (Kariz ops pattern, minus
   its generic-error flaw): Rahyaab jobs already exist — show their
   step list and last error verbatim in the UI.
4. Compact per-server live strip above the cards (BackPack strip):
   CPU/mem/disk/uptime per server in one line each. DONE — deployed
   to the live hub 2026-10-26 night.
5. Keep the standing rules: empty sections deleted, never faked; a dash
   means not-reported, never zero; charts draw only from healer_history.
6. Future, not now: an NPS-style one-time-key agent registration for
   multi-server fleets, and Smite-style per-pair quota fields.
7. wg-easy lesson for Rahyaab's engine (not the dashboard): a
   WireGuard-only link is not reliable on this Iran<->foreign path
   right now — keep the multi-protocol healer with TCP/GRE/ESP
   fallbacks as the core design.
8. Cleanup (2026-10-26 night): all survey services, containers,
   units, configs and test listeners removed from both servers;
   production verified afterwards (healer active, hub active,
   GRE 0% loss ~38 ms, hub dashboard 200 from the foreign host).
   Left untouched: healer, rahyaab-hub, GRE/ESP units, PasarGuard,
   and the pre-existing /usr/local/bin/frpc+frps binaries (dated
   Aug 14, before this survey, inert, no listeners).
