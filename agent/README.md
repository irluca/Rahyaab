# best-tunnel-agent — resident watcher (Phase 4, v3.0)

A single static-ish Rust binary that lives on each server and watches
**only the program's own tunnel units**. It exists for one scenario:
the laptop (and dashboard) is off, and a tunnel unit dies. The agent
brings that unit back under policy, and records what happened so the
dashboard can read it later.

## Authority (decision D2: restart + report only)

- The config file `/etc/best-tunnel/agent.toml` names the owned units.
  The agent restarts **only** those units, and only with
  `systemctl restart`, and only when a unit is not active.
- Anti-flap policy: at most `max_restarts_per_hour` restarts in any
  rolling hour (default 3), never sooner than `restart_cooldown_secs`
  after the previous restart (default 60s). Past the cap it logs a
  `restart_refused` event and stops trying.
- If the units are up but the local delivery port does not answer,
  the agent reports (`delivery_failed`) and does **not** restart:
  restarting a healthy unit fixes no backend problem.
- The agent **never** switches protocols, **never** touches any other
  service, has **no** network listener, makes **no** outbound
  connection, and **never** updates itself.

## Heartbeat and events

- Heartbeat: `/var/lib/best-tunnel/agent-heartbeat.json`, rewritten
  every check interval (default 15s) via temp-file + rename, so a
  reader never sees a torn write. A heartbeat that stops advancing
  **is** the down signal (Phase 5 turns it into an alert).
- Events: JSON lines in `/var/log/best-tunnel/agent-events.jsonl`
  (`unit_restarted`, `restart_refused`, `delivery_failed`).
- Restarting the agent unit resets its in-memory restart counter;
  that is the documented reset path after a flap-limit stop.

## Build and install

- Zero dependencies: `cargo build --release` with plain rustc
  (built and tested with Ubuntu 24.04's apt rustc 1.75.0; no crates.io
  access needed, which matters on filtered routes).
- The binary is installed only through `install_agent.sh`, which
  refuses any binary whose SHA-256 does not match the pinned value
  the operator recorded at build time. There is no self-update path.
- Build pin for the first live install (2026-10-24, built on the
  Turkey test host): SHA-256
  `948dd9862471a95bc1c0f72eebd283eb3e77c890a49b661f7d54776fe0fb0899`.

## Live acceptance (2026-10-24, test pair)

- Both agents installed; heartbeats fresh, units active, delivery ok.
- Cut test: the Iran rathole server was stopped by hand; the agent
  restarted it and the 443 listener came back, and the
  before/after diff of all active services on both hosts was empty
  (nothing but the owned unit changed state).
- Flap test: four stops 70s apart against the production policy
  (3/hour, 60s cooldown) — three restarts, then a refusal with
  `flap limit reached`, and the unit stayed down until the operator
  started it again.
