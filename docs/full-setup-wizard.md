# Full-setup wizard — design (2026-10-27)

Goal, in the user's words: on two raw servers, the script and the
dashboard together install and do everything, with no Muse needed.
The only trust bootstrap is one shared step, and it is honest: two
servers that have never met cannot trust each other out of nothing.

## Join flow — the primary UX (install.sh 1.4.0)

The user rejected typing the node IP into the script ("این خیلی بده
که") and asked for the Kariz/Smite way: the script first asks
"node or master?", and the node connects to the master. That is now
the primary flow; full-setup below stays as the master-driven
alternative.

1. Master: `bash install.sh` → pick **master**. Installs the hub,
   enables BBR, issues the panel certificate, self-registers
   (`hub.wizard --self-host`), and prints a one-line join command
   carrying a fresh single-use token + the panel certificate's
   SHA256 fingerprint. Re-printing (menu item 11 / `--print-join`)
   generates a fresh token and invalidates the old one.
2. Node: paste that one line. It installs the node role, enables
   BBR, fetches the master's certificate, verifies it against the
   fingerprint from the command, then POSTs to `/api/join` using the
   verified certificate as its CA (not curl -k on an unverified
   channel), sending the token + its own SSH host key. The hub
   validates the token (constant-time compare, deleted after one
   successful join), creates the node record with the request's
   source IP (auto-detected, never typed), pins the node's host key
   (stale lines for that host dropped first), returns the hub
   public key for the node to authorise, creates the first pair
   (master = iran, node = foreign) and enqueues a `full_setup` job
   that runs the wizard chain in the background.
3. A pair that already has a current protocol gets no new job:
   joining never redeploys a live pair on its own. Node-rebuild
   recovery is: delete the pair in the dashboard, print a fresh join
   command, re-join.

The join endpoint is unauthenticated by design (the token is the
credential), placed before the session check in `_route`, like
`/api/setup`. A missing master record, a missing hub public key, or
a bad token fails with a clear error and creates nothing.

## One command (install.sh 1.3.0) — master-driven alternative

On the hub server, as root:

```bash
bash install.sh --full-setup <node-host> --bbr --ip-cert --yes
```

(or menu item 10). Runs steps 1–7 in order. The node root password
is asked once, in step 2, and never stored. If a pair with the same
name is already set up (it has a current protocol), full-setup stops
before anything destructive; an interrupted earlier run (no current
protocol yet) can be resumed by running it again.

Live proving: the chain has been tested piece by piece (remote-node
install live; registration + measure/deploy/install chain offline
with injected fakes). The end-to-end run happens on the operator's
rebuild, never on a live production pair — deploying over a live
pair would move its tunnel, so it is deliberately not tested there.

## The one trust step (unavoidable, and only once)

Two options, the operator picks one at setup time:

1. **One-time root password (default path).** On the hub server,
   `install.sh push-key --node <foreign>` asks for the node's root
   password once, installs the hub public key on the node, pins the
   node's host key, verifies key-only login, and then discards the
   password. It is never stored, logged, or printed. After that,
   everything is key-only and the password is never needed again.
2. **Manual key paste (no password).** `install.sh` prints the hub
   public key; the operator appends that one line to the node's
   `/root/.ssh/authorized_keys` and pins the host key. Same end
   state, one manual line.

There is no third option that is both automatic and honest: a
script cannot invent trust between two strangers.

## Pipeline (all on the hub server, all key-auth after step 2)

1. **Hub install** — `install.sh --role hub --bbr --ip-cert` (or
   `--domain`). Installs code, unit, BBR, certificate. Generates the
   hub keypair at `/etc/rahyaab/hub_key` if none exists; an existing
   private key is never overwritten, and a missing `.pub` is rebuilt
   from it (`ssh-keygen -y`).
2. **Push key** — `install.sh push-key --node <foreign>` (step above).
3. **Remote node install** — `install.sh --remote-node <foreign>`:
   tars the hub's own `/opt/rahyaab` code, copies it plus
   `install.sh` to the node over the hub key, and runs the node
   install there (`--role node --bbr --local`). Verifies code +
   BBR on the node. Fails cleanly if the node host key was never
   pinned (run push-key first).
4. **Register in the hub DB** — servers (iran, foreign, healer=iran)
   and the pair are written to the hub database by
   `hub/wizard.py` (`python3 -m hub.wizard --db
   /var/lib/rahyaab/hub.db --iran-host X --foreign-host Y`), so the
   dashboard shows them. Idempotent by pair name; server records
   carry no key_path, so the hub uses its default hub key. Inner
   addresses default to 10.10.11.1 (Iran) / 10.10.11.2 (foreign),
   overridable by flags. Later pairs take the next /24.
5. **First tunnel, honestly measured** — `orchestrator/wizard_setup.py`
   (`run_setup`): first seeds the engine's pinned-key store from
   `/root/.ssh/known_hosts` (`seed_host_pins`), so a first sweep or
   deploy connection presenting a different host key is REJECTED,
   never blindly pinned. Then it measures ONE protocol (default GRE)
   with the engine's own single-benchmark path (temporary test tunnel
   on ports 8897/8898, never the production frontend) and deploys
   that protocol for production with `deploy_tunnel` (verified +
   rollback). A disqualified or non-positive score aborts the setup
   instead of inventing a score. Deploy-first is required, not a
   preference: a pair with no deployed tunnel produces no monitor
   sample, so the healer cannot conjure the first tunnel by itself.
   GRE verification is inner ICMP + DNAT, so it works on raw servers
   with no listener on the foreign frontend.
6. **Healer auto-install** — `orchestrator/install_healer_wizard.py`
   (`wizard_install`): same `install()` as the laptop installer, but
   over key auth (`KeyHost`, pinned host keys, hub key) instead of
   passwords. It generates a dedicated healer keypair on the hub
   server if missing (never overwrites), authorises it on BOTH
   servers, writes the healer config (pair, hosts, key path,
   frontend port, active tunnel, candidate scores) + unit, runs the
   `--once` validation pass, starts the service, and verifies the
   heartbeat reports HEALTHY. No Telegram token at setup time;
   alerts are wired later from the dashboard's own settings.
   The measured score is also recorded in the hub pair row
   (`hub.store.update_pair_measurement`), so the dashboard shows the
   real score from the start.
7. **Fill the rest by measurement** — the existing
   `benchmark_scheduler` re-runs full sweeps on ACTIVE pairs, so
   the remaining candidates arrive as real rows over time. The
   operator may also run a full sweep up front instead of the
   quick start (flag `--sweep full`); quick start is the default
   because a 12-protocol sweep is long and the tunnel must not
   wait for it.

## What already exists (reused, not rewritten)

- `install.sh`: hub/node install, BBR, domain/IP/custom certs,
  update, status, uninstall, re-run safety.
- `install.sh push-key` + `ensure_hub_key` (1.1.x): key generation
  and one-time-password bootstrap.
- `hub/ssh.py`: key-only executor, unknown hosts rejected.
- `hub/store.py` + server/pair API: fleet and pair records.
- `orchestrator/install_healer.py`: healer config + unit install
  (laptop/password form — the wizard adapts it to key auth and
  wizard-supplied config; the laptop form stays untouched).
- `orchestrator/benchmark_scheduler.py`: re-sweeps on ACTIVE pairs.
- `orchestrator/healer.py`: from-down failover (the path a fresh
  pair's first tunnel and every later recovery share).

## Deliberately NOT in the wizard

- Operator account creation stays in the dashboard setup form
  (the script never creates accounts or passwords).
- PasarGuard: never touched, never installed, never read.
- No passwords are ever stored: not in the hub DB, not in files,
  not in logs. The one-time node password lives only in the
  push-key process memory.
- No faked scores: candidate_scores only ever holds measured
  values; a protocol never measured is absent, not zero.
