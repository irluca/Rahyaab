# Full-setup wizard — design (2026-10-27)

Goal, in the user's words: on two raw servers, the script and the
dashboard together install and do everything, with no Muse needed.
The only trust bootstrap is one shared step, and it is honest: two
servers that have never met cannot trust each other out of nothing.

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
   `hub/wizard.py` (`python3 -m hub.wizard register --db
   /var/lib/rahyaab/hub.db --iran-host X --foreign-host Y`), so the
   dashboard shows them. Idempotent by pair name; server records
   carry no key_path, so the hub uses its default hub key. Inner
   addresses default to 10.10.11.1 (Iran) / 10.10.11.2 (foreign),
   overridable by flags. Later pairs take the next /24.
5. **First tunnel, honestly measured** — deploy GRE (the carrier
   that has measured best on this route in every sweep) via the
   engine, verify ping + L7, and record its real measurement as the
   initial `candidate_scores`. Nothing is faked: the initial map
   holds exactly the protocols actually measured.
6. **Healer auto-install** — generate a dedicated healer keypair on
   the hub server, append its public key to BOTH servers over the
   hub key, write the healer config (pair, hosts, key path,
   frontend port, active tunnel, candidate scores) + unit with
   `orchestrator/install_healer.py`'s install path adapted to
   key auth, and start it. Verify the heartbeat reports HEALTHY.
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
