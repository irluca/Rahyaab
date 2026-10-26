# Phase 4 runbook — live install of the Rahyaab hub

## Gate (user action, already requested)

Authorize the hub public key on BOTH fleet servers (as root, via
MobaXterm or any shell):

```
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOj11vA8iW7EOQ+LSZjhrplKgNOereSKNMi0NEVgH400 rahyaab-hub' >> /root/.ssh/authorized_keys
```

No password is involved anywhere in Phase 4. The hub private key
lives at `.hub-key/hub_key` in the workspace and is git-ignored; it
is copied to `/etc/rahyaab/hub_key` (0600) on the hub host only and
never pushed to GitHub.

## Run (from this VM, once the gate is done)

```
cd ~/workspace/projects/rahyaab
python3 -m hub.install_hub --check-only   # verify key + healer, change nothing
python3 -m hub.install_hub               # install + adopt + verify
```

The installer prints the Iran host's SSH host-key fingerprint on
first connect; compare it with `ssh-keygen -lf
/etc/ssh/ssh_host_ed25519_key.pub` on the server if in doubt.

## What the installer changes — and what it never touches

- Installs: `/opt/rahyaab` (hub + dashboard), `/etc/rahyaab/hub_key`,
  systemd unit `rahyaab-hub` (127.0.0.1:8890), hub DB
  `/var/lib/rahyaab/hub.db` with the adopted pair.
- Never touches: the healer unit, `/opt/best-tunnel`, the live GRE
  tunnel, or PasarGuard in any way. Preflight refuses to install if
  the healer is not active.

## After install (user action)

1. From your laptop: `ssh -L 8890:127.0.0.1:8890 root@94.184.23.90`
2. Open http://127.0.0.1:8890/ and create the operator account
   (setup form, shown only because no account exists yet).
3. The adopted pair `manag-netlen` is already there: GRE, inner
   10.10.11.x, sweep candidate scores.

## Live tests through the hub (Phase 4 acceptance)

- Dashboard shows the pair and its healer status as healthy.
- A `healer_status` job from the dashboard appends a history point
  and the pair's chart draws it.
- A `connectivity` job to the pair succeeds.
- Healer restart from the dashboard returns ok and the unit comes
  back active (the live GRE tunnel is not interrupted by a healer
  restart: the healer is the watcher, not the tunnel).
- PasarGuard node untouched throughout (its Xray on *:443 keeps
  running; nothing on the foreign host is installed or changed by
  the hub except its host key being pinned in the hub host's
  known_hosts — pinning is a read of a public key, not a change to
  the foreign host).
