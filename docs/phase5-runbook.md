# Phase 5 runbook — private GitHub repo push + tag

## State

Local git repo is ready and committed (`a6d3229`, branch `main`):
phases 1–3 plus the Phase 4 installer and runbooks. The hub private
key (`.hub-key/`) is git-ignored and was verified absent from the
commit. Nothing has been pushed yet.

## Gate (user action)

One of these, then tell Muse it is done:

1. **Preferred (same as Tunnel Studio Pro):** create an empty
   PRIVATE repo on GitHub named `Rahyaab`, then add this VM's public
   key (safe to share) as a deploy key with **write** access.
   (Done 2026-10-27 — and the repo was then made public the same day,
   so the installer download path works without a token.) The
   deploy key is per-repo, so the Tunnel_Studio_Pro key does not
   carry over — add this one to the new repo:
   `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID+cFqcIhiMEORrQz42eyyXC186JR6aT5zVwazqZq4/m hatch`
2. **Or:** create the empty private repo and let Muse open the
   browser under your GitHub session to push from there.

## Run (once the gate is done)

```
cd ~/workspace/projects/rahyaab
git remote add origin git@github.com:irluca/Rahyaab.git
git push -u origin main
git tag v1.0 -m "Rahyaab v1.0: hub + dashboard + live pair"
git push origin v1.0
```

The tag is cut only after Phase 4's live tests pass — not before.
If Phase 4 is still gated when the repo is created, the push of the
phases 1–3 commit can still go ahead, and the tag waits.

## Final report contents

- Repo link + tag.
- Phase-by-phase status (1–3 done, 4 live-verified, 5 pushed).
- How to reach the hub (SSH forward to the Iran host, port 8890)
  and create the operator account.
- Remaining user-side items carried over: rotate the two new
  servers' root passwords and the alert-bot token (unchanged since
  26 Oct); the healer is unaffected by root-password rotation
  because it uses its own key.
