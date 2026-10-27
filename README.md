# Rahyaab (رهیاب)

Server-side tunnel control plane, derived from Tunnel Studio Pro.
The dashboard, checking and monitoring run on a server, and tunnels
can be built between any two fleet servers — not only the dashboard host.

Red line, unchanged from Tunnel Studio Pro: this tool only establishes
the best tunnel between servers, monitors it constantly, and
re-establishes it immediately if cut. It never touches a PasarGuard
panel — no configs, nodes or users, by any path.

## Layout

- `orchestrator/` — the proven Tunnel Studio Pro engine, ported
  wholesale (benchmark, deploy, healer, failover, alerts). Its offline
  suite lives here as `test_offline_suite.py`.
- `agent/` — the resident Rust agent (restart-only, reports only),
  ported wholesale.
- `hub/` — Phase 2: fleet registry, pairs, JSON API, healer control,
  jobs, login. (In progress.)
- `dashboard/` — Phase 3: the new dashboard, built fresh. It will not
  resemble the old Tunnel Studio Pro dashboard.
- Root `*.sh` / `*.bat` — the shipped server installers and launchers
  the engine's supply-chain tests pin. They are part of the port, not
  decoration: the suite fails without them at the repo root.

## Status

- Phase 1 (foundation) — DONE 2026-10-26: engine + agent ported,
  offline suite green: **158 passed, 13 subtests passed**.
- Phase 2 (hub control plane) — DONE 2026-10-26: stdlib JSON API
  (setup-once operator account, PBKDF2 + hashed session tokens,
  fleet/pair CRUD, healer status/start/stop/restart over
  key-only SSH, background job queue, events). Offline test green
  (hub/test_hub.py), plus a live CLI smoke run (health, setup,
  second-setup refused). Since the evening of 2026-10-26 the hub is
  PUBLIC at https://94.184.23.90:8890 (self-signed cert, Secure
  cookies, HSTS, login rate limiting) by the user's decision; before
  that it was localhost-only via SSH forwarding.
- Phase 3 (new dashboard) — DONE 2026-10-26: single-page app in
  dashboard/ (RTL, right sidebar, dark professional theme, Vazirmatn,
  counter strip with click-to-filter, pair cards with real SVG history
  charts, events timeline, Ctrl-K palette, login/setup views), served
  by the hub itself. Charts draw only from a new healer_history table
  (one point per status refresh; no point, no line — never faked).
  Tests green (hub/test_hub.py + hub/test_dashboard.py), JS syntax
  checked, CLI smoke run served the page.
- Phase 4 (live install on the two servers + live tests via the hub)
  — DONE 2026-10-26 evening: hub installed on the Iran host
  (`rahyaab-hub`, 127.0.0.1:8890), pair manag-netlen adopted (GRE,
  10.10.11.x, sweep scores), live tests through the hub API all
  passed (healer healthy, healer_status + connectivity jobs, history
  points, healer restart and recovery with a new pid). The throwaway
  test operator was deleted afterwards; the hub is setup-pending for
  the real operator. GRE still serving (0% loss, ~37 ms) and the
  foreign :443 listener untouched throughout.
- Phase 5 (private GitHub repo push + tag + final report) — pending
  push: local repo committed (`b300f50`, branch `main`, hub key
  verified absent) and runbook in `docs/phase5-runbook.md`; push
  waits on the user creating the empty private repo and adding the
  VM deploy key. The v1.0 tag waits for Phase 4's live tests.

## نصب روی سرور (install.sh)

نصب‌کننده یک‌خطی و زیبای رهیاب که روی خود سرور اجرا می‌شود
(با ایده از نصب‌کننده‌های BackPack و Kariz — منوی تعاملی، بدون داکر):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/irluca/Rahyaab/main/install.sh)
```

منو: نصب هاب (داشبورد) یا نود (بدون داشبورد)، فعال‌سازی BBR،
گواهی پنل (دامنه با Let's Encrypt و تمدید خودکار، آی‌پی با
self-signed و تایمر تمدید خودکار، یا گواهی آماده خودتان)،
به‌روزرسانی کد، نمایش وضعیت، حذف. مسیر غیرتعاملی هم دارد
(`--role hub --bbr --domain panel.example.com --email you@example.com`
یا `--role hub --bbr --ip-cert`) و با `--local` می‌شود از روی
فایل‌های محلی نصب کرد (تا وقتی ریپوی فاز ۵ پوش نشده).

نکته‌ها: اجرای دوباره امن است (دیتابیس و گواهی‌ها دست نمی‌خورند)؛
ساخت حساب اپراتور، افزودن سرورها، بنچمارک و پیکربندی نگهبان از
داخل داشبورد انجام می‌شود؛ اسکریپت به PasarGuard و به نگهبانِ در
حال اجرا دست نمی‌زند. توجه: Let's Encrypt برای آی‌پی خالی گواهی
نمی‌دهد، پس مسیر آی‌پی self-signed است (مرورگر بار اول هشدار می‌دهد).
