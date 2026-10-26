#!/usr/bin/env python3
"""Phase 6 fleet surface: the data behind the fleet map, the live
per-tunnel cards, the Health Center, and the محک wizard's reasons.

This module is deliberately dashboard-free: it reads storage and runs
the product's own analysers (health check, preflight, TTL verdict), so
its builders are testable offline and the dashboard only renders what
they return. Nothing here opens a host session on its own - the
diagnostics entry takes runners the caller opened, under the caller's
host lock.
"""
import time

import storage
import failover
import monitoring
import preflight


def fleet_overview(now: float = None) -> list[dict]:
    """One card per pair: current state, 24 h uptime, failover count,
    and any live quarantine. A page refresh reads this from the
    database only - it never touches a host.
    """
    now = now or time.time()
    out = []
    for p in storage.get_pairs():
        pid = p["id"]
        hist = storage.get_health_history(pid, limit=1)
        up24 = storage.health_uptime_summary(pid, since_ts=now - 86400)
        out.append({
            "id": pid,
            "name": p.get("name", ""),
            "status": (p.get("status") or "").upper(),
            "active_tunnel": (p.get("active_tunnel") or "").strip(),
            "mode": (p.get("mode") or "manual").strip().lower(),
            "auto_protocol": (p.get("auto_protocol") or "").strip(),
            "underlay_carrier": (p.get("underlay_carrier") or "").strip(),
            "last_verdict": hist[0]["verdict"] if hist else None,
            "last_latency_ms": hist[0]["latency_ms"] if hist else None,
            "last_loss_pct": hist[0]["loss_pct"] if hist else None,
            "uptime_24h_pct": up24["uptime_pct"],
            "outages_24h": up24["outages"],
            "failovers": storage.count_failovers(pid),
            "quarantine": storage.get_quarantine(pid),
        })
    return out


def persian_score_reasons(row: dict, profile: str = "balanced") -> list[str]:
    """Plain-Persian reasons for a benchmark row's score.

    The wizard shows a number; a number without a reason is a verdict
    the operator cannot act on. Each reason names one measured component
    and what it means, in the user's own plain language - no component
    jargon, no English scorespeak. An empty breakdown means "everything
    measured fine", and that is said too.
    """
    bd = row.get("breakdown") or {}
    reasons = []
    score = float(row.get("score", 0.0) or 0.0)
    if score >= 80:
        reasons.append("عملکرد کلی عالی است")
    elif score >= 60:
        reasons.append("عملکرد کلی خوب است، ولی جای بهتر شدن دارد")
    else:
        reasons.append("عملکرد کلی ضعیف است")
    s_lat = bd.get("s_lat")
    if s_lat is not None and s_lat < 0.7:
        reasons.append("تاخیرش نسبت به مسیر پایه بالاست")
    s_jit = bd.get("s_jit")
    if s_jit is not None and s_jit < 0.7:
        reasons.append("نوسان تاخیر (جیتر) زیاد است؛ برای بازی و تماس حساس است")
    s_bulk = bd.get("s_bulk")
    if s_bulk is not None and s_bulk < 0.7:
        reasons.append("ظرفیت انتقالش محدود است؛ برای دانلود سنگین کم می‌آورد")
    s_stab = bd.get("s_stab")
    if s_stab is not None and s_stab < 0.9:
        reasons.append("در تست پایداری قطع و وصل داشته است")
    if (bd.get("loss_penalty") or 0) > 0:
        reasons.append("افت بسته دارد")
    tp = row.get("throughput_mbps")
    if tp:
        reasons.append(f"سرعت اندازه‌گیری‌شده: {tp} مگابیت بر ثانیه")
    if row.get("disqualified"):
        reasons.append("این اندازه‌گیری کامل نشد و در رتبه‌بندی حساب نمی‌شود")
    if profile and profile != "balanced":
        reasons.append(f"با پروفایل {profile} سنجیده شده است")
    return reasons


def diagnose_pair(ir_runner, fr_runner, pair: dict, active: str) -> dict:
    """One diagnostics report: health verdict, preflight findings, and
    the TTL injection verdict, plus the pair's quarantine and auto state.

    Read-only except for the probe script the health check installs
    (the same install the monitor already performs on every pass).

    Phase 6 remainder (dual-endpoint panel): the report also carries
    the FULL preflight structure under "preflight" - per-host facts and
    both path directions - not just the flat findings list. The panel
    renders Iran-side and foreign-side telemetry side by side from it,
    so the operator can see which end is sick instead of reading a
    JSON dump. "preflight_findings" stays for compatibility.
    """
    pid = pair.get("id", 1)
    health = failover.TunnelHealthChecker.check_health(
        ir_runner, fr_runner, pair, active, dry_run=False)
    try:
        pf = preflight.build_preflight_report(
            ir_runner, fr_runner,
            pair["iran"]["host"], pair["foreign"]["host"])
        pf_findings = pf.get("findings", [])
    except Exception as exc:
        pf = {}
        pf_findings = [f"preflight failed: {exc}"]
    try:
        peer = (pair["foreign"].get("dial_host")
                or pair["foreign"]["host"])
        ttl = monitoring.ttl_verdict(
            monitoring.collect_ttl_samples(ir_runner, peer))
    except Exception as exc:
        ttl = {"state": "unknown", "note": f"TTL sampling failed: {exc}"}
    return {
        "pair_id": pid,
        "protocol": active,
        "health": health._asdict(),
        "preflight_findings": pf_findings,
        "preflight": pf,
        "ttl": ttl,
        "quarantine": storage.get_quarantine(pid),
        "mode": (pair.get("mode") or "manual"),
        "auto_protocol": (pair.get("auto_protocol") or ""),
    }
