"""Telegram alerts for Tunnel Studio Pro (Phase 5).

Scope, stated plainly: this module reports the tunnel's own events and
nothing else. It never reads, writes, or talks to the PasarGuard panel,
and it never sends anything but the event text below.

What alerts, and what does not - the noise rule the Phase 5 acceptance
demands ("no alert for ordinary/noise events"):
  * ALERT on a verdict TRANSITION into FAILOVER_EXECUTED (healed by a
    switchover), FAILOVER_ATTEMPTED (heal tried and failed),
    HEAL_DEFERRED (outage persists after one automatic attempt),
    OBSERVE_DOWN (confirmed outage, auto-heal off, nobody acting),
    DEGRADED (quality below the product's own SLA).
  * ALERT on recovery into HEALTHY, but only when the previous verdict
    was a down-family verdict the operator was already told about
    (OBSERVE_DOWN, HEAL_DEFERRED, FAILOVER_ATTEMPTED,
    FAILOVER_EXECUTED). A blip that never alerted (DOWN_PENDING, or a
    DEGRADED that cleared) earns no "recovered" message: alerting the
    closure of something never opened is noise.
  * NEVER on DOWN_PENDING (unconfirmed: the streak is still building,
    and alerting it would spam every confirmation window), on
    NO_BACKEND / AMBIGUOUS_DOWN (an absent application behind the
    tunnel, not a tunnel event), on SKIP/LOCK passes (no sample at
    all), or on a repeated verdict (the monitor's _note already fires
    only on change; the alerter trusts that and additionally checks
    the transition itself).
  * Saturation "high" is a dashboard warning, not a Telegram alert:
    it is a per-pass measurement, and pushing it would spam every
    60 s pass of a busy hour. A DEGRADED alert's text mentions the
    saturation reading when one rode the same pass.

Configuration follows the product's existing pattern (dashboard.py,
failover_monitor.py): plain environment variables, injectable mapping
for tests. The bot token and chat id arrive the way every other
operator secret does - exported from the operator's live.env.txt
before the dashboard starts, never written into the repo, the DB, or
a message. Any error text is redacted before it is logged, so a
failed send can never leak the token into a log line.
"""

import datetime
import json
import os
import urllib.error
import urllib.request

BOT_TOKEN_ENV = "BEST_TUNNEL_TELEGRAM_BOT_TOKEN"
CHAT_ID_ENV = "BEST_TUNNEL_TELEGRAM_CHAT_ID"

# Verdicts that open an incident the operator must hear about.
ALERT_VERDICTS = ("FAILOVER_EXECUTED", "FAILOVER_ATTEMPTED",
                  "HEAL_DEFERRED", "OBSERVE_DOWN", "DEGRADED")
# Verdicts whose HEALTHY transition closes an incident that was opened.
DOWN_FAMILY = ("OBSERVE_DOWN", "HEAL_DEFERRED", "FAILOVER_ATTEMPTED",
               "FAILOVER_EXECUTED")

_PERSIAN_VERDICT = {
    "FAILOVER_EXECUTED": "هیل شد (سوییچ پروتکل انجام شد)",
    "FAILOVER_ATTEMPTED": "تلاش هیل ناموفق بود",
    "HEAL_DEFERRED": "قطعی ادامه دارد (یک بار خودکار تلاش شد)",
    "OBSERVE_DOWN": "قطعی تأیید شده (هیل خودکار خاموش است)",
    "DEGRADED": "کیفیت پایین‌تر از حد مجاز",
    "HEALTHY": "برگشت به حالت سالم",
}


def _redact(text, token):
    if token and token in text:
        return text.replace(token, "***")
    return text


class TelegramAlerter:
    """Sends alert texts to one Telegram chat via the Bot API.

    `sender` is injectable: tests pass a recorder instead of the real
    HTTP call, so no test ever touches the network or a real token.
    """

    def __init__(self, bot_token, chat_id, sender=None):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.sender = sender or self._send_http
        self.last_error = ""

    @classmethod
    def from_env(cls, env=None):
        source = os.environ if env is None else env
        return cls(source.get(BOT_TOKEN_ENV, ""),
                   source.get(CHAT_ID_ENV, ""))

    @property
    def configured(self):
        return bool(self.bot_token and self.chat_id)

    def _send_http(self, text):
        url = ("https://api.telegram.org/bot{}/sendMessage"
               .format(self.bot_token))
        payload = json.dumps({"chat_id": self.chat_id, "text": text,
                              "disable_web_page_preview": True}).encode("utf-8")
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp.read()
            return True
        except Exception as ex:  # noqa: BLE001 - redacted, then reported
            self.last_error = _redact(str(ex), self.bot_token)
            return False

    def send(self, text):
        """Send one alert. Returns False (never raises) when unconfigured
        or when the HTTP call fails, so a notification failure can never
        break a monitor pass."""
        if not self.configured:
            return False
        if self.bot_token in text:
            # A caller bug must not turn the token into message content.
            return False
        try:
            return bool(self.sender(text))
        except Exception as ex:  # noqa: BLE001 - redacted, then reported
            self.last_error = _redact(str(ex), self.bot_token)
            return False


_HEADER_EMOJI = {
    "FAILOVER_EXECUTED": "🔄",
    "FAILOVER_ATTEMPTED": "🚨",
    "HEAL_DEFERRED": "⚠️",
    "OBSERVE_DOWN": "🚨",
    "DEGRADED": "📉",
    "HEALTHY": "✅",
}


def alert_for_transition(previous, verdict, pair_id, protocol, detail="",
                         saturation_alert="", iran_host="",
                         foreign_host=""):
    """Build the alert text for a monitor verdict transition, or return
    "" when this transition earns no alert (see the module docstring).

    `previous` is the verdict before this pass ("" when none recorded).
    The caller owns the transition detection; this function owns the
    policy of which transitions are worth a push message.

    Format (operator feedback, 2026-10-24): Persian, one fact per line,
    emoji-labelled, so Persian and the engine's English reason never
    mix inside one line. The two server addresses ride every alert:
    with several tunnels the pair id alone does not say which servers
    are sick. Hosts are the pair's own addresses as the operator
    entered them (the monitor passes them through); when a caller has
    none, the lines are omitted rather than guessed.
    """
    if verdict in ALERT_VERDICTS and verdict != previous:
        lines = ["{} هشدار تانل".format(_HEADER_EMOJI[verdict]),
                 "📌 جفت: #{}".format(pair_id),
                 "🔌 پروتکل: {}".format(protocol)]
        if iran_host:
            lines.append("🖥️ سرور ایران: {}".format(iran_host))
        if foreign_host:
            lines.append("🌍 سرور خارج: {}".format(foreign_host))
        lines.append("📋 وضعیت: {}".format(_PERSIAN_VERDICT[verdict]))
        if detail:
            lines.append("📝 دلیل: {}".format(detail))
        if saturation_alert:
            lines.append("🌡️ اشباع: {}".format(saturation_alert))
        return "\n".join(lines)
    if verdict == "HEALTHY" and previous in DOWN_FAMILY:
        lines = ["✅ هشدار تانل",
                 "📌 جفت: #{}".format(pair_id),
                 "🔌 پروتکل: {}".format(protocol)]
        if iran_host:
            lines.append("🖥️ سرور ایران: {}".format(iran_host))
        if foreign_host:
            lines.append("🌍 سرور خارج: {}".format(foreign_host))
        lines.append("📋 وضعیت: {}".format(_PERSIAN_VERDICT["HEALTHY"]))
        return "\n".join(lines)
    return ""


def build_daily_summary(pairs_health):
    """One-day summary text from per-pair health rows.

    `pairs_health` is a list of dicts with pair_id, protocol, uptime_pct
    (0-100 as storage.health_uptime_summary reports it, or None),
    outages_24h, failovers. Kept separate from the sender so the text
    is unit-testable without a token.
    """
    lines = ["📊 گزارش روزانه سلامت تانل‌ها"]
    for row in pairs_health:
        uptime = row.get("uptime_pct")
        uptime_txt = "—" if uptime is None else "{:.0f}%".format(uptime)
        lines.append("📌 جفت #{} — پروتکل: {}"
                     .format(row.get("pair_id"), row.get("protocol", "?")))
        if row.get("iran_host"):
            lines.append("🖥️ سرور ایران: {}".format(row["iran_host"]))
        if row.get("foreign_host"):
            lines.append("🌍 سرور خارج: {}".format(row["foreign_host"]))
        lines.append("📈 آپتایم ۲۴ ساعته: {} | قطعی: {} | سوییچ: {}"
                     .format(uptime_txt, row.get("outages_24h", 0),
                             row.get("failovers", 0)))
    return "\n".join(lines)
