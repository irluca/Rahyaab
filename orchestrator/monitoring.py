"""Next-generation monitoring signals (Phase 3): RST-injection TTL analysis
and tunnel saturation.

TunnelHealthChecker already answers "is the tunnel up and how fast is it".
Two failure shapes it cannot see:

1. **RST injection.** On filtered paths the middlebox often does not block a
   flow outright; it forges TCP RSTs (and sometimes DNS answers) into it. The
   tunnel then looks "flaky" rather than down, and every health signal wobbles
   without a culprit. Forged packets betray themselves by TTL: they are
   injected from a different network depth than the real peer, so replies from
   one "host" arrive with two distinct TTL clusters - in the reference panel's
   field data, real replies at ~48-52 and injected ones at ~62 or ~254. One
   cluster is a path; two clusters far apart are a fingerprint.

2. **Saturation.** A tunnel at 95% of its measured capacity is one burst from
   queueing collapse, while its latency still reads fine. Capacity-relative
   load - current throughput against the best throughput this pair/protocol
   has actually demonstrated - is the early warning, with the alert line at
   80% (the threshold the reference implementation uses).

Both signals are pure analysers over samples, so they are pinned offline;
the collectors below are thin read-only fetches.
"""

from __future__ import annotations

import re

SATURATION_ALERT_PCT = 80.0
_TTL_CLUSTER_GAP = 8
_TTL_ANOMALY_MIN_SHARE = 0.15
_TTL_ANOMALY_MIN_COUNT = 2

_TTL_RE = re.compile(r"ttl=(\d+)", re.IGNORECASE)


def parse_ttl_samples(ping_output: str) -> list[int]:
    """TTL values from per-reply ping lines (`... ttl=52 time=...`)."""
    return [int(m.group(1)) for m in _TTL_RE.finditer(ping_output or "")]


def ttl_verdict(samples: list[int]) -> dict:
    """Judge a TTL sample set. Stable single cluster: clean. A second cluster
    at least _TTL_CLUSTER_GAP away, carrying a real share of the samples:
    injection suspected. Anything thinner stays 'inconclusive' - a detector
    that cries wolf on jitter would be muted within a week, and correctly."""
    if len(samples) < 5:
        return {"state": "unknown", "dominant_ttl": None, "anomaly_ttls": [],
                "note": "too few samples to judge the path"}
    dominant = max(set(samples), key=samples.count)
    anomalies = [t for t in samples if abs(t - dominant) >= _TTL_CLUSTER_GAP]
    share = len(anomalies) / len(samples)
    if len(anomalies) >= _TTL_ANOMALY_MIN_COUNT and share >= _TTL_ANOMALY_MIN_SHARE:
        return {"state": "injection_suspected", "dominant_ttl": dominant,
                "anomaly_ttls": sorted(set(anomalies)),
                "note": f"replies arrive with two TTL families: real path ~{dominant} "
                        f"and {sorted(set(anomalies))} in {share:.0%} of samples - "
                        "the signature of forged RST/answer injection on this path"}
    if all(abs(t - dominant) <= 2 for t in samples):
        return {"state": "clean", "dominant_ttl": dominant, "anomaly_ttls": [],
                "note": f"single stable TTL family ~{dominant}"}
    return {"state": "inconclusive", "dominant_ttl": dominant,
            "anomaly_ttls": sorted(set(anomalies)),
            "note": "TTL scatter without a distinct second family; could be a "
                    "route change - resample before concluding"}


def collect_ttl_samples(runner, peer_ip: str, count: int = 20) -> list[int]:
    _rc, out, _ = runner.run(f"ping -c {count} -i 0.2 -W 2 {peer_ip}",
                             check=False, best_effort=True, timeout=30, retryable=True)
    return parse_ttl_samples(out)


def saturation_pct(bytes_delta: float, window_s: float, capacity_mbps) -> float | None:
    """Load as a percentage of demonstrated capacity. Unknown capacity stays
    None: a saturation number computed against a guessed capacity would be a
    confident lie in exactly the direction that pages people at night."""
    if not capacity_mbps or capacity_mbps <= 0 or window_s <= 0:
        return None
    mbps = (bytes_delta * 8.0 / window_s) / 1e6
    return round(100.0 * mbps / capacity_mbps, 1)


def saturation_state(pct) -> str:
    if pct is None:
        return "unknown"
    return "high" if pct >= SATURATION_ALERT_PCT else "ok"


def read_iface_counters(runner, iface: str) -> dict:
    """One read of an interface's byte counters; two reads a window apart are
    the saturation input. Values that cannot be read stay None."""
    cmd = (f"cat /sys/class/net/{iface}/statistics/rx_bytes "
           f"/sys/class/net/{iface}/statistics/tx_bytes 2>/dev/null")
    _rc, out, _ = runner.run(cmd, check=False, best_effort=True,
                             timeout=20, retryable=True)
    values = []
    for line in (out or "").splitlines():
        try:
            values.append(int(line.strip()))
        except ValueError:
            values.append(None)
    while len(values) < 2:
        values.append(None)
    return {"rx_bytes": values[0], "tx_bytes": values[1]}
