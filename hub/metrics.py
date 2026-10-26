"""Real metrics for the rich dashboard — nothing here is estimated.

Server metrics come from /proc and df on the fleet server itself.
Pair latency is a real ping over the tunnel's inner addresses, and
pair throughput is the real byte counters of the carrier interface
(/sys/class/net/<iface>/statistics/*_bytes), differenced between
samples by the store. A server that cannot be read, or a pair whose
carrier interface is gone, simply yields no point — the dashboard
says so instead of drawing an invented line.
"""

from __future__ import annotations

import re

SERVER_COMMAND = (
    "echo LOAD $(cut -d' ' -f1 /proc/loadavg); "
    "free | awk '/^Mem:/{printf \"MEM %.1f\\n\", 100*$3/$2}'; "
    "df / | awk 'NR==2{print \"DISK \" $5}'; "
    "awk '{print \"UP \" $1}' /proc/uptime"
)

CARRIER_IFACE = {"GRE": "grep1", "ESP": "espp1"}


def parse_server_metrics(output: str) -> dict:
    data: dict = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "LOAD":
            data["load1"] = float(parts[1])
        elif len(parts) >= 2 and parts[0] == "MEM":
            data["mem_used_pct"] = float(parts[1])
        elif len(parts) >= 2 and parts[0] == "DISK":
            data["disk_used_pct"] = float(parts[1].rstrip("%"))
        elif len(parts) >= 2 and parts[0] == "UP":
            data["uptime_seconds"] = float(parts[1])
    if not data:
        raise ValueError("no server metrics parsed")
    return data


def parse_ping_avg(output: str) -> float | None:
    m = re.search(r"rtt [^=]*= [\d.]+/([\d.]+)/", output)
    return float(m.group(1)) if m else None


def collect_server(executor) -> dict:
    rc, out, err = executor.run(SERVER_COMMAND, timeout=30)
    if rc != 0:
        raise RuntimeError(f"server metrics command failed: {err.strip()}")
    return parse_server_metrics(out)


def collect_pair(executor, pair: dict) -> dict:
    data: dict = {"latency_ms": None, "rx_bytes": None, "tx_bytes": None}
    inner = pair.get("inner_foreign")
    if inner:
        rc, out, _ = executor.run(f"ping -c 2 -W 2 {inner}", timeout=30)
        if rc == 0:
            data["latency_ms"] = parse_ping_avg(out)
    iface = CARRIER_IFACE.get(pair.get("current_protocol") or "")
    if iface:
        rc, out, _ = executor.run(
            f"cat /sys/class/net/{iface}/statistics/rx_bytes "
            f"/sys/class/net/{iface}/statistics/tx_bytes", timeout=20)
        if rc == 0:
            nums = out.split()
            if len(nums) >= 2:
                data["rx_bytes"] = int(nums[0])
                data["tx_bytes"] = int(nums[1])
    return data
