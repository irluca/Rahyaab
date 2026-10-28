"""Per-pair healer paths.

One healer instance owns one pair, so the unit, config, key, database,
heartbeat and switch files all carry the pair id. Two pairs on one master
never share a file, and a dashboard switch for pair N can only ever be
read by pair N's healer.

The pre-multi-node single-instance paths (best-tunnel-healer.service,
healer.json, healer.db, healer-heartbeat.json, switch-request.json) are
legacy: new code never reads them. A pair whose healer predates this
scheme needs its healer reinstalled before dashboard status and switch
work for it again; its auto-healing keeps running on the legacy unit
until then.

hub/healerctl.py mirrors this scheme (it cannot import this module);
keep the two in sync.
"""


def unit_name(pair_id: int) -> str:
    return "best-tunnel-healer-p%d" % int(pair_id)


def unit_path(pair_id: int) -> str:
    return "/etc/systemd/system/%s.service" % unit_name(pair_id)


def config_path(pair_id: int) -> str:
    return "/etc/best-tunnel/healer-p%d.json" % int(pair_id)


def key_path(pair_id: int) -> str:
    return "/etc/best-tunnel/healer-p%d_key" % int(pair_id)


def db_path(pair_id: int) -> str:
    return "/var/lib/best-tunnel/healer-p%d.db" % int(pair_id)


def heartbeat_path(pair_id: int) -> str:
    return "/var/lib/best-tunnel/healer-heartbeat-p%d.json" % int(pair_id)


def switch_request_path(pair_id: int) -> str:
    return "/var/lib/best-tunnel/switch-request-p%d.json" % int(pair_id)


def switch_result_path(pair_id: int) -> str:
    return "/var/lib/best-tunnel/switch-result-p%d.json" % int(pair_id)
