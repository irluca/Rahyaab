"""Offline tests for hub/healerctl.py: every command must carry the pair id,
so two pairs on one master never share a unit, heartbeat or switch file."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hub import healerctl  # noqa: E402
from hub.ssh import FakeExecutor  # noqa: E402

HEARTBEAT = '{"updated_at": "2099-01-01T00:00:00+00:00", "running": true}'


def test_status_uses_per_pair_unit_and_heartbeat():
    fake = FakeExecutor({
        "systemctl is-active": (0, "active\n", ""),
        "cat ": (0, HEARTBEAT, ""),
    })
    result = healerctl.status(fake, 3)
    assert any("best-tunnel-healer-p3" in c for c in fake.commands)
    assert any("healer-heartbeat-p3.json" in c for c in fake.commands)
    assert result["unit_active"] is True
    assert result["healthy"] is True


def test_start_stop_restart_use_per_pair_unit():
    fake = FakeExecutor()
    for action in (healerctl.start, healerctl.stop, healerctl.restart):
        assert action(fake, 2)["ok"] is True
    assert any("systemctl start best-tunnel-healer-p2" in c for c in fake.commands)
    assert any("systemctl stop best-tunnel-healer-p2" in c for c in fake.commands)
    assert any("systemctl restart best-tunnel-healer-p2" in c for c in fake.commands)


def test_request_switch_writes_per_pair_request():
    fake = FakeExecutor()
    assert healerctl.request_switch(fake, 2, "frp", "abc123")["ok"] is True
    assert any("switch-request-p2.json" in c for c in fake.commands)


def test_switch_result_reads_per_pair_result():
    fake = FakeExecutor({
        "cat ": (0, '{"request_id": "r1", "status": "done"}', ""),
    })
    assert healerctl.switch_result(fake, 2, "r1")["status"] == "done"
    assert any("switch-result-p2.json" in c for c in fake.commands)
    assert healerctl.switch_result(fake, 2, "other") is None
