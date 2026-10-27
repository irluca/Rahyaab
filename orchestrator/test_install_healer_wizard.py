"""Offline tests for the wizard-side healer install adapter.

install()'s hosts are faked with an in-memory filesystem; no network,
no real servers, no systemd. The point is the wiring: key creation
flow, authorisation, config + unit contents, and the start check.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

import install_healer  # noqa: E402
import install_healer_wizard  # noqa: E402

FAKE_PUB = "ssh-ed25519 AAAAWIZARDTEST best-tunnel-healer"
HEARTBEAT = json.dumps({"active_tunnel": "GRE", "verdicts": {"1": "HEALTHY"}})


class FakeHost:
    def __init__(self, label):
        self.label = label
        self.fs = {}
        self.exec_log = []

    def exec(self, cmd, timeout=120, check=True):
        self.exec_log.append(cmd)
        if cmd.startswith("test -e "):
            path = cmd[len("test -e "):].strip()
            return (0 if path in self.fs else 1), "", ""
        if "ssh-keygen" in cmd:
            self.fs[install_healer.KEY_PATH] = "private"
            self.fs[install_healer.KEY_PATH + ".pub"] = FAKE_PUB
            return 0, "", ""
        if cmd.strip() == "echo $HOME":
            return 0, "/root\n", ""
        if "systemctl is-active" in cmd:
            return 0, "active\n", ""
        if "--once" in cmd:
            return 0, "once-ok", ""
        return 0, "", ""

    def read_file(self, path):
        return self.fs.get(path, "")

    def write_file(self, path, content, mode=0o600):
        self.fs[path] = content

    def close(self):
        pass


@pytest.fixture
def fakes(monkeypatch):
    made = {}

    def factory(host, port, user, key_path, known_hosts="/root/.ssh/known_hosts"):
        fake = FakeHost(host)
        made[host] = fake
        return fake

    monkeypatch.setattr(install_healer_wizard, "KeyHost", factory)
    return made


def test_wizard_install_fresh_key(fakes):
    result = install_healer_wizard.wizard_install(
        "203.0.113.10", "203.0.113.20", pair_id=1, pair_name="wizard-pair",
        frontend_port=443, active_tunnel="GRE", candidate_scores={"GRE": 99.9},
        hub_key_path="/etc/rahyaab/hub_key",
        code_dir=os.path.dirname(os.path.abspath(__file__)),
        settle_seconds=0)
    assert "healer keypair created on Iran host" in result["steps"]
    assert "healer public key authorised on foreign host" in result["steps"]
    assert result["active"] == "active"
    iran = fakes["203.0.113.10"]
    foreign = fakes["203.0.113.20"]
    cfg = json.loads(iran.fs[install_healer.CONFIG_PATH])
    assert cfg["pair_id"] == 1
    assert cfg["active_tunnel"] == "GRE"
    assert cfg["candidate_scores"] == {"GRE": 99.9}
    assert cfg["key_path"] == install_healer.KEY_PATH
    assert "telegram" not in cfg
    assert install_healer.UNIT_PATH in iran.fs
    assert FAKE_PUB in foreign.fs["/root/.ssh/authorized_keys"]


def test_wizard_install_existing_key_skips_keygen(fakes):
    # Pre-seed the Iran fake's keypair and the foreign authorisation by
    # patching the factory to pre-fill after construction.
    orig = install_healer_wizard.KeyHost

    def seeding_factory(host, port, user, key_path, known_hosts="/root/.ssh/known_hosts"):
        fake = orig(host, port, user, key_path, known_hosts)
        if host == "203.0.113.10":
            fake.fs[install_healer.KEY_PATH] = "private"
            fake.fs[install_healer.KEY_PATH + ".pub"] = FAKE_PUB
        if host == "203.0.113.20":
            fake.fs["/root/.ssh/authorized_keys"] = FAKE_PUB + "\n"
        return fake

    import install_healer_wizard as wiz
    wiz.KeyHost = seeding_factory
    result = wiz.wizard_install(
        "203.0.113.10", "203.0.113.20", pair_id=1, pair_name="wizard-pair",
        frontend_port=443, active_tunnel="GRE", candidate_scores={"GRE": 99.9},
        hub_key_path="/etc/rahyaab/hub_key",
        code_dir=os.path.dirname(os.path.abspath(__file__)),
        settle_seconds=0)
    assert "healer keypair already present on Iran host" in result["steps"]
    assert "healer public key already authorised on foreign host" in result["steps"]
    iran = fakes["203.0.113.10"]
    assert not any("ssh-keygen" in c for c in iran.exec_log)
