"""Offline checks for the Phase 4 installer (no SSH, no servers)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hub.install_hub import adoption_script, unit_file


def test_unit_binds_localhost_only():
    unit = unit_file()
    assert "--host 127.0.0.1 --port 8890" in unit
    assert "0.0.0.0" not in unit


def test_adoption_script_adopts_live_pair_and_compiles():
    script = adoption_script("94.184.23.90", "217.11.164.209")
    compile(script, "adopt.py", "exec")
    assert "manag-netlen" in script
    assert "GRE" in script and "10.10.11.1" in script and "10.10.11.2" in script
    assert "99.96" in script  # sweep median for GRE
    assert "bot_token" not in script
    assert "password" not in script.lower()
    assert "PasarGuard" not in script
