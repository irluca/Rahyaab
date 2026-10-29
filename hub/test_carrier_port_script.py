"""Tests for the carrier port-change script itself (hub/jobs.py).

The script runs on the healer host, so these tests run its real
text against a stub `iptables` and a stub reapply script in temp
dirs: no SSH, no live hosts, no root. The stub iptables keeps a
rule file whose lines are `table|chain|spec`, and answers -C/-D/
-A/-I the way the kernel answers them, including the duplicate
rules repeated deploys have left on live hosts.
"""

import json
import os
import sqlite3
import subprocess
import sys

import pytest

from hub import jobs

MANIFEST = """\
@kind best-tunnel-firewall-manifest-v1
@pair prod-1-GRE
@role iran
@iface grep1
@comment best-tunnel-1-prod-GRE
S|net.ipv4.ip_forward=1
R|filter|INPUT|I|1|-p 47 -s 203.0.113.20/32 -m comment --comment best-tunnel-1-prod-GRE -j ACCEPT
R|nat|PREROUTING|A|0|-p tcp ! -i grep1 --dport 443 -m comment --comment best-tunnel-1-prod-GRE -j DNAT --to-destination 10.10.11.2:443
R|nat|PREROUTING|A|0|-p udp ! -i grep1 --dport 443 -m comment --comment best-tunnel-1-prod-GRE -j DNAT --to-destination 10.10.11.2:443
R|filter|FORWARD|I|1|-p tcp -d 10.10.11.2 --dport 443 -m comment --comment best-tunnel-1-prod-GRE -j ACCEPT
R|filter|FORWARD|I|1|-p udp -d 10.10.11.2 --dport 443 -m comment --comment best-tunnel-1-prod-GRE -j ACCEPT
R|filter|FORWARD|I|1|-m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment best-tunnel-1-prod-GRE -j ACCEPT
R|mangle|FORWARD|A|0|-p tcp --tcp-flags SYN,RST SYN -m comment --comment best-tunnel-1-prod-GRE -j TCPMSS --clamp-mss-to-pmtu
R|nat|POSTROUTING|A|0|-d 10.10.11.2 ! -s 10.10.11.1 -m comment --comment best-tunnel-1-prod-GRE -j MASQUERADE
"""

IPTABLES_STUB = """\
#!/bin/bash
# Stub iptables: a rule file of "table|chain|spec" lines.
RULES="$BT_RULES_FILE"
table="filter"; op=""; chain=""; spec=()
while [ $# -gt 0 ]; do
  case "$1" in
    -t) table="$2"; shift 2;;
    -C|-D|-A|-I) op="$1"; chain="$2"; shift 2
      if [ "$op" = "-I" ]; then shift; fi
      spec=("$@"); break;;
    *) shift;;
  esac
done
key="$table|$chain|${spec[*]}"
touch "$RULES"
case "$op" in
  -C) grep -Fxq "$key" "$RULES";;
  -D) if grep -Fxq "$key" "$RULES"; then
        grep -Fxv "$key" "$RULES" > "$RULES.tmp" && mv "$RULES.tmp" "$RULES"
      else exit 1; fi;;
  -A|-I) echo "$key" >> "$RULES";;
  *) exit 2;;
esac
"""

REAPPLY_STUB = """\
#!/bin/bash
# Stub of best-tunnel-fw-reapply.sh: install every manifest R row
# that -C does not already find, nothing else.
MAN="$1"
while IFS= read -r line; do
  case "$line" in
    R\\|*)
      IFS='|' read -r _r _t _c _v _p _spec <<<"$line"
      set -f; args=(); for w in $_spec; do args+=("$w"); done; set +f
      targs=(); [ "$_t" = "filter" ] || targs=(-t "$_t")
      if [ "$_v" = "I" ] && [ "$_p" != "0" ]; then
        iptables "${targs[@]}" -C "$_c" "${args[@]}" >/dev/null 2>&1 \\
          || iptables "${targs[@]}" -I "$_c" "$_p" "${args[@]}" >/dev/null 2>&1
      else
        iptables "${targs[@]}" -C "$_c" "${args[@]}" >/dev/null 2>&1 \\
          || iptables "${targs[@]}" -A "$_c" "${args[@]}" >/dev/null 2>&1
      fi
      ;;
  esac
done < "$MAN"
"""


@pytest.fixture()
def stage(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    ipt = bin_dir / "iptables"
    ipt.write_text(IPTABLES_STUB)
    ipt.chmod(0o755)
    reapply = bin_dir / "reapply.sh"
    reapply.write_text(REAPPLY_STUB)
    reapply.chmod(0o755)
    db_dir = tmp_path / "db"
    cfg_dir = tmp_path / "cfg"
    fw_dir = tmp_path / "fw"
    for d in (db_dir, cfg_dir, fw_dir):
        d.mkdir()
    conn = sqlite3.connect(db_dir / "healer-p1.db")
    conn.execute("CREATE TABLE pairs (id INTEGER PRIMARY KEY, frontend_port INTEGER)")
    conn.execute("INSERT INTO pairs VALUES (1, 443)")
    conn.commit()
    conn.close()
    (cfg_dir / "healer-p1.json").write_text(
        json.dumps({"frontend_port": 443, "pair_id": 1}))
    (fw_dir / "best-tunnel-prod-p1-gre-fw.rules").write_text(MANIFEST)
    rules_file = tmp_path / "rules.txt"
    # The live host's rules, including a duplicated DNAT row.
    rules = []
    for line in MANIFEST.splitlines():
        if not line.startswith("R|"):
            continue
        _, table, chain, _v, _p, spec = line.split("|", 5)
        rules.append("%s|%s|%s" % (table, chain, spec))
    tcp_dnat = [r for r in rules if "DNAT" in r and "tcp" in r][0]
    rules.append(tcp_dnat)  # duplicate, as seen live
    rules_file.write_text("\n".join(rules) + "\n")
    env = dict(os.environ)
    env.update({
        "BT_HEALER_DB_DIR": str(db_dir),
        "BT_HEALER_CFG_DIR": str(cfg_dir),
        "BT_FW_DIR": str(fw_dir),
        "BT_IPTABLES": str(ipt),
        "BT_FW_REAPPLY": str(reapply),
        "BT_RULES_FILE": str(rules_file),
        "PATH": str(bin_dir) + ":" + env["PATH"],
    })
    return {"env": env, "db_dir": db_dir, "cfg_dir": cfg_dir,
            "fw_dir": fw_dir, "rules_file": rules_file}


def _run_script(stage, *argv):
    return subprocess.run(
        [sys.executable, "-c", jobs._CARRIER_PORT_SCRIPT] + list(argv),
        capture_output=True, text=True, env=stage["env"])


def _rules(stage):
    return stage["rules_file"].read_text().splitlines()


def _db_port(stage):
    conn = sqlite3.connect(stage["db_dir"] / "healer-p1.db")
    row = conn.execute(
        "SELECT frontend_port FROM pairs WHERE id = 1").fetchone()
    conn.close()
    return row[0]


def _cfg_port(stage):
    return json.loads(
        (stage["cfg_dir"] / "healer-p1.json").read_text())["frontend_port"]


def _manifest(stage):
    return (stage["fw_dir"] / "best-tunnel-prod-p1-gre-fw.rules").read_text()


def test_moves_dnat_with_the_port(stage):
    res = _run_script(stage, "1", "443", "21232")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "ok" in res.stdout
    manifest = _manifest(stage)
    assert "--dport 21232" in manifest
    assert "--to-destination 10.10.11.2:21232" in manifest
    assert "--dport 443" not in manifest
    assert "10.10.11.2:443" not in manifest
    rules = _rules(stage)
    assert any("21232" in r and "DNAT" in r for r in rules)
    assert not any("443" in r and ("DNAT" in r or "dport 443" in r)
                   for r in rules)
    # Port-independent rows survive: protocol accept, clamp, masquerade.
    assert any("-p 47" in r for r in rules)
    assert any("MASQUERADE" in r for r in rules)
    assert any("ESTABLISHED" in r for r in rules)
    # No duplicate DNAT rows remain either.
    dnat = [r for r in rules if "DNAT" in r]
    assert len(dnat) == len(set(dnat)) == 2  # tcp + udp
    assert _db_port(stage) == 21232
    assert _cfg_port(stage) == 21232


def test_rerun_is_idempotent(stage):
    assert _run_script(stage, "1", "443", "21232").returncode == 0
    res = _run_script(stage, "1", "443", "21232")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "ok" in res.stdout
    assert _db_port(stage) == 21232
    assert _cfg_port(stage) == 21232


def test_missing_manifest_fails_without_touching_records(stage):
    (stage["fw_dir"] / "best-tunnel-prod-p1-gre-fw.rules").unlink()
    res = _run_script(stage, "1", "443", "21232")
    assert res.returncode != 0
    assert _db_port(stage) == 443
    assert _cfg_port(stage) == 443
