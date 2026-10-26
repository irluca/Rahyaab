#!/usr/bin/env python3
"""Measure which candidate cover destinations REALITY can actually use - from both hosts.

REALITY's camouflage depends entirely on the cover being reachable and honest: the server proxies
every non-REALITY connection to `handshake.server:443`, and the client puts that same name in the
outer SNI. A cover that does not resolve, or answers with a default-vhost certificate for a
different name, produces a tunnel that is not camouflaged but still *deploys successfully* - the
failure only shows up when someone looks at the wire.

So membership in protocols.REALITY_COVER_POOL is decided here, by measurement, on the two hosts that
have to use it:

  FOREIGN (the dialer)  must resolve to IPv4, answer on 443, complete TLS 1.3, present a chain that
      verifies against public CAs, and host the SNI it was named with.
  IRAN (the side that sends the SNI) must be able to reach the same name. A destination that this
      country already blocks is not camouflage - traffic carrying a blocked SNI to an unblocked IP is
      precisely the anomaly a DPI looks for.

Addresses are never printed: only counts and verdicts. Nothing is deployed and nothing is configured;
this script only opens outbound TLS connections and reads certificates.

    set -a && . ~/.best_tunnel/live.env.txt && set +a && python3 orchestrator/vet_reality_covers.py

This file lives in the repository rather than in a scratch directory because the pool it decides is
shipped: `protocols.REALITY_COVER_POOL` is a load-bearing constant, and "membership is decided by
measurement" is only reproducible if the measuring tool and `validate_reality_cover`'s rules travel
with the code that uses the verdict. Its decision functions are unit-tested offline
(test_offline_suite.py); only `main()` touches the network, and it refuses unless live work was
explicitly enabled.
"""
import os
import re
import sys

import mock_ssh
import protocols
import storage

# Candidates, not conclusions. Anything that reads as plausible for a big-provider endpoint gets
# measured; the pool keeps only the ones that pass both sides. Order is alphabetical so the table is
# stable across runs.
CANDIDATES = [
    "artemis.microsoft.com",
    "cds.apple.com",
    "clients1.google.com",
    "cloudflare-dns.com",
    "devcloud.com",
    "dl.google.com",
    "download.developer.apple.com",
    "download.microsoft.com",
    "gateway.icloud.com",
    "github.com",
    "login.microsoftonline.com",
    "one.one.one.one",
    "secure.apple.com",
    "update.code.visualstudio.com",
    "www.apple.com",
    "www.cloudflare.com",
    "www.google.com",
    "www.microsoft.com",
]

def artifact_path() -> str:
    """Write the run beside the database, because `main()` already refuses to run when the database is
    inside the working tree - so that gate is what keeps this artifact out of the deliverable. A run
    records hostnames and certificate subjects; a scratch-directory default would have put it in the
    repository, which is the thing the gate exists to prevent.
    """
    return os.path.join(os.path.dirname(os.path.abspath(storage.DB_PATH)), "vet_reality_covers.out")


# One connection, everything read off it. The leaf is the first PEM block of -showcerts output; the
# SAN list and CN come from x509 rather than from s_client's prose, which differs between versions.
FACTS_CMD = """
name='__NAME__'
v4=$(getent ahostsv4 "$name" 2>/dev/null | awk '{print $1}' | sort -u | wc -l)
v6=$(getent ahostsv6 "$name" 2>/dev/null | awk '{print $1}' | sort -u | wc -l)
timeout 6 bash -c "exec 3<>/dev/tcp/$name/443" 2>/dev/null && tcp=OK || tcp=FAIL
raw=$(timeout 12 openssl s_client -connect "$name:443" -servername "$name" -alpn h2,http/1.1 -showcerts </dev/null 2>&1)
tls=$(printf '%s' "$raw" | grep -oE 'TLSv1\\.[0-9]' | head -1)
ver=$(printf '%s' "$raw" | grep -oE 'Verify return code: [0-9]+' | head -1 | grep -oE '[0-9]+$')
alpn=$(printf '%s' "$raw" | grep -oE 'ALPN protocol: [a-zA-Z0-9.-]+' | head -1 | awk '{print $3}')
pem=$(printf '%s' "$raw" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | awk '/BEGIN/{n++} n==1')
san=$(printf '%s' "$pem" | openssl x509 -noout -ext subjectAltName 2>/dev/null | tr -d ' \\n')
cn=$(printf '%s' "$pem" | openssl x509 -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\\([^,]*\\).*/\\1/p' | head -1 | tr -d ' ')
echo "FACTS name=$name v4=$v4 v6=$v6 tcp=$tcp tls=${tls:-none} verify=${ver:-none} alpn=${alpn:-none} cn=${cn:-none} san=$san"
"""


def scrub(text: str) -> str:
    """Mask every address-shaped token in anything this tool prints or writes.

    The patterns are storage's own rather than a local copy, and both families are applied without the
    private-range exemption storage keeps for persisted database rows: this output is prose, so a
    masked RFC 1918 token costs a reader nothing, while the v4-only pattern that used to live here passed
    a host's routable IPv6 through untouched - the same gap GLOBAL_IPV6_RE exists because round 062
    measured it in a live artifact.
    """
    text = text or ""
    text = storage.GLOBAL_IPV6_RE.sub("[addr]", text)
    return storage.IPV4_RE.sub("[addr]", text)


def spec(prefix: str) -> dict:
    return {"host": os.environ[f"{prefix}_HOST"], "port": 22,
            "user": os.environ.get(f"{prefix}_USER", "root"),
            "auth": {"type": "password", "value": os.environ[f"{prefix}_PASS"]}}


def run(r, cmd, **kw):
    code, out, err = r.run(cmd, check=False, **kw)
    return code, (out or "") + (err or "")


def parse(line: str) -> dict:
    m = re.search(r"FACTS name=(\S+).*san=(.*)$", line, re.S)
    if not m:
        return {}
    facts = {}
    for token in m.group(0).split():
        if "=" in token and token.split("=", 1)[0] in ("name", "v4", "v6", "tcp", "tls", "verify", "alpn", "cn"):
            k, v = token.split("=", 1)
            facts[k] = v
    facts["san"] = (m.group(2) or "").strip()
    return facts


def sni_hosted(name: str, san: str, cn: str) -> bool:
    """Does the certificate actually serve `name`? A wildcard covers one label, not a whole tree.

    The SAN string arrives exactly as openssl printed it, with its `X509v3 Subject Alternative
    Name:` label still attached and spaces squeezed out. Stripping that label with a greedy sed on
    `DNS:` was the first attempt here, and it kept only the *last* entry - a certificate whose real
    names came earlier in the list then looked like it hosted nothing, which is a wrong verdict in
    the direction that removes a good cover from the pool.
    """
    entries = re.findall(r"DNS:([^,]+)", san or "") + [cn or ""]
    for entry in (e.strip().lower() for e in entries):
        if not entry:
            continue
        if entry == name:
            return True
        if entry.startswith("*.") and name.endswith(entry[1:]) and name.count(".") == entry.count("."):
            return True
    return False


def to_facts(parsed: dict) -> dict:
    return {
        "resolves_v4": int(parsed.get("v4", "0") or 0) >= 1,
        "tcp_open": parsed.get("tcp") == "OK",
        "tls13": parsed.get("tls") == "TLSv1.3",
        "chain_verified": parsed.get("verify") == "0",
        "sni_hosted": sni_hosted(parsed.get("name", ""), parsed.get("san", ""), parsed.get("cn", "")),
    }


def main() -> int:
    if mock_ssh.is_dry_run_enabled():
        print("BEST_TUNNEL_DRY_RUN is not 0; refusing to touch live servers", file=sys.stderr)
        return 2
    if storage.db_is_inside_repo():
        print("BEST_TUNNEL_DB_PATH must point outside the repository", file=sys.stderr)
        return 2
    missing = [k for k in ("IR_HOST", "IR_PASS", "FR_HOST", "FR_PASS") if not os.environ.get(k)]
    if missing:
        print("live.env must be sourced (four host/pass keys are required)", file=sys.stderr)
        return 2

    # The failure this host pair produces most often is the second session not authenticating, and an
    # open that lands before the window whose finally closes it leaves the first session with no
    # reference that survives the raise. Same class as #72, same fix: opens go inside a guard that
    # closes what this call created and re-raises.
    ir = fr = None
    try:
        ir = mock_ssh.get_ssh_runner(spec("IR"), dry_run=False, host_role="iran")
        fr = mock_ssh.get_ssh_runner(spec("FR"), dry_run=False, host_role="foreign")
    except BaseException:
        for runner in (ir, fr):
            if runner is not None:
                runner.close()
        raise

    lines = []
    passing = []
    try:
        for label, r in (("FOREIGN", fr), ("IRAN", ir)):
            print(f"\n=== {label} (each cover measured from the host that has to use it) ===", flush=True)
            for name in sorted(CANDIDATES):
                code, out = run(r, FACTS_CMD.replace("__NAME__", name), timeout=60)
                parsed = parse(out or "")
                if not parsed:
                    print(f"{name:34} NO-OUTPUT rc={code} {scrub(out)[:80]}", flush=True)
                    lines.append(f"{label} {name}: probe produced nothing (rc={code})")
                    continue
                facts = to_facts(parsed)
                ok, failures = protocols.validate_reality_cover(name, facts)
                verdict = "PASS" if ok else "FAIL " + ",".join(failures)
                print(f"{name:34} v4={parsed['v4']} v6={parsed['v6']} tcp={parsed['tcp']} "
                      f"tls={parsed['tls']} verify={parsed['verify']} alpn={parsed['alpn']} "
                      f"cn={scrub(parsed.get('cn', ''))[:30]} -> {verdict}", flush=True)
                lines.append(f"{label} {name}: {verdict}")
                if ok:
                    passing.append((label, name))
    finally:
        ir.close()
        fr.close()

    both = sorted({n for l, n in passing if l == "FOREIGN"} & {n for l, n in passing if l == "IRAN"})
    print("\n===== pool decision =====")
    print(f"candidates measured: {len(CANDIDATES)}   pass on FOREIGN: "
          f"{len({n for l, n in passing if l == 'FOREIGN'})}   pass on IRAN: "
          f"{len({n for l, n in passing if l == 'IRAN'})}")
    print("pass on BOTH (these are the only ones that may enter REALITY_COVER_POOL):")
    for n in both:
        print("   " + n)
    print(f"currently shipped pool: {list(protocols.REALITY_COVER_POOL)}")
    print(f"pool members not confirmed by this run: "
          f"{[n for n in protocols.REALITY_COVER_POOL if n not in both]}")
    out_path = artifact_path()
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(scrub(l) for l in lines) + "\n"
                 + f"\npass-both: {both}\ncurrent-pool: {list(protocols.REALITY_COVER_POOL)}\n")
    print(f"saved: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
