#!/usr/bin/env python3
"""Protocol Templates and Unit Generators for Best Tunnel Studio v2.0.
Generators and scoped teardowns for every protocol in get_supported_protocols():
1. GRE (+ isolated subnet, interface gre-p{id}, precise nat+filter rule deletion)
2. backhaul-wss (WSS transport, token auth, nodelay, buffer 2048)
3. rathole-noise (Stealth noise transport, Noise_NK_25519_ChaChaPoly_BLAKE2s)
4. chisel-wss (Reverse WSS tunnel with TLS cert)
5. frp-TLS (frps on Iran with SAN cert, frpc on Foreign)
6. wstunnel-v10 (Positional URL wss://0.0.0.0:port, secret upgrade path, reverse TCP)
7. xray-reverse (Dual-instance portal on Iran, bridge on Foreign, dynamic UUID & port)
8. kcptun (KCP-FEC, aes-128, JSON config on both sides)

Graduated from quarantine on 2026-10-24 after live witnesses on the
Iran/Turkey test pair (SS-2022 over the GRE carrier, VLESS-REALITY over an
ESP carrier - both deployed by this product, carried real traffic, and
tore down cleanly). First-class protocols now; an operator can re-quarantine
them with BEST_TUNNEL_DISABLE_SINGBOX=1 (see is_singbox_enabled):
9.  singbox-vless-reality
10. singbox-ss-2022

Credentials are never interpolated into ExecStart=. systemd expands ${VAR} into argv, which is
world-readable via /proc/*/cmdline, so every secret is handed to its daemon through a 0600
config file or an environment variable the daemon reads itself.
"""
import uuid
import secrets
import string
import base64
import hashlib
import json
import re
from cryptography.hazmat.primitives.asymmetric import x25519
from safety import generate_firewall_comment

def rnd(n=24) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


# Protocols that *are* the underlay rather than traffic riding on one. Their peer address has to be the
# address the host is reachable at, because they build the path every other transport dials - see
# dial_address for why that cannot be the underlay address.
CARRIER_PROTOCOLS = ("GRE", "ESP")


def dial_address(spec: dict, protocol: str = "") -> str:
    """The address a tunnel dials and a certificate names, which need not be the management address.

    A pair has always carried one host field doing two jobs: the SSH endpoint the orchestrator
    connects to, and the peer address every generator embeds as the dial target and the certificate
    SAN. That holds only while both jobs point at the same address. On infrastructure that refuses
    peer traffic outright - measured on the live test pair with an arrival instrument, not inferred
    from failed connects: TCP, UDP *and* ICMP from the peer never reach the other host in either
    direction (a listener bound for the test arrived at nothing while the initiator timed out, and
    the capture held zero inbound SYN/UDP/echo lines), while IP protocols 47, 50 and 51 all arrive -
    the overlay must come up on a GRE underlay address while management stays on the public one, and
    no pair could express that: the transport either dialed an unreachable address, or SSH failed.
    Both hosts still reach third-party destinations on TCP 443, and both accept inbound TCP:22 from
    the orchestrator's network, so this is a same-provider filter between customer endpoints, not a
    property of the transport - which matters because it means the pair is unusual, not REALITY.

    So a spec may carry `dial_host` beside `host`. Everything that reaches *through* the tunnel uses
    dial_host; everything that reaches the machine itself keeps using host. Unset means identical, so
    pairs created by the dashboard are unaffected.

    GRE and ESP are the two protocols that cannot ride on the underlay, because they are what build it:
    their peer address is the outer endpoint of `ip tunnel add` / `ip link add type vti`, and that has to
    be the address the host is reachable at - which is exactly why IP protocol 47 and 50 are the things
    to test when TCP is filtered.
    """
    if protocol in CARRIER_PROTOCOLS:
        return spec["host"]
    return spec.get("dial_host") or spec["host"]


def carrier_kind(pair: dict) -> str:
    """What wraps this pair's overlay traffic on the wire: 'gre', 'esp', or 'public'.

    `dial_host` exists because the overlay sometimes has to come up on an underlay address while
    management stays on the public one, and until the ESP carrier existed, GRE was the only generator
    that could build such an underlay - so "has a dial_host" and "is wrapped in cleartext proto 47" were
    the same fact, and engine.carrier_camouflage_block relied on that. They are no longer the same fact:
    an ESP underlay also sets dial_host, and refusing a transport whose camouflage the envelope
    *protects* would be exactly backwards. So the carrier is now declared, on the pair row (schema v8),
    and written by the thing that makes it true - deploying ESP sets 'esp', tearing it down clears the
    declaration.

    A pair with a dial_host and no declaration resolves to 'gre', not to 'public'. That is a fail-closed
    default rather than a guess about history: every pair stored before schema v8 that carried a
    dial_host carried a GRE one, and for a pair created afterwards, treating an unrecorded carrier as
    the cleartext one keeps the REALITY refusal armed until something has actually made the envelope
    encrypted.
    """
    declared = str(pair.get("underlay_carrier") or "").strip().lower()
    if declared in ("gre", "esp"):
        return declared
    iran = pair.get("iran") or {}
    foreign = pair.get("foreign") or {}
    # Both shapes are checked because both reach here. dashboard.pair_for_operations and
    # failover_monitor.pairs_from_storage hand the gate a nested spec, while a row read straight out of
    # SQLite (storage.get_pair) is flat. A gate that only recognised the nested shape would answer
    # 'public' for a real GRE pair and un-refuse REALITY - the one direction of error this function
    # exists to make impossible.
    if (iran.get("dial_host") or foreign.get("dial_host")
            or pair.get("iran_dial_host") or pair.get("foreign_dial_host")):
        return "gre"
    return "public"


def dials_gre_underlay(pair: dict) -> bool:
    """True when this pair's overlay is wrapped in a cleartext GRE envelope, so proto 47 shows its innards.

    GRE has no confidentiality at all, which is not a theoretical worry: on the live pair an outer
    capture of `proto 47` traffic showed the cover SNI in cleartext inside the envelope
    (witness_reality_dpi.py, W-series) - the envelope is a window. This is the predicate the carrier
    gate refuses on; see carrier_kind for why it can no longer be inferred from dial_host alone.
    """
    return carrier_kind(pair) == "gre"


# The two carriers are measured through their interface rather than through a local frontend socket:
# nothing user-space listens on the peer's loopback, so the question a probe answers is whether inner
# packets arrive at all. Their inner addressing therefore has one home, here, rather than one copy in the
# generator that configures the /30 and another in the engine that pings it - a probe aimed at a stale
# address reads as 100% loss on a healthy carrier, which is the failure shape this project has already
# been told to treat as a verdict on the transport.
INNER_PROBED = ("GRE", "ESP")


def carrier_iface(protocol: str, pair_id: int, namespace: str = "prod") -> str:
    """The interface name a carrier owns: grep/espp plus pair id, plus 'b' for a benchmark carrier."""
    base = "grep" if protocol == "GRE" else "espp"
    return f"{base}{pair_id}{'b' if namespace == 'bench' else ''}"


def carrier_inner_pair(protocol: str, pair_id: int, namespace: str = "prod") -> tuple[str, str]:
    """(local, peer) inner addresses of a carrier's /30 - GRE on 10.10/10.11, ESP on 10.12/10.13.

    Separate octets per carrier are load-bearing, not tidiness: a pair can hold a GRE underlay and an ESP
    underlay at the same time (protos 47 and 50 both arrive), and two interfaces claiming one address
    would make the routing decision, and therefore the measurement, depend on which unit started first.
    """
    octet = "10.10" if protocol == "GRE" else "10.12"
    idx = (pair_id % 200) + 10
    if namespace == "bench":
        octet = "10.11" if protocol == "GRE" else "10.13"
        idx = ((pair_id + 50) % 200) + 10
    return f"{octet}.{idx}.1", f"{octet}.{idx}.2"


# The one listing a VTI collision is read from. `-d` is what emits the `vti remote <addr> local <addr>`
# clause; without it the addresses are not shown and the collision is invisible.
VTI_LISTING_CMD = "ip -d -o link show type vti 2>/dev/null"
# Two commands rather than one string joined with `||`, for two reasons that are both about being able to
# say what happened: the gate can tell which listing answered, and `is_read_only_command` judges a whole
# string, so a compound one is rejected outright instead of being classifiable at all.
# The fallback exists because `2>/dev/null` makes a *failed* read print nothing, and nothing is exactly
# what "no VTI here" prints: a host whose iproute2 rejects the `type vti` filter would be reported free.
# Reading every link still answers the question - `_vti_clause` keys on the bare `vti` token, so non-vti
# lines contribute nothing.
# Neither read reissues today, for two separate measured reasons (scratch/scan_retryable_redirects.py):
# the classifier rejects any redirect, and even with `2>/dev/null` stripped `ip -d -o link show type vti`
# is still refused, because the `ip` subcommand check reads the token after `ip` and finds the `-d` option
# instead of `link`. `retryable=True` at both call sites is therefore a no-op, not a retry policy -
# escalated as report059 item 53 rather than quietly widening a safety classifier.
VTI_LISTING_FALLBACK_CMD = "ip -d -o link show 2>/dev/null"

_VTI_ADDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_VTI_NAME_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$")


def _vti_clause(line: str) -> dict:
    """{'remote': tok, 'local': tok} for one `ip -d -o link` line, {} when it carries no vti clause."""
    toks = line.split()
    if "vti" not in toks:
        return {}
    i = toks.index("vti")
    out: dict[str, str] = {}
    for j in range(i + 1, min(i + 8, len(toks) - 1)):
        if toks[j] == "numtxqueues":  # the tunability tail: nothing after it is part of the clause
            break
        if toks[j] in ("remote", "local") and toks[j] not in out:
            out[toks[j]] = toks[j + 1]
    return out


def vti_occupant(listing: str, local_ip: str, remote_ip: str, iface: str) -> str:
    """Name of a VTI on this host that already owns the ordered pair (local_ip, remote_ip), else ''.

    The rule this implements was measured on 2026-10-11 in an isolated namespace on both live hosts
    (scratch/vti_endpoint_collision3_20261011.out, scratch/vti_orientation_20261011.out), because the ESP
    carrier failed to start with `RTNETLINK answers: File exists` while every listing said the name was
    free:

      * a second VTI on the same (local, remote) pair is refused **whatever the key** (attempt A created,
        attempt B with the carrier's own key refused);
      * the refusal survives renaming (attempt D, a fourth name, refused) - so no name is free on a tuple
        somebody else holds;
      * a different endpoint pair is accepted with the *same* key (attempt C) - so the collision is the
        endpoints, not the key, and rotating `ESP_SEED` cannot free a carrier;
      * the reversed direction is a different key (baseline `A->B` plus `B->A` both created, on both
        hosts) - so this matcher compares the ordered pair and must not compare the unordered one, which
        would refuse deploys the kernel accepts.

    Two consequences for the product, and they are the reason this function exists: at most one ESP carrier
    can exist between these two hosts *per direction*, so pair 1 and pair 2 on the same hosts cannot both
    have one and a production carrier and a benchmark carrier cannot overlap; and an interface that is
    merely *present* is not necessarily inert - the device that held the tuple here was a stopped leftover
    of a reuse test. A deploy that discovers this occupant late fails inside systemd as
    `status=2/INVALIDARGUMENT` with the real reason in a journal line, so the caller asks before writing.

    `iface` is excluded because under the reuse design the carrier's own nameplate is the expected state of
    a redeploy; the question is only whether somebody *else* holds the tuple. The kernel's default `ip_vti0`
    declares `remote any local any`, which is not an address and therefore never matches - a fact this
    depends on rather than assumes, since `ip_vti0` is present on both live hosts.
    """
    for token, what in ((local_ip, "local_ip"), (remote_ip, "remote_ip")):
        if not _VTI_ADDR_RE.match(token or ""):
            raise ValueError(f"vti_occupant: {what} is not a dotted-quad IPv4 address")
    if not _VTI_NAME_RE.match(iface or ""):
        raise ValueError("vti_occupant: interface name is not a safe token")
    for line in (listing or "").splitlines():
        clause = _vti_clause(line)
        if not clause:
            continue
        if clause.get("remote") == remote_ip and clause.get("local") == local_ip:
            name = line.split()[1] if len(line.split()) > 1 else ""
            name = name.split("@", 1)[0].rstrip(":")
            if name and name != iface:
                return name
    return ""


def generate_noise_keypair() -> tuple[str, str]:
    """Generates standard Noise X25519 keypair for rathole noise transport."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_b64 = base64.b64encode(priv.private_bytes_raw()).decode("ascii")
    pub_b64 = base64.b64encode(pub.public_bytes_raw()).decode("ascii")
    return priv_b64, pub_b64

def generate_self_signed_cert(ip: str) -> tuple[str, str]:
    """Generates RSA-2048 self-signed certificate with IP SAN for TLS transports.

    This certificate is also what the far-side client trusts (`--tls-ca`, `tls_cert`), so it has to
    carry basicConstraints CA:TRUE: Go's verifier rejects a trust anchor without it as "certificate
    signed by unknown authority (possibly because of invalid signature: parent certificate cannot
    sign this kind of certificate)", which is exactly what the live chisel client reported for every
    attempt while all 50 offline tests passed. The extension set mirrors `openssl req -x509`, whose
    defaults are critical CA:TRUE plus SKID/AKID, and which the standalone installers already use
    with certificates that verify on the same hosts.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime, ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ip)])
    alt_names = []
    try:
        alt_names.append(x509.IPAddress(ipaddress.IPv4Address(ip)))
    except Exception:
        alt_names.append(x509.DNSName(ip))

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=True, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ).decode("ascii")
    return cert_pem, key_pem

def generate_ca_leaf_pair(ip: str, common_name: str) -> tuple[str, str, str]:
    """Builds a two-tier PKI: a CA certificate plus a CA:FALSE leaf valid for `ip`.

    Needed by wstunnel only. Its client verifies with rustls/webpki, and a certificate flagged
    basicConstraints CA:TRUE is rejected when it is presented as the *leaf* - even by a client that
    trusts that exact certificate as an anchor. generate_self_signed_cert above deliberately carries
    CA:TRUE because Go's chisel and backhaul clients need the certificate they are given as --tls-ca /
    tls_cert to be usable as an anchor, and those two stacks accept a self-signed CA:TRUE as both roles.
    Sharing one certificate between the two shapes therefore cannot work, so the roles are split here:
    the CA is what the peer installs, the leaf is what the server presents.

    Witnessed on the live pair: with the CA in the client's SSL_CERT_FILE and `--tls-verify-certificate`,
    a leaf carrying only an IP subjectAltName verifies against an SNI of IpAddress(...), so no DNS name
    and no --tls-sni-override are required.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime, ipaddress

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Best Tunnel {common_name} CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    alt = [x509.IPAddress(ipaddress.IPv4Address(ip))]
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ip)]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=820))
        .add_extension(x509.SubjectAlternativeName(alt), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=True, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    ca_pem = ca.public_bytes(serialization.Encoding.PEM).decode("ascii")
    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode("ascii")
    leaf_key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ).decode("ascii")
    return ca_pem, leaf_pem, leaf_key_pem

def conntrack_tuning_cmds() -> list[str]:
    """Returns conntrack tuning as one bash -c script so the shell variables it computes survive.

    Not transactional: the runtime sysctl can succeed while the /etc/sysctl.d write fails, leaving
    the tuning non-persistent across reboots.
    """
    script = """bash -c '
RAM_BYTES=$(grep MemTotal /proc/meminfo | awk "{print \\$2 * 1024}")
CONN_CALC=$(( RAM_BYTES / 16384 * 2 ))
if [ $CONN_CALC -lt 65536 ]; then TARGET_CONN=65536; elif [ $CONN_CALC -gt 262144 ]; then TARGET_CONN=262144; else TARGET_CONN=$CONN_CALC; fi
HASH_SIZE=$(( TARGET_CONN / 4 ))
sysctl -w net.netfilter.nf_conntrack_max=$TARGET_CONN
echo $HASH_SIZE > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
mkdir -p /etc/sysctl.d
echo "net.netfilter.nf_conntrack_max = $TARGET_CONN" > /etc/sysctl.d/99-best-tunnel-conntrack.conf
'"""
    return [script]

# ---------------------------------------------------------
# 1. GRE + DNAT Generator
# ---------------------------------------------------------
#
# 1a'. Firewall durability - the manifest the product re-applies at boot (option (پ), report062 ruling ۱)
#
# Why this exists is a reboot, not a theory. Foreign was restarted for item #55 and every rule the product
# had installed went with the kernel: the deploy path pushes `iptables` commands once, over SSH, and nothing
# re-issues them. Item #54's pre-flight inventory recorded that there is no `/etc/iptables/rules.v4` on the
# host, and the clean-up script left from an earlier round (`iptables -S | grep best-tunnel`) restores only
# the *filter* table - a fail-open by omission, because the NAT rules are the ones that carry the tunnel.
#
# Three rejections, each with the reason kept where it can be argued with:
#   * `iptables-restore` of a saved ruleset is out. Foreign's PREROUTING is shared with Docker
#     (`-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER`, measured in
#     scratch/apply_hairpin_scope_t_20261012.out), and `iptables-restore` *flushes every chain it names*
#     before loading, so restoring our six rules would erase the container runtime's rules. A product must
#     not break a neighbour to persist itself.
#   * `netfilter-persistent` / `iptables-persistent` is out by the manager's ruling ۱ ("فعلاً نصب نشود"),
#     and apt-installing anything at deploy time is the supply-chain class this product already refuses.
#   * Re-running the whole `*_cmds` list is out: those carry `apt-get install`, `modprobe` and `sysctl`, and
#     a boot service is not the place to reach for a package manager.
#
# So the manifest is exactly the durable part of the deploy: one row per firewall rule, carrying **table,
# chain, verb, position and spec**, in the order the deploy issued them. Order matters because PREROUTING is
# first-match (the hairpin was kept alive by a legacy rule *ahead* of the correct one - report062 §3), and
# table matters because a filter-only restore silently drops the DNAT. Replay of `-I <chain> <pos>` and
# `-A <chain>` in manifest order reproduces the chain the deploy built, and `-C` first keeps it idempotent:
# a redeploy finds its own rules present and adds none.
#
# Where it runs: the last `ExecStart` of the carrier's own unit, which is what created the interface the
# rows name. Not a separate `-fw` unit - `build_firewall_manifest` states the blast radius that ruled that
# out. The consequence to keep in mind is that the restore happens at *start*, so rules deleted by hand on a
# running host are not chased until the next boot or restart; that is a drift-detection problem for the
# monitor, not a persistence problem, and it is recorded as such rather than papered over.
#
# The scope rule is the comment. Every row must carry this pair's comment, asserted when the manifest is
# *built* rather than filtered when it is applied: a manifest that could name someone else's rule would be a
# deletion list against Docker. The comment is stored **unquoted** because the applier word-splits the spec,
# and bash does not re-honour quotes found in a variable - a quoted comment would install a second rule whose
# comment is literally `"best-tunnel-..."`, which the next `-C` would not recognise, and the loop of
# duplicating rules would be back. A comment containing a space is therefore refused here, loudly.

FW_REAPPLY_PATH = "/usr/local/sbin/best-tunnel-fw-reapply.sh"
FW_MANIFEST_DIR = "/etc/best-tunnel/firewall"
_FW_ROW = re.compile(r"^iptables\s+(?:-t\s+(\S+)\s+)?-([AI])\s+(\S+)(?:\s+(\d+))?\s+(.*?)"
                     r"(?:\s+2>/dev/null\s*\|\|\s*true|\s*\|\|\s*true)?$")
_FW_COMMENT = re.compile(r"--comment\s+\"?([^\s\"]+)\"?")


def fw_manifest_rows(cmds, comment):
    """`{R|table|chain|verb|pos|spec, S|key=value}` rows, in deploy order, from the plan's own command list.

    Every `iptables` command must parse or this raises: a silently skipped rule is the same class of defect
    as the filter-only restore - the boot would come up with a chain that *looks* applied.
    """
    rows = []
    for cmd in cmds:
        stripped = cmd.strip()
        if stripped.startswith("sysctl -w "):
            # `ip_forward` is as boot-fragile as the rules: without it the carrier forwards nothing and the
            # restored DNATs just refill a DROP-by-default path. It is the only non-iptables durable write
            # the carriers use, so it travels as its own row kind.
            rows.append("S|" + stripped.split(" ", 2)[2].strip())
            continue
        if not stripped.startswith("iptables"):
            continue
        m = _FW_ROW.match(stripped)
        if not m:
            raise ValueError(f"firewall manifest cannot parse a rule command, refusing to write a manifest "
                             f"that would silently omit it: {stripped[:120]}")
        table, verb, chain, pos, spec = m.groups()
        table = table or "filter"
        got = _FW_COMMENT.findall(spec)
        if got != [comment]:
            raise ValueError(f"manifest row is not scoped by this pair's comment (found {got}, want "
                             f"[{comment}]): {spec[:120]}. An unscoped row would be a deletion list against "
                             f"another tenant's rules.")
        spec = spec.replace(f'"{comment}"', comment)
        if '"' in spec or "|" in spec or "\\" in spec:
            raise ValueError(f"manifest spec carries a character the applier word-splits on, refusing: "
                             f"{spec[:120]}")
        rows.append(f"R|{table}|{chain}|{verb}|{pos or '0'}|{spec}")
    if not rows:
        raise ValueError("no firewall rules and no sysctl in the plan; a manifest with nothing to restore is "
                         "a unit that reports success while persisting nothing")
    return rows


def build_firewall_manifest(svc_name, pair_id, namespace, protocol, role, iface, cmds, comment):
    """The manifest file, and the `ExecStart` line the carrier unit runs to apply it.

    Deliberately *not* a second systemd unit. A `<carrier>-fw` unit would have to sit in the plan's
    `iran_units`/`foreign_units` for `enable --now` to start it, and every consumer of those lists - the
    health gate at `failover.check_health`, the benchmark's stop/disable passes, the post-deploy
    verification - would then read a unit that an already-deployed pair has never had as a unit that is
    down. On the first upgrade after this change that is every live pair on the host at once: a phantom
    `inactive`, scored as `DOWN`, acted on as a protocol switchover. Applying the rows inside the carrier's
    own unit is the same boot restore with no new name for anything to mis-read, and it gets the ordering
    for free: `ExecStart` lines run in sequence, so rows naming `-i {iface}` are issued by the same unit
    that created `{iface}` and no inter-unit dependency has to be trusted.
    """
    rows = fw_manifest_rows(cmds, comment)
    manifest_path = f"{FW_MANIFEST_DIR}/{svc_name}-fw.rules"
    manifest = ("\n".join([
        "@kind best-tunnel-firewall-manifest-v1",
        f"@pair {namespace}-{pair_id}-{protocol}",
        f"@role {role}",
        f"@iface {iface}",
        f"@comment {comment}",
    ] + rows) + "\n")
    return {
        "manifest_path": manifest_path,
        "manifest": manifest,
        "rows": rows,
        # Staged with mode 0600 by `SafeSSHRunner.write_file`, so it is invoked through bash and never
        # relies on the executable bit - the spelling the ESP carrier already uses for its xfrm batch.
        "exec_line": f"ExecStart=/bin/bash {FW_REAPPLY_PATH} {manifest_path}",
        # The manifest is removed *before* the rule deletes, not after: a teardown that dies half-way must
        # not leave a file that reinstalls rules that were meant to be gone. Netfilter rules live in memory
        # and die with the kernel, so a torn-down pair's rules can only come back through its manifest.
        "teardown": [f"rm -f {manifest_path}"],
    }


def _add_fw_exec(unit_text, exec_line):
    """Place the manifest's `ExecStart` last among the carrier's, immediately before its `ExecStop`.

    The position is the guarantee, so it is not left to whoever edits the unit text next: systemd runs
    `ExecStart` lines in order, and the rows name `-i <carrier iface>`, which only exists once the carrier's
    own `ip tunnel add` / `ip link add` has run. A unit whose shape this cannot see raises rather than
    returning a unit that silently never applies its rules.
    """
    if "\nExecStop=" not in unit_text:
        raise ValueError("carrier unit has no ExecStop line to order the firewall manifest before, refusing "
                         "to guess where its rules should be applied")
    n_stops = unit_text.count("\nExecStop=")
    if n_stops != 1:
        raise ValueError(f"carrier unit declares {n_stops} ExecStop lines; the manifest's position among "
                         "them would be ambiguous")
    return unit_text.replace("\nExecStop=", "\n" + exec_line + "\nExecStop=", 1)


# Read, don't run: this text is what the product stages onto the host, so test_81 asserts it and then
# *executes* it against a stub `iptables` rather than trusting a substring.
FW_REAPPLY_SCRIPT = r"""#!/bin/bash
# best-tunnel firewall re-applier. Generated text from orchestrator/protocols.py - do not edit on the host.
#
# Idempotent by construction: every row is tested with `-C` before it is issued and re-tested after it is
# issued, so a start on a host that already holds its rules adds none, and a boot that starts from an empty
# table installs all of them. It never flushes a chain, never re-orders a rule it did not install, and never
# names a rule that is not in its own manifest - that manifest was filtered by comment when it was built,
# which is a build-time check rather than a runtime grep.
set -o pipefail
MAN="${1:-}"
[ -n "$MAN" ] && [ -r "$MAN" ] || { echo "FWREAPPLY: manifest missing or unreadable"; exit 2; }
IPT="$(command -v iptables-nft 2>/dev/null || command -v iptables 2>/dev/null)"
[ -n "$IPT" ] || { echo "FWREAPPLY: no iptables binary on this host"; exit 2; }
IFACE=""
rows=()
sysctls=()
present=0; applied=0; failed=0; unconfirmed=0
while IFS= read -r line; do
  case "$line" in
    '') ;;
    \#*) ;;
    @iface\ *) IFACE="${line#@iface }" ;;
    @*) ;;
    S\|*) sysctls+=("${line#S|}") ;;
    R\|*) rows+=("$line") ;;
    # A line of a kind this script does not know is a manifest that did not come from this product, or one
    # that was truncated after it was written. Half a manifest applied quietly is the fail-open this file
    # exists to close, so the whole run stops here.
    *) echo "FWREAPPLY: unrecognised line kind in a manifest"; exit 2 ;;
  esac
done < "$MAN"
[ "${#rows[@]}" -gt 0 ] || { echo "FWREAPPLY: manifest names no rules, nothing was restored"; exit 2; }
# Wait for the carrier *before* issuing anything: a row naming an interface cannot be installed while the
# device is absent, and half a chain applied is worse than none - the rules that did land would forward
# traffic into a tunnel that does not exist yet.
if [ -n "$IFACE" ]; then
  for _ in $(seq 1 30); do ip link show "$IFACE" >/dev/null 2>&1 && break; sleep 1; done
  if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "FWREAPPLY: carrier interface $IFACE never appeared; refusing to install rows that name it"
    exit 1
  fi
fi
for k in "${sysctls[@]}"; do
  # `ip_forward` is as boot-fragile as the rules: without it the carrier forwards nothing and a restored
  # DNAT just refills a path that drops by default.
  sysctl -w "$k" >/dev/null 2>&1 || failed=$((failed+1))
done
# Counts only: the rows carry routable peer addresses, and this output goes into the journal, where
# whatever reads it is not necessarily the operator.
for line in "${rows[@]}"; do
  IFS='|' read -r _r _t _c _v _p _spec <<<"$line"
  set --
  # Globs off while the spec is split: a spec token is an argument, never a pattern to expand.
  set -f
  for _w in $_spec; do set -- "$@" "$_w"; done
  set +f
  targs=()
  [ "$_t" = "filter" ] || targs=(-t "$_t")
  if "$IPT" "${targs[@]}" -C "$_c" "$@" >/dev/null 2>&1; then
    present=$((present+1))
    continue
  fi
  if [ "$_v" = "I" ] && [ "$_p" != "0" ]; then
    "$IPT" "${targs[@]}" -I "$_c" "$_p" "$@" >/dev/null 2>&1 || { failed=$((failed+1)); continue; }
  else
    "$IPT" "${targs[@]}" -A "$_c" "$@" >/dev/null 2>&1 || { failed=$((failed+1)); continue; }
  fi
  # Success is a re-read of the kernel, not iptables' exit status: the carrier unit may stay active only
  # when the rule is *in the table now*, which is the claim the frontend's serving actually depends on.
  if "$IPT" "${targs[@]}" -C "$_c" "$@" >/dev/null 2>&1; then
    applied=$((applied+1))
  else
    unconfirmed=$((unconfirmed+1))
  fi
done
echo "FWREAPPLY: rows=${#rows[@]} present=$present applied=$applied failed=$failed unconfirmed=$unconfirmed"
[ "$failed" -gt 0 ] && exit 1
[ "$unconfirmed" -gt 0 ] && exit 1
exit 0
"""


def generate_gre(pair_id: int, ir_ip: str, fr_ip: str, frontend: int, mtu: int = 1376, namespace: str = "prod") -> dict:
    iface = carrier_iface("GRE", pair_id, namespace)
    tun_ir, tun_fr = carrier_inner_pair("GRE", pair_id, namespace)

    cmt = generate_firewall_comment(f"{pair_id}-{namespace}", "GRE")
    svc_name = f"best-tunnel-{namespace}-p{pair_id}-gre"
    sysctl_conf = f"/etc/sysctl.d/99-best-tunnel-{namespace}-p{pair_id}.conf"
    sysctl_body = "net.ipv4.ip_forward = 1\n"

    # Measured on the live pair: the kernel keys a native GRE tunnel by its (remote, local) tuple, so a
    # bench tunnel between the same two addresses as a live one cannot be created at all - `ip tunnel
    # add` answers EEXIST and the benchmark reports the protocol as dead. A key separates them, and both
    # ends of a benchmark come from this function, so the pair is symmetric by construction. Production
    # units stay unkeyed: their packets are what a censor sees, and a key flag would change what is being
    # measured rather than how many tunnels hold the tuple.
    bench_key = 9000 + (pair_id % 1000)
    gre_key = f" ikey {bench_key} okey {bench_key}" if namespace == "bench" else ""

    ir_unit = f"""[Unit]
Description=Best Tunnel GRE Interface ({namespace.title()} Pair {pair_id})
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=-/sbin/ip tunnel del {iface}
ExecStart=/sbin/ip tunnel add {iface} mode gre remote {fr_ip} local {ir_ip} ttl 255{gre_key}
ExecStart=/sbin/ip addr add {tun_ir}/30 dev {iface}
ExecStart=/sbin/ip link set {iface} up mtu {mtu}
ExecStart=/sbin/sysctl -w net.ipv4.conf.{iface}.rp_filter=0
ExecStop=-/sbin/ip tunnel del {iface}

[Install]
WantedBy=multi-user.target
"""
    fr_unit = f"""[Unit]
Description=Best Tunnel GRE Interface ({namespace.title()} Pair {pair_id})
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=-/sbin/ip tunnel del {iface}
ExecStart=/sbin/ip tunnel add {iface} mode gre remote {ir_ip} local {fr_ip} ttl 255{gre_key}
ExecStart=/sbin/ip addr add {tun_fr}/30 dev {iface}
ExecStart=/sbin/ip link set {iface} up mtu {mtu}
ExecStart=/sbin/sysctl -w net.ipv4.conf.{iface}.rp_filter=0
ExecStop=-/sbin/ip tunnel del {iface}

[Install]
WantedBy=multi-user.target
"""

    ir_cmds = [
        "which iptables >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq iptables)",
        "modprobe ip_gre || true",
        "sysctl -w net.ipv4.ip_forward=1",
        f"iptables -I INPUT 1 -p 47 -s {fr_ip}/32 -m comment --comment \"{cmt}\" -j ACCEPT",
        # `! -i {iface}` is the loop-closing token, and it was chosen by a capture, not by a manual. A SYN
        # arriving on the carrier interface addressed to Iran's own inner :443 matched this rule, was
        # DNATed to the carrier's *other end*, and was forwarded straight back out the interface it came in
        # on: measured on the live pair as `PREROUTING/DNAT +1, POSTROUTING/MASQUERADE +1,
        # IpForwDatagrams +10` with the post-NAT header `10.10.11.1.42566 > 10.10.11.2.443 [S]` seen leaving
        # Iran and Foreign's xray answering it (scratch/hairpin_mechanism_capture_20261011.out §3B, §4).
        # So the inner frontend "answered" a probe that should have been refused, and the answer came from
        # the peer - which is what made every health check aimed at Iran's inner port meaningless. A client
        # never arrives on the carrier interface, so excluding it costs the serving path nothing (that rule
        # counted 1425 packets of real traffic before this change).
        f"iptables -t nat -A PREROUTING -p tcp ! -i {iface} --dport {frontend} -m comment --comment \"{cmt}\" -j DNAT --to-destination {tun_fr}:{frontend}",
        f"iptables -t nat -A PREROUTING -p udp ! -i {iface} --dport {frontend} -m comment --comment \"{cmt}\" -j DNAT --to-destination {tun_fr}:{frontend}",
        f"iptables -I FORWARD 1 -p tcp -d {tun_fr} --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT",
        f"iptables -I FORWARD 1 -p udp -d {tun_fr} --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT",
        f"iptables -I FORWARD 1 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment \"{cmt}\" -j ACCEPT",
        f"iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment \"{cmt}\" -j TCPMSS --clamp-mss-to-pmtu",
        # `! -s {tun_ir}`, the same scoping the ESP twin at `generate_esp` has carried since report058: it
        # keeps the carrier's own inner source out of the NAT. It is *not* what closes the loop above -
        # the hairpin packet's source is the peer's inner address, so a source condition cannot exclude it,
        # and this round measured that distinction instead of assuming it.
        f"iptables -t nat -A POSTROUTING -d {tun_fr} ! -s {tun_ir} -m comment --comment \"{cmt}\" -j MASQUERADE"
    ]
    fr_cmds = [
        "which iptables >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq iptables)",
        "modprobe ip_gre || true",
        "sysctl -w net.ipv4.ip_forward=1",
        f"iptables -I INPUT 1 -p 47 -s {ir_ip}/32 -m comment --comment \"{cmt}\" -j ACCEPT",
        f"iptables -I INPUT 1 -i {iface} -p tcp --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT || true",
        f"iptables -I INPUT 1 -i {iface} -p udp --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT || true",
        f"iptables -A FORWARD -i {iface} -m comment --comment \"{cmt}\" -j ACCEPT",
        f"iptables -A FORWARD -o {iface} -m comment --comment \"{cmt}\" -j ACCEPT",
        f"iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment \"{cmt}\" -j ACCEPT",
        f"iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment \"{cmt}\" -j TCPMSS --clamp-mss-to-pmtu"
    ]
    teardown_ir = [
        f"iptables -D INPUT -p 47 -s {fr_ip}/32 -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -t nat -D PREROUTING -p tcp ! -i {iface} --dport {frontend} -m comment --comment \"{cmt}\" -j DNAT --to-destination {tun_fr}:{frontend} 2>/dev/null || true",
        f"iptables -t nat -D PREROUTING -p udp ! -i {iface} --dport {frontend} -m comment --comment \"{cmt}\" -j DNAT --to-destination {tun_fr}:{frontend} 2>/dev/null || true",
        f"iptables -D FORWARD -p tcp -d {tun_fr} --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -D FORWARD -p udp -d {tun_fr} --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -D FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment \"{cmt}\" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true",
        # Token-for-token mirror of the scoped install rule above: `-D` matches a rule by its full
        # specification, so a delete that omits `! -s {tun_ir}` or `! -i {iface}` no-ops against the rule
        # actually present and leaves the entry on the live host forever. test_71 fails on this asymmetry.
        f"iptables -t nat -D POSTROUTING -d {tun_fr} ! -s {tun_ir} -m comment --comment \"{cmt}\" -j MASQUERADE 2>/dev/null || true",
        f"systemctl stop {svc_name} 2>/dev/null || true",
        f"systemctl disable {svc_name} 2>/dev/null || true",
        f"rm -f /etc/systemd/system/{svc_name}.service {sysctl_conf} /etc/sysctl.d/99-best-tunnel.conf",
        f"ip tunnel del {iface} 2>/dev/null || true"
    ]
    teardown_fr = [
        f"iptables -D INPUT -p 47 -s {ir_ip}/32 -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        # The two inner-frontend INPUT ACCEPTs installed with `-I INPUT 1 -i {iface} -p tcp|udp --dport
        # {frontend}` above. They were never deleted here, so every GRE redeploy added two more permanent
        # rules to Foreign: inert once the tunnel is gone but each keeps the `best-tunnel-...-GRE` comment
        # and they accumulate without bound. Found while wiring the ESP carrier (#40), which copies this
        # shape - ESP had the identical gap and is fixed alongside it.
        f"iptables -D INPUT -i {iface} -p tcp --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -D INPUT -i {iface} -p udp --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -D FORWARD -i {iface} -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -D FORWARD -o {iface} -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -D FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment \"{cmt}\" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true",
        f"systemctl stop {svc_name} 2>/dev/null || true",
        f"systemctl disable {svc_name} 2>/dev/null || true",
        f"rm -f /etc/systemd/system/{svc_name}.service {sysctl_conf} /etc/sysctl.d/99-best-tunnel.conf",
        f"ip tunnel del {iface} 2>/dev/null || true"
    ]
    # Option (پ) as ruled: the product persists its own firewall by manifest, not by a package. Both roles
    # get one because Foreign's rules - proto 47 ingress and the carrier FORWARD accepts - are as boot-
    # fragile as Iran's DNATs, and a half-restored pair is the shape that reproduces "deployed but dark".
    fw_ir = build_firewall_manifest(svc_name, pair_id, namespace, "GRE", "iran", iface, ir_cmds, cmt)
    fw_fr = build_firewall_manifest(svc_name, pair_id, namespace, "GRE", "foreign", iface, fr_cmds, cmt)
    return {
        "protocol": "GRE",
        "iran_files": {
            f"/etc/systemd/system/{svc_name}.service": _add_fw_exec(ir_unit, fw_ir["exec_line"]),
            sysctl_conf: sysctl_body,
            FW_REAPPLY_PATH: FW_REAPPLY_SCRIPT,
            fw_ir["manifest_path"]: fw_ir["manifest"],
        },
        "iran_units": [svc_name],
        "foreign_files": {
            f"/etc/systemd/system/{svc_name}.service": _add_fw_exec(fr_unit, fw_fr["exec_line"]),
            sysctl_conf: sysctl_body,
            FW_REAPPLY_PATH: FW_REAPPLY_SCRIPT,
            fw_fr["manifest_path"]: fw_fr["manifest"],
        },
        "foreign_units": [svc_name],
        "iran_cmds": ir_cmds,
        "foreign_cmds": fr_cmds,
        # The manifest is the first thing to go, ahead of the rule deletes it would otherwise resurrect.
        # The script itself is shared by every pair and role on the host and is deliberately left in place:
        # it does nothing without a manifest, and one pair's teardown must not disarm another's boot.
        "teardown_iran": fw_ir["teardown"] + teardown_ir,
        "teardown_foreign": fw_fr["teardown"] + teardown_fr
    }

# ---------------------------------------------------------
# 1b. ESP carrier: the encrypted underlay, keyed by hand
# ---------------------------------------------------------
#
# Why this exists is a measured fact rather than a preference. On the live test pair TCP (:22/:443/
# :8443/:2095/:8897), UDP (:53/:443/:4500/:50000) and ICMP never arrive between the two hosts in
# either direction, while IP protocols 47, 50 and 51 all do - scratch/witness_carrier_paths.out C3
# records a raw ESP packet surfacing on the peer as `IN esp(50) ESP(spi=0x0badc0de,...)` in both
# directions, and the peer's own `ICMP protocol 50 unreachable` coming back, which proves the datagram
# reached the machine and only the missing SA answered it. That filter is what leaves GRE as the only
# carrier available, and GRE is what makes REALITY worthless: the envelope is cleartext, so the cover
# SNI that *is* REALITY's camouflage gets published to anyone filtering proto 47
# (scratch/witness_reality_dpi.py, W-series).
#
# ESP over protocol 50 is the one remedy the measurement allows, and IKE is not available with it: UDP
# 500 and 4500 are dropped both ways, so no SA can be negotiated. That forces manual keying - an xfrm
# state and policy per direction, provisioned with `ip xfrm`, no daemon, no rekeying - and two
# consequences follow from that, recorded here so they are not discovered on a live host:
#
#   * The key is symmetric. An ESP SA therefore authenticates "whoever holds this key", not a
#     destination, which puts this carrier in kcptun's class in destination-authentication terms (see
#     DESTINATION_MECHANISM) and keeps it out of DESTINATION_ANCHORS on purpose. What it buys is
#     confidentiality of the envelope, which is precisely the property the carrier gate judges.
#   * Nothing rekeys and nothing expires. An SA stays installed until it is deleted or the host
#     reboots, so the unit re-provisions it at boot from the same 0600 file, and a teardown has to be
#     able to name the SA it is deleting *after the fact*. Hence the SPIs are derived deterministically
#     instead of generated: failover Stage 3 regenerates the old plan purely in order to tear it down
#     (failover.py `plan_for`), and a plan whose SPI was random would delete an SA that does not exist
#     while the real one stayed installed and still reported success.
ESP_ALGO = "rfc4106(gcm(aes))"  # AES-128-GCM in the RFC 4106 ESP wrapper: one AEAD, no separate auth algo
ESP_KEY_BYTES = 20              # 16-byte AES key + 4-byte salt, which is what iproute2 expects for it
ESP_ICV_BITS = 128              # the tag length, and iproute2 requires it as a third positional token
ESP_MTU = 1350                  # 1400 (measured Iran eth0) minus the tunnel-mode envelope, with margin
ESP_SEED = "best-tunnel-esp-v1"
# The budget a caller must allow when it waits for a carrier stop, and the value the unit declares for
# itself. One number in one place, because the two disagreeing is what produced the false timeouts this
# constant replaces: `systemctl show -p TimeoutStopUSec` on both hosts reports `1min 30s` (systemd's
# distribution default), while every teardown command in this product ran on `SafeSSHRunner.run`'s
# default 30 s (mock_ssh.py:645). A stop that legitimately takes 31 s was therefore reported as a failure
# of a teardown that systemd went on to complete - and after 2026-10-11's measurements, a stop that takes
# 450 s was reported the same way. The unit states its own timeout so the two can never drift apart, and
# `TEARDOWN_TIMEOUT_SEC` is what every caller passes, so the product always outlasts systemd's patience.
CARRIER_STOP_BUDGET_SEC = 90
TEARDOWN_TIMEOUT_SEC = CARRIER_STOP_BUDGET_SEC + 30
# Both spellings above are measured, not recalled (scratch/probe_esp_aead_{iran,foreign}.out, 2026-10-11,
# iproute2-6.15.0 on Debian 13 kernels 6.12.43 and 6.12.105). The `rfc4106(gcm16)` form that circulates in
# how-tos is not a registered algorithm name on these hosts: the kernel's own /proc/crypto lists
# `rfc4106(gcm(aes))`, and the other spelling fails with `Requested AEAD algorithm not found` before any
# SA exists. Omitting the ICV length fails earlier still, at the argument parser, with
# `Error: argument "ALGO-ICV-LEN" is required` - a batch file that installs nothing while the unit
# reports the batch's exit status. 96 bits also installed; 128 is the full GCM tag and what RFC 4106
# profiles by default, so the shorter tag that some VPNs negotiate is not chosen here.


def _esp_spi(pair_id: int, namespace: str, direction: str) -> str:
    """A deterministic, non-zero SPI per (pair, namespace, direction) - `0x` hex, as `ip xfrm` wants.

    An SPI is not a secret; it travels in cleartext in every ESP header. It is however a *global key*
    on a host, because the kernel resolves an SA by (src, dst, proto, spi): two carriers sharing a
    host must not collide, and `0x80000000` keeps every derived value out of the 0x00000000-0x000000FF
    range that RFC 4303 reserves for testing. Determinism is what lets a teardown that was regenerated
    from a pair id still name the installed SA.
    """
    digest = hashlib.sha256(f"{ESP_SEED}|spi|{namespace}|{pair_id}|{direction}".encode()).digest()
    return f"0x{int.from_bytes(digest[:4], 'big') | 0x80000000:08x}"


def _esp_reqid(pair_id: int, namespace: str) -> int:
    """The reqid tying this carrier's policies to its states, also used as the VTI interface key.

    One number per (pair, namespace), deliberately reused as `ip link ... key`: the interface key and
    the policy reqid matching is the documented convention for route-based VTI, and it means
    `ip -d link show espp7` and `ip xfrm policy ls` describe the same carrier to whoever is debugging
    it. reqid 0 means "unset" to the kernel, so the +1 is load-bearing, not cosmetic.
    """
    digest = hashlib.sha256(f"{ESP_SEED}|reqid|{namespace}|{pair_id}".encode()).digest()
    return int.from_bytes(digest[:3], "big") + 1


def generate_esp(pair_id: int, ir_ip: str, fr_ip: str, frontend: int, transport_port: int = 0,
                 namespace: str = "prod", mtu: int = ESP_MTU) -> dict:
    """Manually keyed ESP (IP proto 50) carrier between the two hosts, as a route-based VTI link.

    `ir_ip`/`fr_ip` are the *public* addresses on both carriers - a carrier is what builds the underlay,
    so its peer address is the outer endpoint (`dial_address` special-cases CARRIER_PROTOCOLS for this
    reason). `transport_port` is accepted and ignored: every other generator needs a port for its own
    daemon, while a carrier carries whatever the frontend DNAT says, and `generate_benchmark_plan`
    passes that argument to everything except GRE.

    Shape of the data plane, and why each piece is where it is:
      * A VTI interface owns the inner /30 and confines which traffic is protected. Selecting the SA by
        inner address alone (no interface) would need a wildcard to cover the DNAT'ed, *forwarded*
        flows, because a forwarded packet is looked up before POSTROUTING rewrites its source - and a
        wildcard selector would capture the management path too. The interface is what makes "only the
        overlay" expressible.
      * The key material goes in one 0600 batch file per host, fed to `ip -batch`, because `ip xfrm
        state add` takes its key as an argument: any other shape puts the SA key in the argv of a live
        process, and systemd logs the expanded ExecStart line of every ExecStart= it runs into the
        journal - which this product then reads back into benchmark rows. The unit file names only the
        path.
      * Both a `dir out` and a `dir in` policy are installed on each host, and the inbound one carries the
        transform template. This is measured, not assumed: on 2026-10-11 the `dir out`-only shape left the
        carrier dark with `/proc/net/xfrm_stat` reporting `XfrmInNoPols` climbing on both hosts, which is
        the inbound policy check discarding a packet that had already arrived and already matched an SA.
        An earlier revision of this docstring claimed `disable_policy=1` on the interface made an inbound
        policy unnecessary; that claim was tested against hardware and failed, so the policy is installed
        and the claim is gone. A `dir in` policy *without* the template was also tested and also failed
        (`rx=0`), so the template is part of the requirement, not decoration.
      * Iran's MASQUERADE excludes this carrier's own inner source (`! -s <inner iran>`). The rule exists
        so *forwarded* client traffic - arbitrary source, DNAT'ed to the inner peer - has a return path.
        Unscoped it also rewrites the inner-addressed packets the carrier is *certified with*, and on the
        live pair that showed up as `tx_errors` and `tx_carrier_errors` moving one per probe with `TX bytes
        0`, i.e. the interface failing to transmit its own health check. Proven causal by negative control:
        with the inbound policy in place and the unscoped rule restored, Iran's direction fails again with
        that exact signature while the reverse direction keeps passing (scratch/ab_esp_dataplane_combo).
    """
    iface = carrier_iface("ESP", pair_id, namespace)
    tun_ir, tun_fr = carrier_inner_pair("ESP", pair_id, namespace)

    reqid = _esp_reqid(pair_id, namespace)
    spi_ir2fr, spi_fr2ir = _esp_spi(pair_id, namespace, "iran"), _esp_spi(pair_id, namespace, "foreign")
    key_ir2fr = secrets.token_hex(ESP_KEY_BYTES)
    key_fr2ir = secrets.token_hex(ESP_KEY_BYTES)

    cmt = generate_firewall_comment(f"{pair_id}-{namespace}", "ESP")
    svc_name = f"best-tunnel-{namespace}-p{pair_id}-esp"
    sysctl_conf = f"/etc/sysctl.d/99-best-tunnel-{namespace}-p{pair_id}-esp.conf"
    sysctl_body = "net.ipv4.ip_forward = 1\n"
    batch_dir = "/etc/best-tunnel/esp"
    batch_ir = f"{batch_dir}/{namespace}-p{pair_id}-iran.batch"
    batch_fr = f"{batch_dir}/{namespace}-p{pair_id}-foreign.batch"

    # Both hosts install both SAs: each one transmits on its own and receives on the peer's. What differs
    # per host is the `dir out` policy, and it has to differ. A template resolves to a state by
    # (saddr, daddr, proto, reqid), so a policy on Foreign that named Iran's outer direction would match
    # the Iran->Foreign SA and make Foreign emit ESP carrying Iran's address as its outer source - which
    # the peer drops as a martian, so the carrier reports "deployed" and stays dark. Two files holding the
    # same keying material read from opposite ends is what "manually keyed" means here, and why a
    # one-sided deploy leaves the carrier dark rather than half-encrypted.
    #
    # The algorithm name is written unquoted on purpose. This file is not read by a shell: `ip -batch` does
    # its own whitespace splitting, and a version that did not honour quotes would hand the parser
    # `"rfc4106(gcm(aes))"` with the quote characters inside the token, which is an unparseable algorithm
    # name. Unquoted is the only spelling correct under both splitters, and the name has no whitespace.
    #
    # The consequence of that second splitter is load-bearing and was measured: the name contains
    # parentheses, so it may exist only inside the batch file. Issued through a shell - which is what every
    # `run()` in this product is - the same token is a bash syntax error before `ip` starts
    # (`syntax error near unexpected token \`(\``, see the `bare:` lines of the probe). The batch file is
    # therefore the one place the AEAD name can appear, which is also why the teardown below deletes by
    # (src, dst, proto, spi) and never names the algorithm.
    states = [
        f"xfrm state add src {ir_ip} dst {fr_ip} proto esp spi {spi_ir2fr} reqid {reqid} "
        f"mode tunnel replay-window 32 aead {ESP_ALGO} 0x{key_ir2fr} {ESP_ICV_BITS}",
        f"xfrm state add src {fr_ip} dst {ir_ip} proto esp spi {spi_fr2ir} reqid {reqid} "
        f"mode tunnel replay-window 32 aead {ESP_ALGO} 0x{key_fr2ir} {ESP_ICV_BITS}",
    ]

    def batch_for(local_outer: str, remote_outer: str, src_inner: str, dst_inner: str) -> str:
        lines = states + [
            f"xfrm policy add src {src_inner} dst {dst_inner} dir out "
            f"tmpl src {local_outer} dst {remote_outer} proto esp mode tunnel reqid {reqid}",
            # The mirror of the outbound selector, with the template naming the SA that carries this
            # direction (outer source is the peer). Without it the decapsulated packet is dropped by the
            # inbound policy check on the peer - measured as `XfrmInNoPols`, see this generator's docstring.
            f"xfrm policy add src {dst_inner} dst {src_inner} dir in "
            f"tmpl src {remote_outer} dst {local_outer} proto esp mode tunnel reqid {reqid}",
        ]
        return "\n".join(lines) + "\n"

    # The bare selectors, once, and the source of both shapes this generator needs: the unit's pre-clean
    # (which must be one shell-safe string) and the teardown list (which must tolerate "already gone").
    # Deletion is by exact (src, dst, proto, spi) and exact selector, never `ip xfrm ... flush`: a flush
    # is a host-wide operation, and this host may hold an SA belonging to something else.
    xfrm_del_bare = [
        f"/sbin/ip xfrm policy del src {tun_ir} dst {tun_fr} dir out",
        f"/sbin/ip xfrm policy del src {tun_fr} dst {tun_ir} dir out",
        # Both inbound directions, because both hosts install both selectors' worth of state and a policy
        # left behind is an orphan that survives the interface, the SA and the unit - which is precisely
        # what happened to a `dir in` policy added by a diagnostic whose teardown list only knew `dir out`.
        f"/sbin/ip xfrm policy del src {tun_fr} dst {tun_ir} dir in",
        f"/sbin/ip xfrm policy del src {tun_ir} dst {tun_fr} dir in",
        f"/sbin/ip xfrm state del src {ir_ip} dst {fr_ip} proto esp spi {spi_ir2fr}",
        f"/sbin/ip xfrm state del src {fr_ip} dst {ir_ip} proto esp spi {spi_fr2ir}",
    ]
    xfrm_teardown = [f"{c} 2>/dev/null || true" for c in xfrm_del_bare]

    def unit_for(local: str, remote: str, inner: str, batch: str) -> str:
        return f"""[Unit]
Description=Best Tunnel ESP Carrier ({namespace.title()} Pair {pair_id})
After=network-online.target
Wants=network-online.target
# `TimeoutStopUSec` is a `[Unit]` key. Written under `[Service]` - which is where an earlier revision of
# this unit had it - systemd on both hosts logs `Unknown key 'TimeoutStopUSec' in section [Service],
# ignoring.` on every reload (journal lines of 2026-10-11, 11:40:15 and 11:42:28) and silently falls back to
# the distribution default. That default happened to be 1min30s, which is also `CARRIER_STOP_BUDGET_SEC`, so
# `systemctl show -p TimeoutStopUSec` agreed with the declared value and the line looked honoured while it
# was being ignored. A budget that only exists by coincidence is not a contract between the unit and its
# callers, which is the entire reason this constant exists.
TimeoutStopUSec={CARRIER_STOP_BUDGET_SEC}s

[Service]
Type=oneshot
RemainAfterExit=yes
# The carrier interface is created once and then reused; no lifecycle operation unregisters it. Measured
# on 2026-10-11: `ip link del` of a VTI that has transformed traffic parks the calling task in
# `netdev_run_todo` forever on the Foreign host - `unregister_netdevice: waiting for espp1 to become
# free. Usage count = -895`, negative and never reaching zero, seven such tasks after seven teardowns,
# the oldest still uninterruptible three hours later. Removing every candidate holder first (tenant
# sockets, conntrack entries for the inner /30, all SAs and policies) and bringing the link down before
# deleting it each changed the number but not the 450 s, while the same delete on a carrier that had
# never carried a packet returned in 0 s. `ip link set down` on that same loaded interface returned
# immediately, so the operation is what blocks, not what holds: down is the stop, and the interface
# survives as a named-but-inert object until the host reboots. A stale interface with different `key`
# parameters cannot be repaired in place, and is caught by `engine.carrier_inner_reachable` before any
# tenant is allowed onto it rather than being trusted.
ExecStartPre=/bin/sh -c '{"; ".join(xfrm_del_bare)}; true'
ExecStart=/bin/sh -c '/sbin/ip link show dev {iface} >/dev/null 2>&1 || /sbin/ip link add name {iface} type vti local {local} remote {remote} key {reqid}'
ExecStart=/sbin/ip addr replace {inner}/30 dev {iface}
ExecStart=/sbin/ip link set {iface} up mtu {mtu}
ExecStart=/sbin/sysctl -q -w net.ipv4.conf.{iface}.disable_policy=1 -w net.ipv4.conf.{iface}.rp_filter=0 -w net.ipv4.conf.{iface}.forwarding=1 -w net.ipv4.conf.{iface}.send_redirects=0
ExecStart=/sbin/ip -batch {batch}
# `-` because the one failure this command can produce is "the interface is not there" - a device removed
# behind systemd's back, which is what the previous revision of this unit did to itself - and a stop that
# reports that as a failure leaves the unit in ActiveState=failed, the residue measured on the live host
# after the 2026-10-11 runs. The product does not take this exit code on trust anyway: a carrier's stop is
# verified by reading the interface state and re-probing the inner path, not by systemctl's silence.
ExecStop=-/sbin/ip link set {iface} down

[Install]
WantedBy=multi-user.target
"""

    ir_unit = unit_for(ir_ip, fr_ip, tun_ir, batch_ir)
    fr_unit = unit_for(fr_ip, ir_ip, tun_fr, batch_fr)

    esp_cmds = [
        "which iptables >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq iptables)",
        "mkdir -p /etc/best-tunnel/esp",
        "modprobe esp4 || true",
        "modprobe xfrm_user || true",
        "modprobe ip_vti || true",
        "sysctl -w net.ipv4.ip_forward=1",
    ]
    ir_cmds = esp_cmds + [
        f"iptables -I INPUT 1 -p 50 -s {fr_ip}/32 -m comment --comment \"{cmt}\" -j ACCEPT",
        # `! -i {iface}` for the reason measured in `generate_gre`: a SYN that arrives on the carrier
        # interface addressed to this host's own inner frontend would otherwise be DNATed to the carrier's
        # other end and forwarded back out the interface it came in on. Same chain, same port-only rule, so
        # the ESP carrier has the same loop and needs the same exclusion.
        f"iptables -t nat -A PREROUTING -p tcp ! -i {iface} --dport {frontend} -m comment --comment \"{cmt}\" -j DNAT --to-destination {tun_fr}:{frontend}",
        f"iptables -t nat -A PREROUTING -p udp ! -i {iface} --dport {frontend} -m comment --comment \"{cmt}\" -j DNAT --to-destination {tun_fr}:{frontend}",
        f"iptables -I FORWARD 1 -p tcp -d {tun_fr} --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT",
        f"iptables -I FORWARD 1 -p udp -d {tun_fr} --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT",
        f"iptables -I FORWARD 1 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment \"{cmt}\" -j ACCEPT",
        f"iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment \"{cmt}\" -j TCPMSS --clamp-mss-to-pmtu",
        f"iptables -t nat -A POSTROUTING -d {tun_fr} ! -s {tun_ir} -m comment --comment \"{cmt}\" -j MASQUERADE",
    ]
    fr_cmds = esp_cmds + [
        f"iptables -I INPUT 1 -p 50 -s {ir_ip}/32 -m comment --comment \"{cmt}\" -j ACCEPT",
        f"iptables -I INPUT 1 -i {iface} -p tcp --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT || true",
        f"iptables -I INPUT 1 -i {iface} -p udp --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT || true",
        f"iptables -A FORWARD -i {iface} -m comment --comment \"{cmt}\" -j ACCEPT",
        f"iptables -A FORWARD -o {iface} -m comment --comment \"{cmt}\" -j ACCEPT",
        f"iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment \"{cmt}\" -j ACCEPT",
        f"iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment \"{cmt}\" -j TCPMSS --clamp-mss-to-pmtu",
    ]
    # `xfrm_teardown` above is the same list with `2>/dev/null || true` appended, derived from the same
    # source so the unit's pre-clean and the teardown can never drift apart.
    #
    # No lifecycle operation issues `ip link del` on the carrier any more, and this is the second half of
    # the rule stated in `unit_for`: the interface is left named-but-inert. The teardown list still brings
    # it down explicitly because the unit's `ExecStop` is not guaranteed to have run (a disabled unit, a
    # unit removed while failed).
    #
    # The order below is not stylistic, and it was not chosen until it was measured. On 2026-10-11 the
    # session's carrier stop - `systemctl stop`, which runs `ip link set espp1 down` - never completed on
    # Foreign: `State 'stop-sigterm' timed out. Killing.` then `Processes still around after SIGKILL.
    # Ignoring.`, the unit record ending `Result=timeout ActiveState=failed` half an hour later, and the
    # same command on the *same* interface returning in 0.42 s once the carrier was idle
    # (scratch/carrier_zombie_state_20261011.out). The difference between those two outcomes is what was
    # attached when it ran: the stop happened while the SAs and policies were still installed and a tenant
    # was still pushing 157 Mbps through the interface. So the rule is that the operations which are
    # measured to complete - deleting the policies and the states, which is what actually stops the
    # envelope carrying anything - come first, and the operation that can park comes last. An inert carrier
    # does not need `down` to be safe; `down` is tidiness, and tidiness must not be allowed to block
    # security work. `ip -o link show dev <iface>` still answers for a parked device, so a later redesign
    # must not read the nameplate as proof of anything.
    teardown_ir = [
        f"iptables -D INPUT -p 50 -s {fr_ip}/32 -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -t nat -D PREROUTING -p tcp ! -i {iface} --dport {frontend} -m comment --comment \"{cmt}\" -j DNAT --to-destination {tun_fr}:{frontend} 2>/dev/null || true",
        f"iptables -t nat -D PREROUTING -p udp ! -i {iface} --dport {frontend} -m comment --comment \"{cmt}\" -j DNAT --to-destination {tun_fr}:{frontend} 2>/dev/null || true",
        f"iptables -D FORWARD -p tcp -d {tun_fr} --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -D FORWARD -p udp -d {tun_fr} --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -D FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment \"{cmt}\" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true",
        # Mirrors the scoped install rule token for token: `-D` matches a rule by its full specification, so
        # a delete that omits `! -s {tun_ir}` no-ops against the rule actually present and leaves a
        # MASQUERADE entry on the live host forever. test_71 fails on exactly this asymmetry.
        f"iptables -t nat -D POSTROUTING -d {tun_fr} ! -s {tun_ir} -m comment --comment \"{cmt}\" -j MASQUERADE 2>/dev/null || true",
    ] + xfrm_teardown + [
        f"systemctl stop {svc_name} 2>/dev/null || true",
        f"systemctl disable {svc_name} 2>/dev/null || true",
        f"ip link set {iface} down 2>/dev/null || true",
        f"rm -f /etc/systemd/system/{svc_name}.service {sysctl_conf} {batch_ir}",
        # Measured live on 2026-10-11: after the shipped teardown had removed the unit file, Foreign still
        # reported `LoadState=loaded ActiveState=failed UnitFileState=bad`. `rm` takes the file, not the
        # record - systemd keeps the failed entry in memory until a reload, and a unit that is still
        # `loaded` is not a unit that has been removed. A stop that ran out TimeoutStopUSec=1min30s is what
        # put it in that state, so this is not cosmetic: it is the normal shape of an ESP teardown on a busy
        # host. `daemon-reload` forgets the deleted file, `reset-failed` clears the failure record.
        "systemctl daemon-reload 2>/dev/null || true",
        f"systemctl reset-failed {svc_name} 2>/dev/null || true",
    ]
    teardown_fr = [
        f"iptables -D INPUT -p 50 -s {ir_ip}/32 -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        # The two inner-frontend INPUT ACCEPTs installed above with `-I INPUT 1 -i {iface} -p tcp|udp
        # --dport {frontend}`. They were missing here, so a teardown left them behind forever: nothing
        # arrives on a down interface, but they keep the `best-tunnel-...-ESP` comment on the host and they
        # accumulate a duplicate on every redeploy. Measured live on 2026-10-11 - after teardown Foreign
        # still held exactly these two ESP-labelled rules while Iran held zero.
        f"iptables -D INPUT -i {iface} -p tcp --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -D INPUT -i {iface} -p udp --dport {frontend} -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -D FORWARD -i {iface} -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -D FORWARD -o {iface} -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -D FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment \"{cmt}\" -j ACCEPT 2>/dev/null || true",
        f"iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment \"{cmt}\" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true",
    ] + xfrm_teardown + [
        # Same drain-then-stop order as Iran's list above, and the same reason: this is the host on which
        # the stop parked, with the SAs still installed at the moment it ran.
        f"systemctl stop {svc_name} 2>/dev/null || true",
        f"systemctl disable {svc_name} 2>/dev/null || true",
        f"ip link set {iface} down 2>/dev/null || true",
        f"rm -f /etc/systemd/system/{svc_name}.service {sysctl_conf} {batch_fr}",
        # Same on the peer: the failed record is per-host, and this is the host whose stop ran out its
        # 90-second budget during the first measured run.
        "systemctl daemon-reload 2>/dev/null || true",
        f"systemctl reset-failed {svc_name} 2>/dev/null || true",
    ]

    fw_ir = build_firewall_manifest(svc_name, pair_id, namespace, "ESP", "iran", iface, ir_cmds, cmt)
    fw_fr = build_firewall_manifest(svc_name, pair_id, namespace, "ESP", "foreign", iface, fr_cmds, cmt)
    return {
        "protocol": "ESP",
        # Carrier metadata, safe to report and to keep in memory: SPIs are cleartext on the wire, and
        # inner addresses identify nothing outside the pair. It holds no key material by construction,
        # and test_68 asserts that the SA keys below appear nowhere in this sub-dict.
        "esp": {
            "iface": iface, "namespace": namespace, "reqid": reqid, "mtu": mtu, "algo": ESP_ALGO,
            "tun_ir": tun_ir, "tun_fr": tun_fr, "spi_ir2fr": spi_ir2fr, "spi_fr2ir": spi_fr2ir,
            "batch_ir": batch_ir, "batch_fr": batch_fr,
        },
        "iran_files": {
            f"/etc/systemd/system/{svc_name}.service": _add_fw_exec(ir_unit, fw_ir["exec_line"]),
            sysctl_conf: sysctl_body,
            batch_ir: batch_for(ir_ip, fr_ip, tun_ir, tun_fr),
            FW_REAPPLY_PATH: FW_REAPPLY_SCRIPT,
            fw_ir["manifest_path"]: fw_ir["manifest"],
        },
        # The manifest persists only the netfilter half of this carrier. The xfrm states and policies are
        # re-provisioned by the unit's own `ip -batch` line from the 0600 batch file, which is why no key
        # material appears in a manifest row - and why the manifest's ExecStart is placed *after* it.
        "iran_units": [svc_name],
        "foreign_files": {
            f"/etc/systemd/system/{svc_name}.service": _add_fw_exec(fr_unit, fw_fr["exec_line"]),
            sysctl_conf: sysctl_body,
            batch_fr: batch_for(fr_ip, ir_ip, tun_fr, tun_ir),
            FW_REAPPLY_PATH: FW_REAPPLY_SCRIPT,
            fw_fr["manifest_path"]: fw_fr["manifest"],
        },
        "foreign_units": [svc_name],
        "iran_cmds": ir_cmds,
        "foreign_cmds": fr_cmds,
        # Ahead of everything else, for the reason the GRE twin states: a manifest that outlives a teardown
        # reinstalls these rules at the next boot, after the SAs and policies they forward into are gone.
        "teardown_iran": fw_ir["teardown"] + teardown_ir,
        "teardown_foreign": fw_fr["teardown"] + teardown_fr,
    }


# ---------------------------------------------------------
# 2. Backhaul-WSS Generator
# ---------------------------------------------------------
def generate_backhaul_wss(pair_id: int, ir_ip: str, fr_ip: str, frontend: int, transport_port: int = 3080, namespace: str = "prod", backend_port: int = None) -> dict:
    backend = int(backend_port) if backend_port else frontend
    tok = rnd(32)
    svc_ir = f"best-tunnel-{namespace}-p{pair_id}-backhaul-server"
    svc_fr = f"best-tunnel-{namespace}-p{pair_id}-backhaul-client"
    cfg_ir = f"/etc/best-tunnel/backhaul/{namespace}-server-p{pair_id}.toml"
    cfg_fr = f"/etc/best-tunnel/backhaul/{namespace}-client-p{pair_id}.toml"
    cert_path = f"/etc/best-tunnel/certs/backhaul-{namespace}-p{pair_id}-cert.pem"
    key_path = f"/etc/best-tunnel/certs/backhaul-{namespace}-p{pair_id}-key.pem"
    ca_path_fr = f"/etc/best-tunnel/certs/backhaul-{namespace}-p{pair_id}-ca.pem"
    cert_pem, key_pem = generate_self_signed_cert(ir_ip)

    server_toml = f"""[server]
bind_addr = "0.0.0.0:{transport_port}"
transport = "wss"
token = "{tok}"
keepalive_period = 75
nodelay = true
heartbeat = 40
channel_size = 2048
tls_cert = "{cert_path}"
tls_key = "{key_path}"
ports = ["{frontend}={backend}"]
log_level = "info"
"""
    client_toml = f"""[client]
remote_addr = "{ir_ip}:{transport_port}"
transport = "wss"
token = "{tok}"
tls_cert = "{ca_path_fr}"
keepalive_period = 75
nodelay = true
heartbeat = 40
retry_interval = 3
"""
    ir_unit = f"""[Unit]
Description=Best Tunnel Backhaul Server ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/backhaul -c {cfg_ir}
[Install]
WantedBy=multi-user.target
"""
    fr_unit = f"""[Unit]
Description=Best Tunnel Backhaul Client ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/backhaul -c {cfg_fr}
[Install]
WantedBy=multi-user.target
"""
    return {
        "protocol": "backhaul-wss",
        "iran_files": {
            cfg_ir: server_toml,
            cert_path: cert_pem,
            key_path: key_pem,
            f"/etc/systemd/system/{svc_ir}.service": ir_unit
        },
        "iran_units": [svc_ir],
        "foreign_files": {
            cfg_fr: client_toml,
            ca_path_fr: cert_pem,
            f"/etc/systemd/system/{svc_fr}.service": fr_unit
        },
        "foreign_units": [svc_fr],
        "iran_cmds": ["mkdir -p /etc/best-tunnel/backhaul /etc/best-tunnel/certs"],
        "foreign_cmds": ["mkdir -p /etc/best-tunnel/backhaul /etc/best-tunnel/certs"],
        "teardown_iran": [f"systemctl stop {svc_ir} 2>/dev/null || true", f"systemctl disable {svc_ir} 2>/dev/null || true", f"rm -f /etc/systemd/system/{svc_ir}.service {cfg_ir} {cert_path} {key_path}"],
        "teardown_foreign": [f"systemctl stop {svc_fr} 2>/dev/null || true", f"systemctl disable {svc_fr} 2>/dev/null || true", f"rm -f /etc/systemd/system/{svc_fr}.service {cfg_fr} {ca_path_fr}"]
    }

# ---------------------------------------------------------
# 3. Rathole-Noise Generator
# ---------------------------------------------------------
def generate_rathole_noise(pair_id: int, ir_ip: str, fr_ip: str, frontend: int, transport_port: int = 2443, namespace: str = "prod", backend_port: int = None) -> dict:
    backend = int(backend_port) if backend_port else frontend
    tok = rnd(32)
    server_priv, server_pub = generate_noise_keypair()
    svc_ir = f"best-tunnel-{namespace}-p{pair_id}-rathole-server"
    svc_fr = f"best-tunnel-{namespace}-p{pair_id}-rathole-client"
    cfg_ir = f"/etc/best-tunnel/rathole/{namespace}-server-p{pair_id}.toml"
    cfg_fr = f"/etc/best-tunnel/rathole/{namespace}-client-p{pair_id}.toml"

    server_toml = f"""[server]
bind_addr = "0.0.0.0:{transport_port}"

[server.transport]
type = "noise"

[server.transport.noise]
pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
local_private_key = "{server_priv}"

[server.services.s{frontend}]
token = "{tok}"
bind_addr = "0.0.0.0:{frontend}"
"""
    client_toml = f"""[client]
remote_addr = "{ir_ip}:{transport_port}"

[client.transport]
type = "noise"

[client.transport.noise]
pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
remote_public_key = "{server_pub}"

[client.services.s{frontend}]
token = "{tok}"
local_addr = "127.0.0.1:{backend}"
"""
    ir_unit = f"""[Unit]
Description=Best Tunnel Rathole Server ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/rathole {cfg_ir}
[Install]
WantedBy=multi-user.target
"""
    fr_unit = f"""[Unit]
Description=Best Tunnel Rathole Client ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/rathole {cfg_fr}
[Install]
WantedBy=multi-user.target
"""
    return {
        "protocol": "rathole-noise",
        "iran_files": {cfg_ir: server_toml, f"/etc/systemd/system/{svc_ir}.service": ir_unit},
        "iran_units": [svc_ir],
        "foreign_files": {cfg_fr: client_toml, f"/etc/systemd/system/{svc_fr}.service": fr_unit},
        "foreign_units": [svc_fr],
        "iran_cmds": ["mkdir -p /etc/best-tunnel/rathole"],
        "foreign_cmds": ["mkdir -p /etc/best-tunnel/rathole"],
        "teardown_iran": [f"systemctl stop {svc_ir} 2>/dev/null || true", f"systemctl disable {svc_ir} 2>/dev/null || true", f"rm -f /etc/systemd/system/{svc_ir}.service {cfg_ir}"],
        "teardown_foreign": [f"systemctl stop {svc_fr} 2>/dev/null || true", f"systemctl disable {svc_fr} 2>/dev/null || true", f"rm -f /etc/systemd/system/{svc_fr}.service {cfg_fr}"]
    }

# ---------------------------------------------------------
# 4. Chisel-WSS Generator
# ---------------------------------------------------------
def generate_chisel_wss(pair_id: int, ir_ip: str, fr_ip: str, frontend: int, transport_port: int = 2095, namespace: str = "prod", backend_port: int = None) -> dict:
    backend = int(backend_port) if backend_port else frontend
    user = f"tun{pair_id}"
    pwd = rnd(24)
    svc_ir = f"best-tunnel-{namespace}-p{pair_id}-chisel-server"
    svc_fr = f"best-tunnel-{namespace}-p{pair_id}-chisel-client"
    cert_path = f"/etc/best-tunnel/certs/chisel-{namespace}-p{pair_id}-cert.pem"
    key_path = f"/etc/best-tunnel/certs/chisel-{namespace}-p{pair_id}-key.pem"
    ca_path_fr = f"/etc/best-tunnel/certs/chisel-{namespace}-p{pair_id}-ca.pem"
    auth_path_ir = f"/etc/best-tunnel/chisel/{namespace}-auth-p{pair_id}.json"
    env_path_fr = f"/etc/best-tunnel/chisel/{namespace}-env-p{pair_id}"
    # chisel resolves `--auth` from the AUTH environment variable when the flag is absent
    # (verified in chisel v1.10.1 help text). Passing it on ExecStart instead would leak the
    # credential: systemd expands ${VAR} into argv, so it is readable via /proc/*/cmdline.
    env_content = f"AUTH={user}:{pwd}\n"
    cert_pem, key_pem = generate_self_signed_cert(ir_ip)

    # chisel parses --authfile as map[string][]string: {"<user:pass>": ["<remote-addr-regex>", ...]},
    # where the regexes are matched against the address each tunnel requests ("<host>:<port>" for a
    # normal remote, "R:<iface>:<port>" for a reverse forward) and [""] is chisel's own documented
    # equivalent of a full-access --auth entry. The users-keyed array of username/password objects
    # this line used to emit was rejected by the binary on the live host: the server exited 1 with
    # "Invalid JSON" while every offline test still passed, because MockSSHClient records commands
    # instead of parsing the configs it is handed.
    auth_json = json.dumps({f"{user}:{pwd}": [""]})

    ir_unit = f"""[Unit]
Description=Best Tunnel Chisel Server ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/chisel server --port {transport_port} --reverse --authfile {auth_path_ir} --tls-cert {cert_path} --tls-key {key_path}
[Install]
WantedBy=multi-user.target
"""
    fr_unit = f"""[Unit]
Description=Best Tunnel Chisel Client ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
EnvironmentFile={env_path_fr}
ExecStart=/usr/local/bin/chisel client --tls-ca {ca_path_fr} --keepalive 25s https://{ir_ip}:{transport_port} R:{frontend}:127.0.0.1:{backend}
[Install]
WantedBy=multi-user.target
"""
    return {
        "protocol": "chisel-wss",
        "iran_files": {
            auth_path_ir: auth_json,
            cert_path: cert_pem,
            key_path: key_pem,
            f"/etc/systemd/system/{svc_ir}.service": ir_unit
        },
        "iran_units": [svc_ir],
        "foreign_files": {
            env_path_fr: env_content,
            ca_path_fr: cert_pem,
            f"/etc/systemd/system/{svc_fr}.service": fr_unit
        },
        "foreign_units": [svc_fr],
        "iran_cmds": ["mkdir -p /etc/best-tunnel/certs /etc/best-tunnel/chisel"],
        "foreign_cmds": ["mkdir -p /etc/best-tunnel/certs /etc/best-tunnel/chisel"],
        "teardown_iran": [f"systemctl stop {svc_ir} 2>/dev/null || true", f"systemctl disable {svc_ir} 2>/dev/null || true", f"rm -f /etc/systemd/system/{svc_ir}.service {cert_path} {key_path} {auth_path_ir}"],
        "teardown_foreign": [f"systemctl stop {svc_fr} 2>/dev/null || true", f"systemctl disable {svc_fr} 2>/dev/null || true", f"rm -f /etc/systemd/system/{svc_fr}.service {ca_path_fr} {env_path_fr}"]
    }

# ---------------------------------------------------------
# 5. FRP-TLS Generator
# ---------------------------------------------------------
def generate_frp_tls(pair_id: int, ir_ip: str, fr_ip: str, frontend: int, transport_port: int = 7000, namespace: str = "prod", backend_port: int = None) -> dict:
    backend = int(backend_port) if backend_port else frontend
    tok = rnd(32)
    svc_ir = f"best-tunnel-{namespace}-p{pair_id}-frps"
    svc_fr = f"best-tunnel-{namespace}-p{pair_id}-frpc"
    cfg_ir = f"/etc/best-tunnel/frp/{namespace}-frps-p{pair_id}.toml"
    cfg_fr = f"/etc/best-tunnel/frp/{namespace}-frpc-p{pair_id}.toml"
    cert_path_ir = f"/etc/best-tunnel/certs/frp-{namespace}-p{pair_id}-cert.pem"
    key_path_ir = f"/etc/best-tunnel/certs/frp-{namespace}-p{pair_id}-key.pem"
    ca_path_fr = f"/etc/best-tunnel/certs/frp-{namespace}-p{pair_id}-ca.pem"
    cert_pem, key_pem = generate_self_signed_cert(ir_ip)

    frps_toml = f"""bindPort = {transport_port}
auth.method = "token"
auth.token = "{tok}"
transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 15
transport.tls.force = true
transport.tls.certFile = "{cert_path_ir}"
transport.tls.keyFile = "{key_path_ir}"
"""
    frpc_toml = f"""serverAddr = "{ir_ip}"
serverPort = {transport_port}
auth.method = "token"
auth.token = "{tok}"
transport.tcpMux = true
transport.tls.enable = true
transport.tls.disableCustomTLSFirstByte = true
transport.tls.trustedCaFile = "{ca_path_fr}"

[[proxies]]
name = "tunnel-{frontend}"
type = "tcp"
localIP = "127.0.0.1"
localPort = {backend}
remotePort = {frontend}
"""
    ir_unit = f"""[Unit]
Description=Best Tunnel FRPS ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/frps -c {cfg_ir}
[Install]
WantedBy=multi-user.target
"""
    fr_unit = f"""[Unit]
Description=Best Tunnel FRPC ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/frpc -c {cfg_fr}
[Install]
WantedBy=multi-user.target
"""
    return {
        "protocol": "frp-TLS",
        "iran_files": {
            cfg_ir: frps_toml,
            cert_path_ir: cert_pem,
            key_path_ir: key_pem,
            f"/etc/systemd/system/{svc_ir}.service": ir_unit
        },
        "iran_units": [svc_ir],
        "foreign_files": {
            cfg_fr: frpc_toml,
            ca_path_fr: cert_pem,
            f"/etc/systemd/system/{svc_fr}.service": fr_unit
        },
        "foreign_units": [svc_fr],
        "iran_cmds": ["mkdir -p /etc/best-tunnel/frp /etc/best-tunnel/certs"],
        "foreign_cmds": ["mkdir -p /etc/best-tunnel/frp /etc/best-tunnel/certs"],
        "teardown_iran": [f"systemctl stop {svc_ir} 2>/dev/null || true", f"systemctl disable {svc_ir} 2>/dev/null || true", f"rm -f /etc/systemd/system/{svc_ir}.service {cfg_ir} {cert_path_ir} {key_path_ir}"],
        "teardown_foreign": [f"systemctl stop {svc_fr} 2>/dev/null || true", f"systemctl disable {svc_fr} 2>/dev/null || true", f"rm -f /etc/systemd/system/{svc_fr}.service {cfg_fr} {ca_path_fr}"]
    }

# ---------------------------------------------------------
# 6. Wstunnel-v10 Generator
# ---------------------------------------------------------
def generate_wstunnel_v10(pair_id: int, ir_ip: str, fr_ip: str, frontend: int, transport_port: int = 2096, namespace: str = "prod", backend_port: int = None) -> dict:
    backend = int(backend_port) if backend_port else frontend
    secret_path = rnd(16)
    svc_ir = f"best-tunnel-{namespace}-p{pair_id}-wstunnel-server"
    svc_fr = f"best-tunnel-{namespace}-p{pair_id}-wstunnel-client"
    cert_path = f"/etc/best-tunnel/certs/wstunnel-{namespace}-p{pair_id}-cert.pem"
    key_path = f"/etc/best-tunnel/certs/wstunnel-{namespace}-p{pair_id}-key.pem"
    ca_path = f"/etc/best-tunnel/certs/wstunnel-{namespace}-p{pair_id}-ca.pem"
    env_path_ir = f"/etc/best-tunnel/wstunnel/{namespace}-env-p{pair_id}"
    env_path_fr = f"/etc/best-tunnel/wstunnel/{namespace}-env-p{pair_id}"
    ca_pem, cert_pem, key_pem = generate_ca_leaf_pair(ir_ip, f"wstunnel p{pair_id} {namespace}")
    # wstunnel reads its own WSTUNNEL_* environment variables natively (verified against the
    # v10.1.7 binary). Keeping the secret path out of ExecStart matters because systemd expands
    # ${VAR} into argv, which is world-readable through /proc/*/cmdline.
    env_content_ir = f"WSTUNNEL_RESTRICT_HTTP_UPGRADE_PATH_PREFIX={secret_path}\n"
    # SSL_CERT_FILE is what makes verification possible without touching the host's global trust
    # store: wstunnel's rustls stack honours it (witnessed on the live pair - with the CA in
    # SSL_CERT_FILE and an otherwise clean ca-certificates bundle the client completed a verified
    # handshake and opened its remote frontend), while SSL_CERT_DIR was not honoured at all.
    env_content_fr = (f"WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX={secret_path}\n"
                      f"SSL_CERT_FILE={ca_path}\n")

    ir_unit = f"""[Unit]
Description=Best Tunnel wstunnel v10 Server ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
EnvironmentFile={env_path_ir}
ExecStart=/usr/local/bin/wstunnel server wss://0.0.0.0:{transport_port} --tls-certificate {cert_path} --tls-private-key {key_path}
[Install]
WantedBy=multi-user.target
"""
    fr_unit = f"""[Unit]
Description=Best Tunnel wstunnel v10 Client ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
EnvironmentFile={env_path_fr}
ExecStart=/usr/local/bin/wstunnel client --tls-verify-certificate -R "tcp://0.0.0.0:{frontend}:127.0.0.1:{backend}" wss://{ir_ip}:{transport_port}
[Install]
WantedBy=multi-user.target
"""
    return {
        "protocol": "wstunnel-v10",
        "iran_files": {
            env_path_ir: env_content_ir,
            ca_path: ca_pem,
            cert_path: cert_pem,
            key_path: key_pem,
            f"/etc/systemd/system/{svc_ir}.service": ir_unit
        },
        "iran_units": [svc_ir],
        "foreign_files": {
            env_path_fr: env_content_fr,
            ca_path: ca_pem,
            f"/etc/systemd/system/{svc_fr}.service": fr_unit
        },
        "foreign_units": [svc_fr],
        "iran_cmds": ["mkdir -p /etc/best-tunnel/certs /etc/best-tunnel/wstunnel"],
        "foreign_cmds": ["mkdir -p /etc/best-tunnel/certs /etc/best-tunnel/wstunnel"],
        "teardown_iran": [f"systemctl stop {svc_ir} 2>/dev/null || true", f"systemctl disable {svc_ir} 2>/dev/null || true", f"rm -f /etc/systemd/system/{svc_ir}.service {cert_path} {key_path} {ca_path} {env_path_ir}"],
        "teardown_foreign": [f"systemctl stop {svc_fr} 2>/dev/null || true", f"systemctl disable {svc_fr} 2>/dev/null || true", f"rm -f /etc/systemd/system/{svc_fr}.service {ca_path} {env_path_fr}"]
    }

# ---------------------------------------------------------
# 7. Xray-Reverse Dual-Instance Generator
# ---------------------------------------------------------
def generate_xray_reverse(pair_id: int, ir_ip: str, fr_ip: str, frontend: int, transport_port: int = None, namespace: str = "prod", backend_port: int = None) -> dict:
    backend = int(backend_port) if backend_port else frontend
    tunnel_uuid = str(uuid.uuid4())
    secret_tag = rnd(12)
    inter_port = transport_port if transport_port else (2080 + (pair_id % 100))
    svc_portal = f"best-tunnel-{namespace}-p{pair_id}-xray-portal"
    svc_bridge = f"best-tunnel-{namespace}-p{pair_id}-xray-bridge"
    cfg_portal = f"/etc/best-tunnel/xray/{namespace}-portal-p{pair_id}.json"
    cfg_bridge = f"/etc/best-tunnel/xray/{namespace}-bridge-p{pair_id}.json"

    portal_json = f"""{{
  "log": {{"loglevel": "info"}},
  "reverse": {{
    "portals": [
      {{"tag": "portal-{secret_tag}", "domain": "reverse.{secret_tag}.local"}}
    ]
  }},
  "inbounds": [
    {{
      "tag": "external-in",
      "port": {frontend},
      "protocol": "dokodemo-door",
      "settings": {{"address": "127.0.0.1", "port": {frontend}, "network": "tcp"}}
    }},
    {{
      "tag": "inter-connect",
      "port": {inter_port},
      "protocol": "vmess",
      "settings": {{"clients": [{{"id": "{tunnel_uuid}"}}]}}
    }}
  ],
  "routing": {{
    "rules": [
      {{"type": "field", "inboundTag": ["inter-connect"], "domain": ["full:reverse.{secret_tag}.local"], "outboundTag": "portal-{secret_tag}"}},
      {{"type": "field", "inboundTag": ["external-in"], "outboundTag": "portal-{secret_tag}"}}
    ]
  }}
}}"""

    bridge_json = f"""{{
  "log": {{"loglevel": "info"}},
  "reverse": {{
    "bridges": [
      {{"tag": "bridge-{secret_tag}", "domain": "reverse.{secret_tag}.local"}}
    ]
  }},
  "outbounds": [
    {{
      "tag": "tunnel-out",
      "protocol": "vmess",
      "settings": {{
        "vnext": [
          {{"address": "{ir_ip}", "port": {inter_port}, "users": [{{"id": "{tunnel_uuid}"}}]}}
        ]
      }}
    }},
    {{
      "tag": "local-dest",
      "protocol": "freedom",
      "settings": {{"redirect": "127.0.0.1:{backend}"}}
    }}
  ],
  "routing": {{
    "rules": [
      {{"type": "field", "inboundTag": ["bridge-{secret_tag}"], "domain": ["full:reverse.{secret_tag}.local"], "outboundTag": "tunnel-out"}},
      {{"type": "field", "inboundTag": ["bridge-{secret_tag}"], "outboundTag": "local-dest"}}
    ]
  }}
}}"""

    ir_unit = f"""[Unit]
Description=Best Tunnel Xray Portal ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/xray run -c {cfg_portal}
[Install]
WantedBy=multi-user.target
"""
    fr_unit = f"""[Unit]
Description=Best Tunnel Xray Bridge ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/xray run -c {cfg_bridge}
[Install]
WantedBy=multi-user.target
"""
    return {
        "protocol": "xray-reverse",
        "iran_files": {cfg_portal: portal_json, f"/etc/systemd/system/{svc_portal}.service": ir_unit},
        "iran_units": [svc_portal],
        "foreign_files": {cfg_bridge: bridge_json, f"/etc/systemd/system/{svc_bridge}.service": fr_unit},
        "foreign_units": [svc_bridge],
        "iran_cmds": ["mkdir -p /etc/best-tunnel/xray"],
        "foreign_cmds": ["mkdir -p /etc/best-tunnel/xray"],
        "teardown_iran": [f"systemctl stop {svc_portal} 2>/dev/null || true", f"systemctl disable {svc_portal} 2>/dev/null || true", f"rm -f /etc/systemd/system/{svc_portal}.service {cfg_portal}"],
        "teardown_foreign": [f"systemctl stop {svc_bridge} 2>/dev/null || true", f"systemctl disable {svc_bridge} 2>/dev/null || true", f"rm -f /etc/systemd/system/{svc_bridge}.service {cfg_bridge}"]
    }

# ---------------------------------------------------------
# 8. KCP-FEC (kcptun with Reed-Solomon Error Correction)
# ---------------------------------------------------------
def generate_kcptun(pair_id: int, ir_ip: str, fr_ip: str, frontend: int, transport_port: int = 4090, namespace: str = "prod", backend_port: int = None) -> dict:
    backend = int(backend_port) if backend_port else frontend
    key = rnd(32)
    svc_server = f"best-tunnel-{namespace}-p{pair_id}-kcptun-server"
    svc_client = f"best-tunnel-{namespace}-p{pair_id}-kcptun-client"
    cfg_server = f"/etc/best-tunnel/kcptun/{namespace}-server-p{pair_id}.json"
    cfg_client = f"/etc/best-tunnel/kcptun/{namespace}-client-p{pair_id}.json"

    server_json = f"""{{
  "listen": ":{transport_port}",
  "target": "127.0.0.1:{backend}",
  "key": "{key}",
  "crypt": "aes-128",
  "mode": "fast3",
  "datashard": 10,
  "parityshard": 3,
  "nocomp": false
}}"""

    client_json = f"""{{
  "localaddr": ":{frontend}",
  "remoteaddr": "{fr_ip}:{transport_port}",
  "key": "{key}",
  "crypt": "aes-128",
  "mode": "fast3",
  "datashard": 10,
  "parityshard": 3,
  "nocomp": false
}}"""

    fr_unit = f"""[Unit]
Description=Best Tunnel KCP-FEC Server ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=3
ExecStart=/usr/local/bin/kcptun-server -c {cfg_server}
[Install]
WantedBy=multi-user.target
"""

    ir_unit = f"""[Unit]
Description=Best Tunnel KCP-FEC Client ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=3
ExecStart=/usr/local/bin/kcptun-client -c {cfg_client}
[Install]
WantedBy=multi-user.target
"""

    return {
        "protocol": "kcptun",
        "iran_files": {
            cfg_client: client_json,
            f"/etc/systemd/system/{svc_client}.service": ir_unit
        },
        "iran_units": [svc_client],
        "foreign_files": {
            cfg_server: server_json,
            f"/etc/systemd/system/{svc_server}.service": fr_unit
        },
        "foreign_units": [svc_server],
        "iran_cmds": ["mkdir -p /etc/best-tunnel/kcptun"],
        "foreign_cmds": ["mkdir -p /etc/best-tunnel/kcptun"],
        "teardown_iran": [
            f"systemctl stop {svc_client} 2>/dev/null || true",
            f"systemctl disable {svc_client} 2>/dev/null || true",
            f"rm -f /etc/systemd/system/{svc_client}.service {cfg_client}"
        ],
        "teardown_foreign": [
            f"systemctl stop {svc_server} 2>/dev/null || true",
            f"systemctl disable {svc_server} 2>/dev/null || true",
            f"rm -f /etc/systemd/system/{svc_server}.service {cfg_server}"
        ]
    }

# ---------------------------------------------------------
# 10. Hysteria2 Generator (graduated 2026-10-24)
# ---------------------------------------------------------
def _generate_hy2_cert(sni: str, dial_ip: str) -> tuple[str, str, str]:
    """ECDSA P-256 self-signed cert for a HY2 server, plus its pinSHA256.

    Three constraints from the live witness, each earned by a failed run:
      * ECDSA, not Ed25519: HY2's Chrome-parroting handshake fails an
        Ed25519 leaf, and the docs say so.
      * SANs, not CN-only: Go's x509 rejects a CN-only cert even when the
        client pins the fingerprint ("relies on legacy Common Name").
      * CA:TRUE, like generate_self_signed_cert: pinSHA256 alone does not
        bypass chain verification in HY2's TLS stack ("signed by unknown
        authority"), so the client also trusts this cert as its `ca`.
    The cert is per-pair and short-lived (30 days); rotation is a
    redeploy, which regenerates all three artifacts together.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime, ipaddress

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sni)])
    alt_names = [x509.DNSName(sni)]
    try:
        alt_names.append(x509.IPAddress(ipaddress.IPv4Address(dial_ip)))
    except Exception:
        pass
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=True, key_cert_sign=True, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ).decode("ascii")
    digest = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    pin = ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
    return cert_pem, key_pem, pin


def generate_hysteria2(pair_id: int, ir_ip: str, fr_ip: str, frontend: int, transport_port: int = 2444, namespace: str = "prod", backend_port: int = None) -> dict:
    """Hysteria2 over QUIC: server on Foreign, client on Iran.

    The direction follows the product's reverse convention in the sense
    that matters: the user-facing listener is on Iran (the tcpForwarding
    listener on the frontend), and delivery lands on Foreign's loopback
    (remote 127.0.0.1:backend) - the same shape as rathole's client
    service, except the roles are not swapped: HY2's client is the side
    that dials, so it sits on Iran and dials the server on Foreign's
    carrier-inner address, exactly as the live witness proved. Salamander
    obfuscation is always on (a HY2 server without it is just HTTP/3),
    and TLS is pinned two ways (pinSHA256 + ca) - never insecure.
    """
    backend = int(backend_port) if backend_port else frontend
    auth = rnd(32)
    obfs = rnd(32)
    sni = f"hy2-p{pair_id}.local"
    cert_pem, key_pem, pin = _generate_hy2_cert(sni, fr_ip)
    svc_ir = f"best-tunnel-{namespace}-p{pair_id}-hysteria2-client"
    svc_fr = f"best-tunnel-{namespace}-p{pair_id}-hysteria2-server"
    cfg_ir = f"/etc/best-tunnel/hysteria2/{namespace}-client-p{pair_id}.yaml"
    cfg_fr = f"/etc/best-tunnel/hysteria2/{namespace}-server-p{pair_id}.yaml"
    ca_ir = f"/etc/best-tunnel/hysteria2/{namespace}-ca-p{pair_id}.pem"
    cert_fr = f"/etc/best-tunnel/hysteria2/{namespace}-cert-p{pair_id}.pem"
    key_fr = f"/etc/best-tunnel/hysteria2/{namespace}-key-p{pair_id}.pem"

    server_yaml = f"""listen: {fr_ip}:{transport_port}
auth:
  type: password
  password: {auth}
tls:
  cert: {cert_fr}
  key: {key_fr}
obfs:
  type: salamander
  salamander:
    password: {obfs}
"""
    client_yaml = f"""server: {fr_ip}:{transport_port}
auth: {auth}
tls:
  sni: {sni}
  pinSHA256: {pin}
  ca: {ca_ir}
obfs:
  type: salamander
  salamander:
    password: {obfs}
tcpForwarding:
  - listen: 0.0.0.0:{frontend}
    remote: 127.0.0.1:{backend}
"""
    ir_unit = f"""[Unit]
Description=Best Tunnel Hysteria2 Client ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/hysteria -c {cfg_ir} client
[Install]
WantedBy=multi-user.target
"""
    fr_unit = f"""[Unit]
Description=Best Tunnel Hysteria2 Server ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/hysteria -c {cfg_fr} server
[Install]
WantedBy=multi-user.target
"""
    return {
        "protocol": "hysteria2",
        "iran_files": {cfg_ir: client_yaml, ca_ir: cert_pem,
                       f"/etc/systemd/system/{svc_ir}.service": ir_unit},
        "iran_units": [svc_ir],
        "foreign_files": {cfg_fr: server_yaml, cert_fr: cert_pem, key_fr: key_pem,
                          f"/etc/systemd/system/{svc_fr}.service": fr_unit},
        "foreign_units": [svc_fr],
        "iran_cmds": ["mkdir -p /etc/best-tunnel/hysteria2"],
        "foreign_cmds": ["mkdir -p /etc/best-tunnel/hysteria2"],
        "teardown_iran": [f"systemctl stop {svc_ir} 2>/dev/null || true", f"systemctl disable {svc_ir} 2>/dev/null || true", f"rm -f /etc/systemd/system/{svc_ir}.service {cfg_ir} {ca_ir}"],
        "teardown_foreign": [f"systemctl stop {svc_fr} 2>/dev/null || true", f"systemctl disable {svc_fr} 2>/dev/null || true", f"rm -f /etc/systemd/system/{svc_fr}.service {cfg_fr} {cert_fr} {key_fr}"]
    }


# ---------------------------------------------------------
# REALITY cover destinations
# ---------------------------------------------------------
# REALITY's camouflage is an outer TLS ClientHello aimed at a *real* destination: the server proxies
# every connection that is not a valid handshake onward to `handshake.server:443`, and the client puts
# that same name in the SNI. With one name hardcoded in the generator, the entire fleet shares a
# single point of failure - whoever decides to block that one SNI blocks every tunnel at once, and a
# censor that sees the same SNI to the same destination from thousands of unrelated IPs has a
# population fingerprint handed to it for free. So the cover is selected from a pool, per pair.
#
# Membership is empirical, not reputational. A cover is only usable if, *from the host that has to
# reach it*, it resolves to IPv4, answers on 443, completes TLS 1.3, presents a chain that verifies
# against public CAs, and actually hosts the SNI it was named with (a default-vhost certificate for a
# different name means the mimicry is off). orchestrator/vet_reality_covers.py measures all five from both
# live hosts; the pool below contains only what passed there, measured 2026-10-10, out of 18
# candidates - 13 passed both hosts. The tool ships beside this file rather than in a scratch directory
# so that the claim "decided by measurement" is reproducible from the deliverable itself.
#
# Deliberately fewer than the 13 that passed: breadth across unrelated operators is the property
# being bought. Six corporations and eight distinct SNI namespaces means a block aimed at one of them
# takes down a slice of the fleet instead of all of it. Names were dropped for cause in that same run
# - a Microsoft download host that only negotiates TLS 1.2, Cloudflare's resolver names because they
# answer a different SNI and are refused from Iran, and Apple's developer CDN edge, which presented a
# certificate for a name it does not host when dialed from one of the two networks.
#
# This is a point-in-time measurement: covers rotate CDN edges and CAs, and "reachable from Iran" is
# a policy that can change without anything breaking here. Re-run the vetting before adding a name.
# Note also that editing this pool changes which cover every pair gets, so it must ship to both peers
# in one release - a pool changed under an already-deployed peer leaves two peers disagreeing about
# the expected SNI, and that failure looks exactly like DPI blocking.
REALITY_COVER_PORT = 443
REALITY_COVER_POOL: tuple = (
    "gateway.icloud.com",
    "www.apple.com",
    "www.google.com",
    "www.microsoft.com",
    "update.code.visualstudio.com",
    "github.com",
    "www.cloudflare.com",
    "devcloud.com",
)

_FQDN_RE = re.compile(r"^(?=.*[a-z])[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
COVER_REQUIREMENTS = ("resolves_v4", "tcp_open", "tls13", "chain_verified", "sni_hosted")


def select_reality_cover(pair_id: int, server_name: str = "") -> str:
    """The cover name a pair's REALITY tunnel uses. Deterministic, never random.

    Random per call would be wrong twice over: regenerating a config would move an already-deployed
    peer to a different destination (the two sides then disagree on the expected SNI and the handshake
    silently degrades into a proxied connection that fails), and the report could not say which cover
    a running tunnel is using. So the mapping is `pair_id % len(pool)`: stable for a given pool, and
    different pairs land on different destinations.

    An explicit `server_name` is accepted as an operator override and is checked for syntax only -
    an address is not a cover (TLS SNI carries host names, so an IP here produces a client that
    never completes the REALITY handshake, which reads like DPI blocking). Whether an override is
    *reachable* is a live fact, validated by validate_reality_cover from the precheck script.
    """
    if server_name:
        name = server_name.strip().lower()
        if not _FQDN_RE.match(name):
            raise ValueError(
                f"REALITY cover {name!r} is not a hostname: it must be a lowercase FQDN with at least "
                f"two labels (e.g. www.example.com). An IP address cannot be a cover - the SNI it "
                f"produces matches no certificate, so the handshake fails for a reason that looks "
                f"exactly like blocking.")
        return name
    pool = REALITY_COVER_POOL
    if not pool:
        raise ValueError("REALITY_COVER_POOL is empty: no vetted cover destination to select")
    return pool[int(pair_id) % len(pool)]


def validate_reality_cover(server: str, facts: dict) -> tuple:
    """Decide from measured facts whether `server` can serve as a cover. Pure: no I/O, no network.

    Every unmet requirement is returned, not just the first. An operator who is told only "tcp_open
    failed" will chase a firewall while the real problem is that the name resolves to AAAA only and
    the host has no v6 egress.

    `facts` keys are exactly COVER_REQUIREMENTS, each a bool observed from the host that has to reach
    the destination (for the server side that is the Foreign host dialing the handshake; for the
    client side it is the Iran host, whose SNI must be one that a user in that country would plausibly
    be sending - a destination the country already blocks is an anomaly signal, not camouflage).
    """
    name = (server or "").strip().lower()
    failures = []
    if not name:
        failures.append("no cover name given")
    missing = [k for k in COVER_REQUIREMENTS if k not in (facts or {})]
    if missing:
        failures.append("facts not measured: " + ", ".join(missing))
    for key in COVER_REQUIREMENTS:
        if key in (facts or {}) and not facts[key]:
            failures.append(key)
    return (not failures, failures)


# ---------------------------------------------------------
# 9. SingBoxAdapter (Phase 2 Modern Core: VLESS-REALITY & Shadowsocks-2022)
# ---------------------------------------------------------
class SingBoxAdapter:
    """Sing-Box 1.9+ / 1.10+ Unified Adapter for Next-Gen Transports (Phase 2).
    Generates declarative JSON configurations, systemd services, and scoped teardowns.
    """

    @staticmethod
    def generate_reality_keys() -> tuple[str, str, str]:
        """Generates (private_key, public_key, short_id) for REALITY transport using X25519."""
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key()
        priv_b64 = base64.urlsafe_b64encode(priv.private_bytes_raw()).decode("ascii").rstrip("=")
        pub_b64 = base64.urlsafe_b64encode(pub.public_bytes_raw()).decode("ascii").rstrip("=")
        short_id = secrets.token_hex(8)
        return priv_b64, pub_b64, short_id

    @staticmethod
    def generate_shadowsocks_key(method: str = "2022-blake3-aes-128-gcm") -> str:
        """Generates cryptographically random base64 key for Shadowsocks-2022."""
        length = 16 if "128" in method else 32
        return base64.b64encode(secrets.token_bytes(length)).decode("ascii")

    @staticmethod
    def validate_config(cfg: dict, check_binary: bool = False) -> bool:
        """Strictly validates sing-box JSON configuration schema.
        Verifies types, tags, listeners, AND critical protocol fields
        (server, uuid, keys, short_id, method, password).
        Optionally executes 'sing-box check -c' if binary is available.
        """
        import os, shutil, subprocess, tempfile

        if not isinstance(cfg, dict):
            return False
        if "inbounds" not in cfg or "outbounds" not in cfg:
            return False
        inbounds = cfg.get("inbounds")
        outbounds = cfg.get("outbounds")
        if not isinstance(inbounds, list) or not isinstance(outbounds, list):
            return False
        if not inbounds or not outbounds:
            return False

        valid_in_types = {"direct", "mixed", "socks", "http", "vless", "shadowsocks", "tun", "redirect", "tproxy"}
        for ib in inbounds:
            if not isinstance(ib, dict):
                return False
            ib_type = ib.get("type")
            if ib_type not in valid_in_types:
                return False
            if "tag" not in ib or "listen_port" not in ib:
                return False
            if not isinstance(ib["listen_port"], int) or ib["listen_port"] <= 0 or ib["listen_port"] > 65535:
                return False

            # Deep field validation for inbounds
            if ib_type == "vless":
                users = ib.get("users")
                if not isinstance(users, list) or not users:
                    return False
                for u in users:
                    if not isinstance(u, dict) or not u.get("uuid"):
                        return False
                tls = ib.get("tls", {})
                if tls.get("enabled"):
                    reality = tls.get("reality", {})
                    if reality.get("enabled"):
                        if not reality.get("private_key") or not reality.get("short_id"):
                            return False
                        hs = reality.get("handshake", {})
                        if not hs.get("server") or not isinstance(hs.get("server_port"), int):
                            return False
            elif ib_type == "shadowsocks":
                if not ib.get("method") or not ib.get("password") or len(ib.get("password", "")) < 16:
                    return False
            elif ib_type == "direct":
                if not ib.get("override_address") or not isinstance(ib.get("override_port"), int):
                    return False

        valid_out_types = {"direct", "vless", "shadowsocks", "socks", "http", "block"}
        for ob in outbounds:
            if not isinstance(ob, dict):
                return False
            ob_type = ob.get("type")
            if ob_type not in valid_out_types:
                return False
            if "tag" not in ob:
                return False

            # Deep field validation for outbounds
            if ob_type == "vless":
                if not ob.get("server") or not isinstance(ob.get("server_port"), int):
                    return False
                if not ob.get("uuid"):
                    return False
                tls = ob.get("tls", {})
                if tls.get("enabled"):
                    if not tls.get("server_name"):
                        return False
                    reality = tls.get("reality", {})
                    if reality.get("enabled"):
                        if not reality.get("public_key") or not reality.get("short_id"):
                            return False
            elif ob_type == "shadowsocks":
                if not ob.get("server") or not isinstance(ob.get("server_port"), int):
                    return False
                if not ob.get("method") or not ob.get("password") or len(ob.get("password", "")) < 16:
                    return False

        # Optional sing-box check -c verification if binary is locally present
        if check_binary or os.getenv("BEST_TUNNEL_FORCE_SINGBOX_BINARY_CHECK", "0") == "1":
            sing_bin = shutil.which("sing-box")
            if sing_bin:
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
                    json.dump(cfg, tf)
                    tf_path = tf.name
                try:
                    res = subprocess.run([sing_bin, "check", "-c", tf_path], capture_output=True, timeout=5)
                    if res.returncode != 0:
                        return False
                except Exception:
                    return False
                finally:
                    if os.path.exists(tf_path):
                        os.remove(tf_path)

        return True

    @classmethod
    def generate_vless_reality(cls, pair_id: int, ir_ip: str, fr_ip: str, frontend: int,
                               transport_port: int = 2090,
                               server_name: str = "",
                               namespace: str = "prod") -> dict:
        """Generates VLESS + REALITY sing-box configuration with chrome uTLS fingerprint and REALITY
        handshake camouflage.

        The mimicry target is not hardcoded here any more: `select_reality_cover(pair_id)` picks it
        from the vetted pool, so pairs do not all share one destination, and an empty `server_name`
        means "use the pool". A non-empty one is an operator override, syntax-checked only - whether
        the name is actually reachable is a live fact that the cover precheck measures.
        """
        cover = select_reality_cover(pair_id, server_name)
        vless_uuid = str(uuid.uuid4())
        priv_key, pub_key, short_id = cls.generate_reality_keys()

        svc_server = f"best-tunnel-{namespace}-p{pair_id}-singbox-vless-server"
        svc_client = f"best-tunnel-{namespace}-p{pair_id}-singbox-vless-client"
        cfg_server = f"/etc/best-tunnel/sing-box/{namespace}-vless-server-p{pair_id}.json"
        cfg_client = f"/etc/best-tunnel/sing-box/{namespace}-vless-client-p{pair_id}.json"

        server_dict = {
            "log": {"level": "info"},
            "inbounds": [
                {
                    "type": "vless",
                    "tag": "vless-in",
                    "listen": "::",
                    "listen_port": transport_port,
                    "users": [
                        {
                            "uuid": vless_uuid,
                            "flow": "xtls-rprx-vision"
                        }
                    ],
                    "tls": {
                        "enabled": True,
                        "server_name": cover,
                        "reality": {
                            "enabled": True,
                            "handshake": {
                                "server": cover,
                                "server_port": REALITY_COVER_PORT
                            },
                            "private_key": priv_key,
                            "short_id": [short_id]
                        }
                    }
                }
            ],
            "outbounds": [
                {
                    "type": "direct",
                    "tag": "direct"
                }
            ],
            "route": {
                "rules": [
                    {
                        "inbound": ["vless-in"],
                        "outbound": "direct"
                    }
                ]
            }
        }

        client_dict = {
            "log": {"level": "info"},
            "inbounds": [
                {
                    "type": "direct",
                    "tag": "local-in",
                    "listen": "0.0.0.0",
                    "listen_port": frontend,
                    "override_address": "127.0.0.1",
                    "override_port": frontend
                }
            ],
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "vless-out",
                    "server": fr_ip,
                    "server_port": transport_port,
                    "uuid": vless_uuid,
                    "flow": "xtls-rprx-vision",
                    "tls": {
                        "enabled": True,
                        "server_name": cover,
                        "utls": {
                            "enabled": True,
                            "fingerprint": "chrome"
                        },
                        "reality": {
                            "enabled": True,
                            "public_key": pub_key,
                            "short_id": short_id
                        }
                    }
                }
            ],
            "route": {
                "rules": [
                    {
                        "inbound": ["local-in"],
                        "outbound": "vless-out"
                    }
                ]
            }
        }

        server_json = json.dumps(server_dict, indent=2)
        client_json = json.dumps(client_dict, indent=2)

        fr_unit = f"""[Unit]
Description=Best Tunnel Sing-Box VLESS-REALITY Server ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=3
ExecStart=/usr/local/bin/sing-box run -c {cfg_server}
[Install]
WantedBy=multi-user.target
"""

        ir_unit = f"""[Unit]
Description=Best Tunnel Sing-Box VLESS-REALITY Client ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=3
ExecStart=/usr/local/bin/sing-box run -c {cfg_client}
[Install]
WantedBy=multi-user.target
"""

        return {
            "protocol": "singbox-vless-reality",
            "cover": cover,
            "iran_files": {
                cfg_client: client_json,
                f"/etc/systemd/system/{svc_client}.service": ir_unit
            },
            "iran_units": [svc_client],
            "foreign_files": {
                cfg_server: server_json,
                f"/etc/systemd/system/{svc_server}.service": fr_unit
            },
            "foreign_units": [svc_server],
            "iran_cmds": ["mkdir -p /etc/best-tunnel/sing-box"],
            "foreign_cmds": ["mkdir -p /etc/best-tunnel/sing-box"],
            "teardown_iran": [
                f"systemctl stop {svc_client} 2>/dev/null || true",
                f"systemctl disable {svc_client} 2>/dev/null || true",
                f"rm -f /etc/systemd/system/{svc_client}.service {cfg_client}"
            ],
            "teardown_foreign": [
                f"systemctl stop {svc_server} 2>/dev/null || true",
                f"systemctl disable {svc_server} 2>/dev/null || true",
                f"rm -f /etc/systemd/system/{svc_server}.service {cfg_server}"
            ]
        }

    @classmethod
    def generate_shadowsocks_2022(cls, pair_id: int, ir_ip: str, fr_ip: str, frontend: int,
                                 transport_port: int = 8388,
                                 method: str = "2022-blake3-aes-128-gcm",
                                 namespace: str = "prod") -> dict:
        """Generates Shadowsocks-2022 sing-box configuration with BLAKE3 key derivation."""
        ss_key = cls.generate_shadowsocks_key(method)

        svc_server = f"best-tunnel-{namespace}-p{pair_id}-singbox-ss-server"
        svc_client = f"best-tunnel-{namespace}-p{pair_id}-singbox-ss-client"
        cfg_server = f"/etc/best-tunnel/sing-box/{namespace}-ss-server-p{pair_id}.json"
        cfg_client = f"/etc/best-tunnel/sing-box/{namespace}-ss-client-p{pair_id}.json"

        server_dict = {
            "log": {"level": "info"},
            "inbounds": [
                {
                    "type": "shadowsocks",
                    "tag": "ss-in",
                    "listen": "::",
                    "listen_port": transport_port,
                    "method": method,
                    "password": ss_key
                }
            ],
            "outbounds": [
                {
                    "type": "direct",
                    "tag": "direct"
                }
            ],
            "route": {
                "rules": [
                    {
                        "inbound": ["ss-in"],
                        "outbound": "direct"
                    }
                ]
            }
        }

        client_dict = {
            "log": {"level": "info"},
            "inbounds": [
                {
                    "type": "direct",
                    "tag": "local-in",
                    "listen": "0.0.0.0",
                    "listen_port": frontend,
                    "override_address": "127.0.0.1",
                    "override_port": frontend
                }
            ],
            "outbounds": [
                {
                    "type": "shadowsocks",
                    "tag": "ss-out",
                    "server": fr_ip,
                    "server_port": transport_port,
                    "method": method,
                    "password": ss_key
                }
            ],
            "route": {
                "rules": [
                    {
                        "inbound": ["local-in"],
                        "outbound": "ss-out"
                    }
                ]
            }
        }

        server_json = json.dumps(server_dict, indent=2)
        client_json = json.dumps(client_dict, indent=2)

        fr_unit = f"""[Unit]
Description=Best Tunnel Sing-Box Shadowsocks-2022 Server ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=3
ExecStart=/usr/local/bin/sing-box run -c {cfg_server}
[Install]
WantedBy=multi-user.target
"""

        ir_unit = f"""[Unit]
Description=Best Tunnel Sing-Box Shadowsocks-2022 Client ({namespace.title()} Pair {pair_id})
After=network-online.target
[Service]
Type=simple
User=root
Restart=always
RestartSec=3
ExecStart=/usr/local/bin/sing-box run -c {cfg_client}
[Install]
WantedBy=multi-user.target
"""

        return {
            "protocol": "singbox-ss-2022",
            "iran_files": {
                cfg_client: client_json,
                f"/etc/systemd/system/{svc_client}.service": ir_unit
            },
            "iran_units": [svc_client],
            "foreign_files": {
                cfg_server: server_json,
                f"/etc/systemd/system/{svc_server}.service": fr_unit
            },
            "foreign_units": [svc_server],
            "iran_cmds": ["mkdir -p /etc/best-tunnel/sing-box"],
            "foreign_cmds": ["mkdir -p /etc/best-tunnel/sing-box"],
            "teardown_iran": [
                f"systemctl stop {svc_client} 2>/dev/null || true",
                f"systemctl disable {svc_client} 2>/dev/null || true",
                f"rm -f /etc/systemd/system/{svc_client}.service {cfg_client}"
            ],
            "teardown_foreign": [
                f"systemctl stop {svc_server} 2>/dev/null || true",
                f"systemctl disable {svc_server} 2>/dev/null || true",
                f"rm -f /etc/systemd/system/{svc_server}.service {cfg_server}"
            ]
        }

# ---------------------------------------------------------
# Master Protocol Dispatcher
# ---------------------------------------------------------
GENERATORS = {
    "GRE": generate_gre,
    "ESP": generate_esp,
    "backhaul-wss": generate_backhaul_wss,
    "rathole-noise": generate_rathole_noise,
    "chisel-wss": generate_chisel_wss,
    "frp-TLS": generate_frp_tls,
    "wstunnel-v10": generate_wstunnel_v10,
    "xray-reverse": generate_xray_reverse,
    "kcptun": generate_kcptun,
    "hysteria2": generate_hysteria2,
    "singbox-vless-reality": SingBoxAdapter.generate_vless_reality,
    "singbox-ss-2022": SingBoxAdapter.generate_shadowsocks_2022
}
BASE_PROTOCOLS = [
    "GRE",
    "ESP",
    "backhaul-wss",
    "rathole-noise",
    "chisel-wss",
    "frp-TLS",
    "wstunnel-v10",
    "xray-reverse",
    "kcptun",
    "hysteria2"
]
SINGBOX_PROTOCOLS = [
    "singbox-vless-reality",
    "singbox-ss-2022"
]

def is_singbox_enabled() -> bool:
    """Whether the sing-box protocols are in the supported set.

    They were quarantined behind BEST_TUNNEL_ENABLE_SINGBOX=1 until they had
    a live witness; on 2026-10-24 both earned one on the Iran/Turkey test
    pair (full deploy -> real traffic -> clean teardown, each over its
    lawful carrier), so they are first-class now. The operator keeps a
    kill switch: BEST_TUNNEL_DISABLE_SINGBOX=1 re-quarantines them.
    BEST_TUNNEL_ENABLE_SINGBOX is still accepted and simply agrees with
    the default.
    """
    import os
    if os.getenv("BEST_TUNNEL_DISABLE_SINGBOX", "0").strip().lower() in ("1", "true", "yes"):
        return False
    return True

def get_supported_protocols() -> list[str]:
    """Single Source of Truth for active supported protocols.
    BASE_PROTOCOLS (10, hysteria2 graduated 2026-10-24) plus
    SINGBOX_PROTOCOLS (2), unless the operator re-quarantined sing-box
    with BEST_TUNNEL_DISABLE_SINGBOX=1.
    """
    if is_singbox_enabled():
        return list(BASE_PROTOCOLS) + list(SINGBOX_PROTOCOLS)
    return list(BASE_PROTOCOLS)

SUPPORTED_PROTOCOLS = get_supported_protocols()
ALL_PROTOCOLS = list(GENERATORS.keys())

# ---------------------------------------------------------------
#  Destination authentication: what proves the far end is the far end
# ---------------------------------------------------------------
#
# Three properties are routinely conflated when a tunnel is reviewed, and a benchmark score can see
# none of them. `verifies_peer` is whether the client refuses a peer that cannot show it holds a
# private half. `pins_destination` is whether the material it was told to trust belongs to *this*
# destination - a per-pair self-signed certificate, a static Noise key - rather than to "whichever CA
# the host happens to carry". The fingerprint derived below is the value an operator can compare out of
# band, and the only thing that makes a rotated key visible instead of silently accepted.
#
# kcptun encrypts a stream while authenticating nothing about *which* endpoint sits at the address
# (both sides hold one symmetric key), and chisel's anchor is a single certificate generated for this
# pair, so chain validation there *is* a destination pin. Neither fact appears in a latency number.
#
# The table below only says where to look. `destination_pin` re-reads the emitted config text and
# reports what that text actually promises, because a comment that disagrees with a config is a bug and
# the config is the thing that runs.
DESTINATION_ANCHORS = {
    # protocol: (side whose client config names the material, pattern picking it out, kind)
    "backhaul-wss": ("foreign_files", r'tls_cert\s*=\s*"([^"]+)"', "pem"),
    "chisel-wss": ("foreign_files", r'--tls-ca\s+(\S+)', "pem"),
    "frp-TLS": ("foreign_files", r'transport\.tls\.trustedCaFile\s*=\s*"([^"]+)"', "pem"),
    "wstunnel-v10": ("foreign_files", r'SSL_CERT_FILE=(\S+)', "pem"),
    "rathole-noise": ("foreign_files", r'remote_public_key\s*=\s*"([^"]+)"', "key"),
    "singbox-vless-reality": ("iran_files", r'"public_key":\s*"([^"]+)"', "key"),
    # The client config is on Iran; the anchor is the CA file it names,
    # and the deployment writes that exact file beside it (the report049
    # shape is a client naming a file nobody wrote - this pair refuses it).
    "hysteria2": ("iran_files", r'ca:\s*(/etc/\S+)', "pem"),
}

DESTINATION_MECHANISM = {
    "backhaul-wss": "wss, verified against this pair's own self-signed certificate",
    "chisel-wss": "https, verified against this pair's own self-signed certificate",
    "frp-TLS": "frps certificate verified against transport.tls.trustedCaFile",
    "wstunnel-v10": "wss verified by rustls against a private CA whose leaf names the dial address",
    "rathole-noise": "Noise_NK with the server static key pinned in remote_public_key",
    "singbox-vless-reality": "REALITY: the server's static x25519 public key is the destination pin",
    "GRE": "GRE (IP proto 47): addressing and routing only, no cryptographic peer authentication",
    "ESP": "manually keyed ESP SA (IP proto 50): the ICV proves the peer holds the key, and the key is "
           "symmetric, so it identifies nobody - confidentiality of the envelope, not of the destination",
    "kcptun": "shared-key KCP: the key encrypts the channel, it does not identify a destination",
    "xray-reverse": "vmess inter-connect with security=none: no TLS layer, no peer authentication",
    "singbox-ss-2022": "Shadowsocks-2022 pre-shared key: a key both sides hold, so no destination identity",
    "hysteria2": "QUIC+TLS, server certificate pinned by fingerprint and trusted as the client's CA",
}


def _pin_hash_of_pem(pem: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    cert = x509.load_pem_x509_certificate(pem.encode("utf-8", errors="replace"))
    return "sha256:" + cert.fingerprint(hashes.SHA256()).hex()


def destination_pin(protocol: str, plan: dict) -> dict:
    """What the emitted client config really says about the destination's identity.

    `status` is the part a caller decides on, and the two failing values mean different things:
    `no-anchor-in-client-config` is a generator regression (the transport was supposed to verify and
    its config no longer carries the material), and `anchor-missing-or-unparseable` is worse - the
    client names a trust file the deployment never writes, which is exactly the report049 wstunnel
    shape: a client with no anchor starts happily and verifies nothing. Both refuse.
    `unauthenticated` is not a defect, it is a property of GRE/kcptun/xray-reverse, so it never refuses
    and never writes a pin row - the pin table holds destinations that are actually authenticated, and
    a row with an empty fingerprint would make "we verified nothing" look like a pin.
    `describe_destination_authentication` is the call that reports that property for a plan; the
    carrier gate is the place that turns it into a refusal when the payload makes it fatal (REALITY
    over a cleartext envelope).
    """
    out = {
        "protocol": protocol,
        "mechanism": DESTINATION_MECHANISM.get(protocol, "not described"),
        "verifies_peer": False,
        "pins_destination": False,
        "anchor": "",
        "fingerprint": "",
        "status": "unauthenticated",
    }
    spec = DESTINATION_ANCHORS.get(protocol)
    if spec is None:
        return out
    side, pattern, kind = spec
    refs = []
    for path, content in (plan.get(side, {}) or {}).items():
        if isinstance(content, str):
            refs.extend(m.group(1) for m in re.finditer(pattern, content))
    if not refs:
        out["status"] = "no-anchor-in-client-config"
        return out
    ref = refs[0]
    out["anchor"] = ref
    if kind == "key":
        out["verifies_peer"] = True
        out["pins_destination"] = True
        out["fingerprint"] = "sha256:" + hashlib.sha256(ref.encode("ascii", errors="replace")).hexdigest()
        out["status"] = "pinned"
        return out
    # Only the side that holds the client config is searched. The peer's copy of the same path is not
    # evidence: if the deployment wrote the CA on the server and never wrote it where the client reads
    # it, a fallback that found the server's copy would report `pinned` and compute a fingerprint for a
    # file the client cannot open - the report049 defect class, laundered by the checker.
    blob = (plan.get(side, {}) or {}).get(ref)
    if isinstance(blob, str):
        try:
            out["fingerprint"] = _pin_hash_of_pem(blob)
            # Set only on success: a client naming a trust file that does not exist or does not
            # parse is not verifying anything, whatever its command line claims. report049's
            # wstunnel client started with no CA at all and reported a healthy tunnel.
            out["verifies_peer"] = True
            out["pins_destination"] = True
            out["status"] = "pinned"
        except Exception as exc:
            out["status"] = f"anchor-missing-or-unparseable ({type(exc).__name__})"
        return out
    out["status"] = "anchor-missing-or-unparseable (file not in plan)"
    return out


def describe_destination_authentication(protocol: str, plan: dict) -> str:
    """One line for an audit row or an operator: the mechanism, and the pin it rests on.

    The whole fingerprint, not a prefix: a truncated pin is the one thing an operator cannot use to
    compare two deployments, and a collision in a displayed prefix reads like a match.
    """
    info = destination_pin(protocol, plan)
    if info["status"] != "pinned":
        return f"{info['mechanism']} [{info['status']}]"
    return (f"{info['mechanism']} [pinned, anchor={info['anchor']}, pin={info['fingerprint']}]")


# ---------------------------------------------------------
# 8b. The backend contract: where a transport DELIVERS what it carries
# ---------------------------------------------------------
#
# Every transport in this product has two ends, and until round 064 only one of them was modelled. The
# end the operator sees is the frontend - a port on Iran a client connects to. The other end is a delivery:
# the tunnel arrives somewhere on the peer host, and unless something listens there the connection is
# carried to nothing. `scratch/backend_contract_census_064.out` measured the gap rather than asserting it:
# 9 of the 11 generators deliver into a host-local port (6 naming `127.0.0.1:<port>` in the artifact they
# write, backhaul via a port map, GRE/ESP by layer-3 routing), **0 of 11** provision or verify a listener
# at that port, and no generator could, up to that measurement, be *told* a different delivery port - the
# number is the frontend
# number duplicated. Pair 2 is what that produces on hardware: `prod-bridge-p2.json:21` says
# `"redirect": "127.0.0.1:9443"`, `ss -tlnH '( sport = :9443 )'` counts 0 listeners, and the unit logs
# `dialing TCP to tcp:127.0.0.1:9443` -> `failed to process outbound traffic`
# (scratch/foreign_churn_probe_060_20261012.out §4-5).
#
# The table declares only *where to look*, exactly like DESTINATION_ANCHORS above: the port is re-read out
# of the emitted artifact, so a generator that changes its delivery point changes the reported contract
# instead of keeping a stale constant. `lands_on` is the host that receives the traffic, which is not the
# host whose file names it (backhaul's port map lives in the server config on Iran and describes a local
# port on the Foreign client), so both are recorded and never conflated.
BACKEND_TARGETS = {
    # protocol: (which side's artifacts hold the text, pattern with a named `backend` group,
    #            which host receives the traffic, the kind of delivery)
    "xray-reverse": ("foreign_files", r'"redirect":\s*"127\.0\.0\.1:(?P<backend>\d+)"',
                     "foreign", "loopback redirect (bridge `local-dest`)"),
    "chisel-wss": ("foreign_files", r'R:\d+:127\.0\.0\.1:(?P<backend>\d+)',
                   "foreign", "chisel remote-forward to loopback"),
    "wstunnel-v10": ("foreign_files", r'-R\s+"tcp://[\d.]+:\d+:127\.0\.0\.1:(?P<backend>\d+)"',
                     "foreign", "wstunnel reverse to loopback"),
    "frp-TLS": ("foreign_files", r'localPort\s*=\s*(?P<backend>\d+)',
                "foreign", "frps proxy to frpc's local port"),
    "kcptun": ("foreign_files", r'"target":\s*"127\.0\.0\.1:(?P<backend>\d+)"',
               "foreign", "kcptun server target on loopback"),
    "rathole-noise": ("foreign_files", r'local_addr\s*=\s*"127\.0\.0\.1:(?P<backend>\d+)"',
                      "foreign", "rathole client service local_addr"),
    "hysteria2": ("iran_files", r'remote:\s*127\.0\.0\.1:(?P<backend>\d+)',
                  "foreign", "hysteria2 tcpForwarding to loopback"),
    "backhaul-wss": ("iran_files", r'ports\s*=\s*\["\d+=(?P<backend>\d+)"\]',
                     "foreign", "backhaul port map: remote=local on the client host"),
    "GRE": ("foreign_files", r'-i\s+grep\d+\s+-p\s+tcp\s+--dport\s+(?P<backend>\d+)',
            "foreign", "layer-3 delivery: the carrier's own interface, INPUT ACCEPT to the host itself"),
    "ESP": ("foreign_files", r'-i\s+espp\d+\s+-p\s+tcp\s+--dport\s+(?P<backend>\d+)',
            "foreign", "layer-3 delivery: the carrier's own interface, INPUT ACCEPT to the host itself"),
}

# These two do not deliver to a local port at all: they are servers whose best outbound is `direct`, so the
# traffic leaves the host for the internet. Naming them is what keeps "no backend target found" from
# meaning "defect" - and the classification is still *checked* against the emitted text below, not trusted
# from this list, so a sing-box generator that ever grows a loopback delivery moves to the other branch.
BACKEND_EGRESS_PROXIES = ("singbox-vless-reality", "singbox-ss-2022")

# The transports whose delivery port the product can actually be told. Carriers are excluded on purpose and
# the exclusion is a refusal rather than a silent ignore (see `backend_port_refusal`): changing a carrier's
# delivery port means changing the DNAT destination on Iran *and* the INPUT rule on Foreign *and* the
# firewall manifest *and* their mirrored deletes, which is its own change with its own hardware A/B.
BACKEND_PORT_DECLARABLE = ("xray-reverse", "chisel-wss", "wstunnel-v10", "frp-TLS", "kcptun",
                           "rathole-noise", "backhaul-wss", "hysteria2")


def backend_target(protocol: str, plan: dict) -> dict:
    """Re-read the emitted plan to say where this tunnel's traffic is delivered, and whether anything
    is promised to be listening there.

    Statuses, and why each exists:
      `declared`          - the artifact names a delivery port. The product does NOT provision a listener
                            there; `provisions_backend` below is the honest answer to that, and it is False
                            for every transport today.
      `egress-proxy`      - the transport delivers to the internet, not to a local port (verified by there
                            being no loopback/target text in the plan, not by membership alone).
      `undeclared-target` - the plan is for a transport that must deliver somewhere, and no artifact says
                            where. That is a generator regression wearing the clothes of a healthy deploy,
                            and it is the status `engine.backend_target_block` refuses on.
    """
    out = {
        "protocol": protocol,
        "status": "undeclared-target",
        "kind": "unknown",
        "lands_on": "",
        "port": None,
        "source": "",
        "provisions_backend": False,
    }
    spec = BACKEND_TARGETS.get(protocol)
    side = spec[0] if spec else None
    blobs = (plan.get(side, {}) or {}) if side else {}
    # Both sides are searched when looking for a *provisioned* listener, because "the plan starts a server"
    # is a property of the whole deployment, and limiting it to the delivery host's own files would let a
    # backend started on the peer be missed.
    all_files = list((plan.get("iran_files", {}) or {}).items()) + \
              list((plan.get("foreign_files", {}) or {}).items())
    for _path, content in all_files:
        if isinstance(content, str) and _backend_provisioning_hit(content):
            out["provisions_backend"] = True
            break

    if spec is None:
        if protocol in BACKEND_EGRESS_PROXIES and not _any_loopback_target(all_files):
            out["status"] = "egress-proxy"
            out["kind"] = "egress proxy: outbound `direct`, no local delivery port in the plan"
        return out

    _side, pattern, lands, kind = spec
    for path, content in (plan.get(side, {}) or {}).items():
        if not isinstance(content, str):
            continue
        m = re.search(pattern, content)
        if m:
            out["status"] = "declared"
            out["kind"] = kind
            out["lands_on"] = lands
            out["port"] = int(m.group("backend"))
            line = content[:m.start()].count("\n") + 1
            out["source"] = f"{path}:{line}"
            return out
    # Named in the table, absent from the artifact: the delivery point moved or vanished.
    return out


def _backend_provisioning_hit(content: str) -> bool:
    """Does this artifact itself start a local service? (http server, iperf3 -s, socat, a listening unit)"""
    return re.search(r"http\.server|HTTPServer|iperf3\s+-s\b|socat\b|\bnc\s+-l\b|python3\s+-m\s+http",
                     content) is not None


def _any_loopback_target(files) -> bool:
    return any(isinstance(c, str) and re.search(r'127\.0\.0\.1:\d+|localPort\s*=\s*\d+|local_addr\s*=|'
                                                 r'"target":\s*"|--dport\s+\d+', c)
               for _p, c in files)


def backend_contract_view() -> dict:
    """The contract as data, for a renderer that must not keep its own copy of this table.

    The dashboard draws the delivery kind and the declarable/egress sets from this, because a second list
    written in JavaScript would drift from the one the deploy consults - and the drift would be silent on
    both sides. Read-only: it names kinds and protocol names, and never an address or a port, since the
    port a pair actually delivers to belongs to the pair row, not to the table.
    """
    return {
        "targets": {proto: {"kind": spec[3], "lands_on": spec[2], "side": spec[0]}
                    for proto, spec in BACKEND_TARGETS.items()},
        "declarable": list(BACKEND_PORT_DECLARABLE),
        "egress_proxies": list(BACKEND_EGRESS_PROXIES),
    }


def backend_port_refusal(protocol: str, frontend: int, backend_port) -> str:
    """A delivery port that cannot be implemented must be refused, not ignored.

    Returning a message instead of raising lets every call site phrase its own refusal, the way
    `carrier_camouflage_block` and `destination_pin_block` already do.
    """
    if backend_port in (None, "", 0) or int(backend_port) == int(frontend):
        return ""
    if protocol in BACKEND_PORT_DECLARABLE:
        return ""
    if protocol in BACKEND_EGRESS_PROXIES:
        return (f"{protocol} has no local delivery port to redirect: its outbound is `direct`, so a "
                f"backend_port declaration cannot be honoured. Leave it unset.")
    return (f"{protocol} cannot be given a separate backend port in this build: the delivery port is "
            f"derived from the frontend ({frontend}) by the carrier's own DNAT and INPUT rules, and "
            f"making it independent touches the rule, its mirrored delete and the boot manifest at once. "
            f"Declare backend_port only for {', '.join(BACKEND_PORT_DECLARABLE)}.")


def _validate_plan_configs(plan: dict, protocol: str, namespace: str) -> dict:
    """Parse every JSON config the generators emitted before anything is told to run it.

    A template that produces invalid JSON is invisible to a schema check written against the Python
    dict it never builds, and the first party to notice is the daemon on a live host: the xray bridge
    unit generated by §7.7 step 7 crash-looped on
    "infra/conf/serial: failed to read config file at line 27 char 7 >
     invalid character '{' after array element"
    while the portal side reported only 'empty worker list'. FailoverCandidateSelector then scored that
    transport 100% loss - a config syntax error wearing the clothes of a DPI verdict. Failing here
    costs a json.loads and cannot be mistaken for a measurement.
    """
    for side in ("iran_files", "foreign_files"):
        for fpath, content in plan.get(side, {}).items():
            if not fpath.endswith(".json") or not isinstance(content, str):
                continue
            try:
                json.loads(content)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{protocol}/{namespace} wrote a config {fpath} that its own parser rejects: "
                    f"{exc.msg} at line {exc.lineno} column {exc.colno}") from exc
    return plan


def generate_deployment(protocol: str, pair_id: int, ir_ip: str, fr_ip: str, frontend: int,
                        backend_port: int = None) -> dict:
    """Build the production plan for one transport, and name the port its traffic is delivered to.

    `backend_port` is the second end of the tunnel: the port on the peer host that must answer. Left unset
    the delivery stays where it always was - the frontend number, which is correct whenever a service
    really does listen on the same number on both hosts and was the only thing the generators could express
    before §8b. A value that the named transport cannot implement raises here rather than being dropped,
    because a silently-ignored declaration produces a tunnel that delivers to the frontend the operator
    just overrode.
    """
    gen = GENERATORS.get(protocol)
    if not gen:
        raise ValueError(f"Unknown protocol: {protocol}")
    refusal = backend_port_refusal(protocol, frontend, backend_port)
    if refusal:
        raise ValueError(refusal)
    kwargs = {"namespace": "prod"}
    if protocol in BACKEND_PORT_DECLARABLE:
        kwargs["backend_port"] = backend_port
    return _validate_plan_configs(gen(pair_id, ir_ip, fr_ip, frontend, **kwargs), protocol, "prod")

def generate_benchmark_plan(protocol: str, pair_id: int, ir_ip: str, fr_ip: str,
                            test_frontend: int = 8898, test_transport: int = 8897) -> dict:
    """Generates an isolated, non-colliding test deployment specifically for running ladder benchmarks.

    No `backend_port` is threaded through on purpose: the benchmark starts its own HTTP backend on the peer
    at `test_frontend` (engine.py:1626-1657) and requires a 200 from it, so its delivery port is *known* to
    be answered and is, by construction, the frontend. Making it configurable would let the sweep measure a
    tunnel whose backend it can no longer reach and score that as transport loss - the exact confusion §8b
    removes from the production path.
    """
    gen = GENERATORS.get(protocol)
    if not gen:
        raise ValueError(f"Unknown protocol for benchmark: {protocol}")
    if protocol == "GRE":
        plan = gen(pair_id, ir_ip, fr_ip, test_frontend, namespace="bench")
    else:
        plan = gen(pair_id, ir_ip, fr_ip, test_frontend, transport_port=test_transport, namespace="bench")

    # Hardening: cap the lifetime of ephemeral benchmark units. `Type=oneshot` ignores RuntimeMaxSec
    # outright - both live hosts logged "RuntimeMaxSec= has no effect in combination with
    # Type=oneshot. Ignoring." during the §7.7 step 7 GRE run - and a directive that is silently
    # ignored is worse than none, because the sweep looks bounded when it is not. A oneshot unit's
    # start phase is already bounded by systemd's default TimeoutStartSec, and a carrier's stop phase is
    # bounded by the `TimeoutStopUSec` its own unit declares, so those units are left alone instead of
    # being given a knob that does nothing. A carrier interface is not destroyed by the benchmark's
    # teardown either: it is brought down and reused by the next run, which is what keeps a measured
    # 450 s kernel unregister off the sweep's path.
    for fdict in (plan.get("iran_files", {}), plan.get("foreign_files", {})):
        for fpath, fcontent in list(fdict.items()):
            if fpath.endswith(".service") and "[Service]" in fcontent and "Type=oneshot" not in fcontent:
                fdict[fpath] = fcontent.replace("[Service]\n", "[Service]\nRuntimeMaxSec=600\n")

    return _validate_plan_configs(plan, protocol, "bench")


