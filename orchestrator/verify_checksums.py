#!/usr/bin/env python3
"""Provenance checker for the pinned release fingerprints in binary_manager.py.

Three modes:

  python3 verify_checksums.py               offline structural audit (no network, safe in CI)
  python3 verify_checksums.py --provenance  check each pin against an independent upstream attestation
  python3 verify_checksums.py --network     re-download every pinned asset and re-verify its SHA-256

The offline mode also cross-checks the sha256 literals inlined in the root *.sh installers against
the table, and audits installer hygiene (line endings, the GitHub-first mirror fallback shared with
binary_manager, and credentials left on an ExecStart line), so the two paths cannot drift apart.

--provenance is what makes a pin meaningful rather than circular. A hash computed from a download
only proves the download was stable; it does not prove the bytes are what upstream published. This
mode compares each pin against the checksum file upstream attaches to the same GitHub release, and
against the digest GitHub itself records for the asset.

Nothing is ever installed or written to disk by this tool; --network hashes in memory.
"""
import hashlib
import io
import ipaddress
import json
import os
import re
import sys
import tarfile
import urllib.request
import zipfile

import binary_manager

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHA256_RE = re.compile(r"\b[0-9a-f]{64}\b")
GITHUB_URL_RE = re.compile(r"https://github\.com/[^\s\"']+")
IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
ALLOWED_HOSTS = {"github.com", "objects.githubusercontent.com"}
UA = {"User-Agent": "BestTunnel-Provenance/2.0"}
RELEASE_URL_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+)/releases/download/([^/]+)/(.+)$")
# Shell variables whose name says they hold a secret. Interpolating one into ExecStart is the leak:
# systemd expands it into the command line, which any local user can read via /proc/<pid>/cmdline.
CREDENTIAL_VAR_RE = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*(PASS|PASSWD|SECRET|TOKEN|CREDENTIAL)[A-Za-z0-9_]*\}?",
                               re.IGNORECASE)
# chisel reads its authfile as map[string][]string ({"<user:pass>": ["<addr-regex>"]}). A
# users-keyed array of username/password objects is the other shape authors reach for, and the
# binary refuses it at startup - a config offline review calls valid and the server cannot parse.
CHISEL_BAD_AUTHFILE_RE = re.compile(r'["\']users["\']\s*:\s*\[\s*\{\s*["\']username["\']')
# Spellings of "do not verify the peer" across the config languages the shipped files use:
# Go/YAML (gost), snake_case variants, JSON/YAML `"insecure": true` (sing-box style), and the
# CLI token chisel/wstunnel take. Until F4 the audit searched for exactly one of these
# (`tls-skip-verify`) and only on ExecStart= lines, so the GOST installer's
# `insecureSkipVerify: true` - inside a YAML heredoc, on no ExecStart line at all - was
# invisible to it. The patterns are assignment-shaped on purpose: prose that merely names
# a spelling (the chisel installers explain in comments why they refuse it) must not trip
# the rule, and comment lines are skipped by the caller for the same reason.
TLS_DISABLE_RES = [
    re.compile(r"insecureSkipVerify\s*:\s*true", re.IGNORECASE),
    re.compile(r"insecure_skip_verify\s*[:=]\s*true", re.IGNORECASE),
    re.compile(r"[\"']?insecure[\"']?\s*:\s*true", re.IGNORECASE),
    re.compile(r"(?<![\w-])tls-skip-verify(?![\w-])"),
]
# Files exempt from the TLS-disable scan only (every other rule still applies): this
# checker, which must name the tokens to hunt them, and the offline suite, which holds
# adversarial fixtures and assertions naming them on purpose.
TLS_SCAN_EXEMPT = {"orchestrator/verify_checksums.py", "orchestrator/test_offline_suite.py"}
GITHUB_API_RELEASE = "https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"

# Checksum file each project publishes inside the same release as the asset we pin:
# binary -> (owner/repo, tag, published checksum filename, asset name inside it).
UPSTREAM_INTEGRITY_FILES = {
    "wstunnel": ("erebe/wstunnel", "v10.1.7", "checksums.txt", "wstunnel_10.1.7_linux_amd64.tar.gz"),
    "chisel": ("jpillora/chisel", "v1.10.1", "chisel_1.10.1_checksums.txt", "chisel_1.10.1_linux_amd64.gz"),
    "frp": ("fatedier/frp", "v0.71.0", "frp_sha256_checksums.txt", "frp_0.71.0_linux_amd64.tar.gz"),
    "backhaul": ("musixal/backhaul", "v0.7.2", "checksums.txt", "backhaul_linux_amd64.tar.gz"),
    "gost": ("go-gost/gost", "v3.3.0", "checksums.txt", "gost_3.3.0_linux_amd64.tar.gz"),
}


def _fail(problems: list, msg: str) -> None:
    problems.append(msg)
    print(f"  [FAIL] {msg}")


def audit_table() -> list[str]:
    """Structural invariants that must hold for every pinned entry."""
    problems: list[str] = []
    print("[*] Auditing OFFICIAL_CHECKSUMS structure")
    for binary, versions in binary_manager.OFFICIAL_CHECKSUMS.items():
        if not versions:
            _fail(problems, f"{binary}: no pinned versions")
        for version, arches in versions.items():
            for arch, entry in arches.items():
                tag = f"{binary} {version} {arch}"
                sha = entry.get("sha256", "")
                url = entry.get("url", "")
                if not re.fullmatch(r"[0-9a-f]{64}", sha):
                    _fail(problems, f"{tag}: sha256 is not 64 lowercase hex chars: {sha!r}")
                if not url.startswith("https://"):
                    _fail(problems, f"{tag}: url is not https: {url!r}")
                else:
                    host = url.split("/")[2]
                    if host not in ALLOWED_HOSTS:
                        _fail(problems, f"{tag}: url host '{host}' is not an approved release host")
                kind = entry.get("archive")
                if kind not in ("zip", "gz", "tar.gz", "raw"):
                    _fail(problems, f"{tag}: unknown archive kind {kind!r}")
                elif kind != "raw":
                    # "raw" is an uncompressed single executable (hysteria):
                    # the download IS the binary, so no archive suffix exists
                    # to match against - the suffix check is meaningless for it.
                    expected_suffix = {"zip": ".zip", "gz": ".gz", "tar.gz": ".tar.gz"}[kind]
                    if not url.endswith(expected_suffix):
                        _fail(problems, f"{tag}: archive kind '{kind}' does not match url suffix '{url}'")
                binaries = entry.get("binaries") or {}
                if not binaries:
                    _fail(problems, f"{tag}: no install targets declared")
                for src, dest in binaries.items():
                    if not dest.startswith("/usr/local/bin/"):
                        _fail(problems, f"{tag}: install target '{dest}' is outside /usr/local/bin")
    if not problems:
        print(f"  OK - {sum(len(v) for v in binary_manager.OFFICIAL_CHECKSUMS.values())} pinned release(s)")
    return problems


def audit_shell_scripts() -> list[str]:
    """Every sha256 and release URL literal in a root installer must be a pinned fingerprint."""
    problems: list[str] = []
    print("[*] Cross-checking sha256 and URL literals in root *.sh installers")
    pinned = {
        e["sha256"]
        for versions in binary_manager.OFFICIAL_CHECKSUMS.values()
        for arches in versions.values()
        for e in arches.values()
    }
    pinned_urls = {
        e["url"]
        for versions in binary_manager.OFFICIAL_CHECKSUMS.values()
        for arches in versions.values()
        for e in arches.values()
    }
    scripts = sorted(f for f in os.listdir(REPO_ROOT) if f.endswith(".sh"))
    if not scripts:
        _fail(problems, "no root .sh installers found")
    checked = 0
    for name in scripts:
        path = os.path.join(REPO_ROOT, name)
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        if "curl " not in text and "wget " not in text:
            continue
        releases = [u for u in GITHUB_URL_RE.findall(text) if "/releases/download/" in u]
        if not releases:
            continue
        checked += 1
        found = set(SHA256_RE.findall(text))
        if not found:
            _fail(problems, f"{name}: downloads a release binary but pins no SHA-256")
            continue
        if "sha256sum" not in text:
            _fail(problems, f"{name}: pins a hash but never calls sha256sum")
        for sha in sorted(found - pinned):
            _fail(problems, f"{name}: sha256 {sha} is not in OFFICIAL_CHECKSUMS")
        for url in sorted(set(releases) - pinned_urls):
            _fail(problems, f"{name}: release URL is not pinned in OFFICIAL_CHECKSUMS: {url}")
    if not problems:
        print(f"  OK - {checked} downloading installer(s) verified against the pinned table")
    return problems


def canonical_mirror_loop() -> str:
    """The exact fallback-loop header every downloading installer must carry.

    Built from binary_manager.MIRROR_PREFIXES so the two download paths cannot drift: changing the
    mirror list there breaks this audit until the standalone installers are updated to match.
    """
    candidates = ' '.join(['"$URL"'] + [f'"https://{p.split("://", 1)[1]}$URL"'
                                        for p in binary_manager.MIRROR_PREFIXES])
    return f"for u in {candidates}; do"


# Shell variables in the standalone installers that hold a tunnel credential.
INSTALLER_SECRET_RE = re.compile(r"\$(?:\{)?(BH_TOKEN|F_TOKEN|R_TOKEN|TUN_UUID|NOISE_PUB|CH_PASS)\b")
# `cat > path <<EOF` (unquoted EOF, so the shell expands credentials into the file) ...
HEREDOC_WRITE_RE = re.compile(r"^cat > (\S+) <<EOF$")
# ... and the grouped form `{ echo ...; } > path`.
GROUP_WRITE_RE = re.compile(r"^\} > (\S+)$")


def secret_config_writes(text: str) -> list[tuple[str, int, int]]:
    """Locates every config write that interpolates a credential.

    Returns (path, start_line_index, end_line_index) for each. Both shell forms are covered, because
    the installers use a heredoc for some protocols and a grouped redirect for others.
    """
    lines = text.split("\n")
    found = []
    i = 0
    while i < len(lines):
        m = HEREDOC_WRITE_RE.match(lines[i])
        if m:
            j = i + 1
            while j < len(lines) and lines[j] != "EOF":
                j += 1
            if INSTALLER_SECRET_RE.search("\n".join(lines[i:j + 1])):
                found.append((m.group(1), i, j))
            i = j + 1
            continue
        mg = GROUP_WRITE_RE.match(lines[i])
        if mg:
            k = i - 1
            while k >= 0 and lines[k].strip() != "{":
                k -= 1
            if k >= 0 and INSTALLER_SECRET_RE.search("\n".join(lines[k:i + 1])):
                found.append((mg.group(1), k, i))
        i += 1
    return found


def undocumented_public_ips(text: str) -> list[tuple[int, str]]:
    """Lines holding an IPv4 literal that is globally routable, i.e. a real host address.

    Loopback, link-local, multicast, reserved, RFC 1918 and the three RFC 5737 documentation
    ranges are all allowed - every fixture is supposed to use documentation space. A routable
    address is operational data about real infrastructure: it survived in this repository as a
    committed Foreign-side IP, and callers must not echo the value while reporting it.

    Like safety.check_command_safe, this matches literals, so an address assembled at runtime
    slips past it. That is acceptable: the failure mode being policed is a hand-edited installer
    committed with a real server in it, not a determined author.
    """
    found: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for candidate in IPV4_RE.findall(line):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip.is_global:
                found.append((lineno, candidate))
    return found


def audit_installer_hygiene() -> list[str]:
    """Platform and hygiene invariants for the root installers.

    Six failure modes that a checksum audit cannot see:
      * CRLF line endings - bash on Linux chokes on them and the shebang stops resolving, so a
        script that passes review on Windows fails at the first command on Debian.
      * A downloader without the canonical GitHub-first mirror fallback, or with a mirror list that
        has drifted from binary_manager.MIRROR_PREFIXES.
      * A credential on an ExecStart line, which is world-readable through /proc/<pid>/cmdline
        for the whole life of the service - or a disabled TLS check anywhere in a shipped file,
        in any of its spellings (F4: the ExecStart-only, single-spelling version of this rule
        could not see a YAML `insecureSkipVerify: true` in an installer heredoc).
      * A credential written to a config file with the default umask, which leaves it 0644 and
        readable by every local user. The orchestrator path already writes 0600 (engine.py:345,
        failover.py:238); the standalone installers must match.
      * A real server address committed into a tracked file, which is the exposure the repository's
        own history accepted only for destroyed servers and never for the working tree.
      * A config written in a schema the target binary does not parse. The one found live was a
        chisel authfile in the users-keyed array form: the offline suite asserted its shape, the
        real server exited 1 on it, and only a running host could tell the two apart.
    """
    problems: list[str] = []
    print("[*] Auditing root installer hygiene (line endings, mirror fallback, secret exposure)")
    canonical = canonical_mirror_loop()
    scripts = sorted(f for f in os.listdir(REPO_ROOT) if f.endswith(".sh"))
    tracked_text = [os.path.join(REPO_ROOT, name) for name in scripts]
    orch = os.path.join(REPO_ROOT, "orchestrator")
    if os.path.isdir(orch):
        tracked_text += sorted(os.path.join(orch, f) for f in os.listdir(orch) if f.endswith(".py"))
    for path in tracked_text:
        rel = os.path.relpath(path, REPO_ROOT).replace(os.sep, "/")
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        text = raw.decode("utf-8", errors="replace")
        for lineno, _addr in undocumented_public_ips(text):
            # Deliberately not quoting the address or the line: this output is meant to be pasted.
            _fail(problems, f"{rel}:{lineno}: commits a routable IPv4 address; use RFC 5737 "
                           f"documentation space and take the real one from the environment")
        for lineno, line in enumerate(text.splitlines(), 1):
            if CHISEL_BAD_AUTHFILE_RE.search(line):
                _fail(problems, f"{rel}:{lineno}: writes a chisel authfile in the users-keyed array "
                                f"form, which chisel 1.10.1 refuses with 'Invalid JSON' at startup; "
                                f"the accepted shape is documented in --authfile help")
        if rel not in TLS_SCAN_EXEMPT:
            for lineno, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if rel.endswith(".sh") and stripped.startswith("ExecStart="):
                    continue  # the dedicated ExecStart pass below reports those
                if any(rx.search(line) for rx in TLS_DISABLE_RES):
                    _fail(problems, f"{rel}:{lineno}: disables TLS verification; a peer that "
                                    f"cannot prove itself must be refused, not waved through "
                                    f"(F4: this scan used to see only ExecStart lines and one "
                                    f"spelling, which is how a YAML config slipped past it)")
    downloaders = 0
    for name in scripts:
        path = os.path.join(REPO_ROOT, name)
        with open(path, "rb") as fh:
            raw = fh.read()
        if b"\r\n" in raw:
            _fail(problems, f"{name}: has CRLF line endings; bash on Linux will not run it")
        text = raw.decode("utf-8", errors="replace")
        is_downloader = "/releases/download/" in text
        if is_downloader:
            downloaders += 1
            if canonical not in text:
                _fail(problems, f"{name}: download has no canonical GitHub-first mirror fallback")
        elif "for u in" in text:
            _fail(problems, f"{name}: carries a mirror loop but downloads no release asset")
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("ExecStart="):
                continue
            # --authfile is fine (a 0600 path); --auth / --auth= puts the secret in argv.
            if re.search(r"--auth(?![A-Za-z-])", stripped):
                _fail(problems, f"{name}: ExecStart passes --auth inline, leaking it into argv")
            if CREDENTIAL_VAR_RE.search(stripped):
                _fail(problems, f"{name}: ExecStart interpolates a credential variable: {stripped[:110]}")
            if "tls-skip-verify" in stripped:
                _fail(problems, f"{name}: ExecStart disables TLS verification")
        # A serving certificate needs a subjectAltName: Go (and therefore chisel, frp and backhaul)
        # rejects CN-only certificates, so omitting the SAN does not merely weaken verification, it
        # makes verification impossible and invites someone to disable it.
        for lineno, line in enumerate(text.splitlines(), 1):
            if "openssl req -x509" in line and "subjectAltName" not in line:
                _fail(problems, f"{name}:{lineno}: self-signed serving certificate has no subjectAltName")
        # A credential written to a config file must not be left world-readable. umask is shell
        # state rather than a per-line directive, so what matters is the last umask in effect at the
        # point of the write - not whether it sits on the immediately preceding line.
        lines = text.split("\n")
        for target, start, end in secret_config_writes(text):
            effective = None
            for prior in lines[:start]:
                mu = re.match(r"^\s*umask\s+(\S+)", prior)
                if mu:
                    effective = mu.group(1)
            if effective != "077":
                _fail(problems, f"{name}: {target} holds a credential but the umask in effect at the "
                                f"write is {effective!r}, not 077")
            after = lines[end + 1].strip() if end + 1 < len(lines) else ""
            if after != f"chmod 600 {target}":
                _fail(problems, f"{name}: {target} holds a credential but is never chmod 600")
    if not problems:
        print(f"  OK - {len(scripts)} installer(s), {downloaders} downloader(s), all LF, "
              f"uniform mirror fallback, no credential in argv or in a world-readable "
              f"config, no routable address committed, no config the binary cannot parse")
    return problems


def _archive_members(kind: str, data: bytes) -> list[str]:
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return z.namelist()
    if kind == "gz":
        return ["<single gzip member>"]
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        return t.getnames()


def verify_network() -> list[str]:
    """Re-download each pinned asset and confirm its SHA-256 and expected contents."""
    problems: list[str] = []
    print("[*] Re-verifying pinned assets against upstream (network)")
    for binary, versions in binary_manager.OFFICIAL_CHECKSUMS.items():
        for version, arches in versions.items():
            for arch, entry in arches.items():
                tag = f"{binary} {version} {arch}"
                url = entry["url"]
                try:
                    req = urllib.request.Request(url, headers=UA)
                    with urllib.request.urlopen(req, timeout=180) as resp:
                        data = resp.read()
                except Exception as exc:
                    _fail(problems, f"{tag}: download failed ({exc})")
                    continue
                actual = hashlib.sha256(data).hexdigest()
                if actual != entry["sha256"]:
                    _fail(problems, f"{tag}: SHA-256 mismatch\n         pinned={entry['sha256']}\n         actual={actual}")
                    continue
                names = _archive_members(entry["archive"], data)
                basenames = {os.path.basename(n) for n in names}
                for src in entry["binaries"]:
                    if entry["archive"] != "gz" and src not in basenames:
                        _fail(problems, f"{tag}: expected member '{src}' missing; archive holds {sorted(basenames)}")
                print(f"  OK - {tag} {len(data)} bytes sha256={actual[:16]}...")
    return problems


def _fetch(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _published_digest(binary: str, asset: str) -> tuple[str, str]:
    """Reads the checksum file upstream published alongside the asset. Returns (digest, source)."""
    spec = UPSTREAM_INTEGRITY_FILES.get(binary)
    if not spec:
        return "", ""
    repo, tag, fname, expected_asset = spec
    if expected_asset != asset:
        return "", ""
    try:
        text = _fetch(f"https://github.com/{repo}/releases/download/{tag}/{fname}").decode("utf-8", "replace")
    except Exception:
        return "", ""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == asset:
            return parts[0].lower().removeprefix("sha256:"), f"{repo}@{tag}:{fname}"
    return "", ""


def _github_asset_digest(owner: str, repo: str, tag: str, asset: str) -> str:
    """Digest GitHub records for a release asset. Only populated for some repositories."""
    try:
        data = json.loads(_fetch(GITHUB_API_RELEASE.format(owner=owner, repo=repo, tag=tag), 30))
    except Exception:
        return ""
    for a in data.get("assets", []):
        digest = a.get("digest") or ""
        if a.get("name") == asset and digest.startswith("sha256:"):
            return digest.removeprefix("sha256:")
    return ""


def verify_provenance() -> list[str]:
    """Confirms each pin against an attestation independent of our own download.

    A pin with no upstream attestation is reported as trust-on-first-use rather than as a failure:
    it still freezes the bytes and detects any later substitution, but it cannot prove the asset was
    not already tampered with at the moment it was pinned.
    """
    problems: list[str] = []
    print("[*] Checking pin provenance against upstream attestations (network)")
    for binary, versions in binary_manager.OFFICIAL_CHECKSUMS.items():
        for version, arches in versions.items():
            for arch, entry in arches.items():
                tag = f"{binary} {version} {arch}"
                pinned = entry["sha256"]
                m = RELEASE_URL_RE.match(entry["url"])
                if not m:
                    _fail(problems, f"{tag}: url is not a GitHub release download URL")
                    continue
                owner, repo, rel_tag, asset = m.groups()

                attestations = []
                published, source = _published_digest(binary, asset)
                if published:
                    if published != pinned:
                        _fail(problems, f"{tag}: pin disagrees with upstream {source}"
                                        f"\n         upstream={published}\n         pinned  ={pinned}")
                        continue
                    attestations.append(f"upstream checksum file ({source})")
                gh = _github_asset_digest(owner, repo, rel_tag, asset)
                if gh:
                    if gh != pinned:
                        _fail(problems, f"{tag}: pin disagrees with the GitHub asset digest"
                                        f"\n         github={gh}\n         pinned={pinned}")
                        continue
                    attestations.append("GitHub release asset digest")

                if attestations:
                    print(f"  OK   - {tag} attested by: {'; '.join(attestations)}")
                else:
                    print(f"  TOFU - {tag} upstream publishes no checksum file and GitHub records no "
                          f"asset digest; pin is trust-on-first-use over TLS from {owner}/{repo}@{rel_tag}")
    return problems


def main() -> int:
    problems = audit_table() + audit_shell_scripts() + audit_installer_hygiene()
    network_requested = "--network" in sys.argv or "--provenance" in sys.argv
    if "--provenance" in sys.argv:
        problems += verify_provenance()
    if "--network" in sys.argv:
        problems += verify_network()
    if not network_requested:
        print("[*] Skipped network checks (pass --provenance and/or --network to run them)")
    print()
    if problems:
        print(f"RESULT: {len(problems)} problem(s) found")
        return 1
    print("RESULT: all pinned fingerprints and installer invariants verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
