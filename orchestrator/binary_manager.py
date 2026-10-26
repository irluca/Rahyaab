#!/usr/bin/env python3
"""Binary Manager and Cryptographic Checksum Verification (R-21 / Sprint 2).
Enforces strict SHA-256 integrity verification on all downloaded external tunneling binaries
(sing-box, wstunnel, rathole, etc.) BEFORE marking them executable or running them.
Rejects any binary whose checksum does not match the pinned official release fingerprint.

This table is the single source of truth for release fingerprints AND for the mirror fallback list.
The root *.sh installers inline the same literals so they can run standalone; `verify_checksums.py`
cross-checks the two, fails if either drifts, and can re-verify every entry against upstream.
"""
import os
import hashlib

# Only amd64 fingerprints have been verified. Any other architecture fails closed rather than
# downloading something nobody has checked.
SUPPORTED_ARCH = "amd64"

# Pinned official release SHA-256 checksums (linux-amd64) for all tunnel binaries (R-21 / P0-2).
# `binaries` maps the name inside the archive to its install target, because several releases do
# not ship a file named after the project (frp ships frpc/frps, and kcptun is apt-only below).
OFFICIAL_CHECKSUMS = {
    "sing-box": {
        "v1.10.1": {
            "amd64": {
                "sha256": "9ec157ec77ffd53054975263fc604e02411d664c422e524272ff3bab23664d31",
                "url": "https://github.com/SagerNet/sing-box/releases/download/v1.10.1/sing-box-1.10.1-linux-amd64.tar.gz",
                "archive": "tar.gz",
                "binaries": {"sing-box": "/usr/local/bin/sing-box"}
            }
        }
    },
    # Hysteria2 graduated 2026-10-24 after a live witness over the GRE
    # carrier (page fetch + iperf both ways through tcpForwarding).
    # Upstream moved from apernet/hysteria to HyNetworks/hysteria; the
    # release ships hashes.txt, and the value below is the one that file
    # carries for hysteria-linux-amd64 (verified live on both test hosts).
    "hysteria": {
        "v2.13.0": {
            "amd64": {
                "sha256": "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691",
                "url": "https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-amd64",
                "archive": "raw",
                "binaries": {"hysteria": "/usr/local/bin/hysteria"}
            }
        }
    },
    "rathole": {
        "v0.5.0": {
            "amd64": {
                "sha256": "3e7d0d0f365120cd3cd351d147d1a12ee960c8068b464d4dd533a3821873b80e",
                "url": "https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-gnu.zip",
                "archive": "zip",
                "binaries": {"rathole": "/usr/local/bin/rathole"}
            }
        }
    },
    "wstunnel": {
        "v10.1.7": {
            "amd64": {
                "sha256": "79c5beda18655d8ededd507995d9aebd524c35ddc7abfd0aa733b98b3fb895a4",
                "url": "https://github.com/erebe/wstunnel/releases/download/v10.1.7/wstunnel_10.1.7_linux_amd64.tar.gz",
                "archive": "tar.gz",
                "binaries": {"wstunnel": "/usr/local/bin/wstunnel"}
            }
        }
    },
    "chisel": {
        "v1.10.1": {
            "amd64": {
                "sha256": "0525aa3c5d457f2a4075e66221d5125d434bedf15006d3271c213f5cd6ff2230",
                "url": "https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz",
                "archive": "gz",
                "binaries": {"chisel": "/usr/local/bin/chisel"}
            }
        }
    },
    "frp": {
        "v0.71.0": {
            "amd64": {
                "sha256": "84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716",
                "url": "https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_linux_amd64.tar.gz",
                "archive": "tar.gz",
                "binaries": {"frpc": "/usr/local/bin/frpc", "frps": "/usr/local/bin/frps"}
            }
        }
    },
    "xray": {
        "v24.11.30": {
            "amd64": {
                "sha256": "679d6ec1c2ecabd84ad1e2deab6e52789c52f0a387902cc72e135a3bb3949554",
                "url": "https://github.com/XTLS/Xray-core/releases/download/v24.11.30/Xray-linux-64.zip",
                "archive": "zip",
                "binaries": {"xray": "/usr/local/bin/xray"}
            }
        }
    },
    "backhaul": {
        "v0.7.2": {
            "amd64": {
                "sha256": "57bf95c2eabeddb1152d2e94ac42f4310883ce0fb909ee2a57bd53503b2dabbc",
                "url": "https://github.com/musixal/backhaul/releases/download/v0.7.2/backhaul_linux_amd64.tar.gz",
                "archive": "tar.gz",
                "binaries": {"backhaul": "/usr/local/bin/backhaul"}
            }
        }
    },
    "gost": {
        "v3.3.0": {
            "amd64": {
                "sha256": "676fb7f78d267b6ae73df719c0c7f2b565dde7147da935cfafbc1e1da558b6d5",
                "url": "https://github.com/go-gost/gost/releases/download/v3.3.0/gost_3.3.0_linux_amd64.tar.gz",
                "archive": "tar.gz",
                "binaries": {"gost": "/usr/local/bin/gost"}
            }
        }
    }
}

# SHA-256 of the file a verified install leaves at each destination, keyed by
# (binary, version, arch). The archive pin in OFFICIAL_CHECKSUMS stays the root
# of trust: these values were measured from installs the verified path itself
# performed (both test hosts, 2026-10-23, byte-identical), so a file hashing to
# the value here is exactly what the pinned archive produced. This lets
# verify_and_install_binary prove an existing install with one local sha256sum
# instead of re-downloading the release on every deploy - on a filtered route
# that download is the slowest, most fragile step of the deploy gate (F7,
# live finding 2026-10-23: two rathole deploys stalled inside it while every
# other step of the same sessions completed). A missing or mismatching file
# falls through to the full verified install, unchanged.
PINNED_INSTALLED_SHA256 = {
    ("rathole", "v0.5.0", "amd64"): {
        "/usr/local/bin/rathole": "d2202f2aa3a432135bddbe1c6104600c6577cd4507a70e77c08741c7ad879926",
    },
    # Raw binary: installed file hash == download hash by construction,
    # and the live witness measured exactly this value on both hosts.
    ("hysteria", "v2.13.0", "amd64"): {
        "/usr/local/bin/hysteria": "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691",
    },
    ("backhaul", "v0.7.2", "amd64"): {
        "/usr/local/bin/backhaul": "7f1b1439d7fe1d15ae0b376e15614fe13d8a12f6e07a90263e310ea2a9d601fb",
    },
    ("chisel", "v1.10.1", "amd64"): {
        "/usr/local/bin/chisel": "0a76c28f5452dbbc146752d0b4e28b10779a337091f59650b94f5e938545572c",
    },
    ("frp", "v0.71.0", "amd64"): {
        "/usr/local/bin/frpc": "f79fff8de3089ec711ff8bdd4b73e00dfe491a1c3d754983c8b0f8d58c21b068",
        "/usr/local/bin/frps": "b95dee2bf29a021c562565cdf2116376b9fa7590361bd36ef57041a04d0e6654",
    },
    ("wstunnel", "v10.1.7", "amd64"): {
        "/usr/local/bin/wstunnel": "c486e46da3a351baaf7e1ee4582f0d14f9c7979aee6da3ddea0777986714e985",
    },
    ("xray", "v24.11.30", "amd64"): {
        "/usr/local/bin/xray": "59cd82b3531b1b0d4026d69a90e948f09fb40bd7aa7e23713ef9d07facbf106d",
    },
}

# Binaries installed through the distribution package manager instead of a GitHub download.
# Trust comes from the distro's signed repository rather than a pinned hash. kcptun is here
# because github.com/xtaci/kcptun is not reachable to establish provenance for a release asset.
APT_PACKAGES = {
    "iperf3": {
        "package": "iperf3",
        "probe": "iperf3",
        "verify": 'IPERF_VER=$(iperf3 -v | head -n 1)\necho "[SUCCESS] iperf3 verified: $IPERF_VER"',
        "links": {}
    },
    "kcptun": {
        "package": "kcptun",
        "probe": "kcptun-server",
        "verify": 'KCP_VER=$(dpkg-query -W -f=\'${Version}\' kcptun)\necho "[SUCCESS] kcptun verified via dpkg: $KCP_VER"',
        # protocols.py addresses /usr/local/bin/kcptun-{client,server}; Debian installs to /usr/bin.
        "links": {
            "/usr/local/bin/kcptun-client": "/usr/bin/kcptun-client",
            "/usr/local/bin/kcptun-server": "/usr/bin/kcptun-server"
        }
    }
}

# Fallback mirrors for hosts that cannot reach github.com (the Iran side). The official release
# URL is ALWAYS tried first; a mirror is only contacted after a network failure.
#
# These mirrors are untrusted third parties. What makes them usable is not the transport but the
# pinned SHA-256 that follows every download: if the bytes do not match the fingerprint published
# by upstream, the install aborts regardless of where they came from. Verification is therefore
# never conditional on the source, and a mirror can only cause a failed install, never a wrong one.
#
# This tuple is the single source of truth for both download paths. The root *.sh installers inline
# the same list so they can run standalone, and verify_checksums.audit_mirror_fallback() fails if
# the two drift apart.
MIRROR_PREFIXES = (
    "https://ghproxy.net/",
    "https://mirror.ghproxy.com/",
    "https://gh.ddlc.top/",
)


def download_candidates(url: str) -> list[str]:
    """Orders download sources for a pinned release URL: GitHub first, then each mirror.

    Order is a security property as well as an availability one - contacting a third-party mirror
    discloses this host's address to it, so mirrors stay unreachable in the common case.
    """
    return [url] + [f"{prefix}{url}" for prefix in MIRROR_PREFIXES]


def compute_file_sha256(filepath: str) -> str:
    """Computes SHA-256 hash of a local file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


def verify_file_sha256(filepath: str, expected_sha256: str) -> bool:
    """Verifies that the file at filepath exactly matches expected SHA-256."""
    if not os.path.isfile(filepath):
        return False
    return compute_file_sha256(filepath) == expected_sha256.strip().lower()


def latest_pinned_version(binary: str) -> str:
    versions = list(OFFICIAL_CHECKSUMS.get(binary, {}).keys())
    if not versions:
        raise ValueError(f"No pinned releases recorded for {binary}")
    return versions[-1]


def get_pinned_checksum(binary: str, version: str | None = None, arch: str = SUPPORTED_ARCH) -> str:
    """Retrieves the pinned official SHA-256 checksum for a binary, or "" if none exists."""
    if version is None:
        version = latest_pinned_version(binary)
    return OFFICIAL_CHECKSUMS.get(binary, {}).get(version, {}).get(arch, {}).get("sha256", "")


def get_download_url(binary: str, version: str | None = None, arch: str = SUPPORTED_ARCH) -> str:
    if version is None:
        version = latest_pinned_version(binary)
    return OFFICIAL_CHECKSUMS.get(binary, {}).get(version, {}).get(arch, {}).get("url", "")


def _resolve_entry(binary: str, version: str | None, arch: str) -> tuple[str, dict]:
    """Fails closed: an unpinned version or unsupported architecture must never resolve to a
    best-effort substitute, because that is how an unverified binary gets installed."""
    if arch != SUPPORTED_ARCH:
        raise ValueError(
            f"No verified fingerprint for {binary} on arch '{arch}'. "
            f"Only '{SUPPORTED_ARCH}' is pinned; refusing to install an unverified build."
        )
    versions = OFFICIAL_CHECKSUMS.get(binary)
    if not versions:
        raise ValueError(f"No pinned checksum or URL found for {binary}")
    if version is None:
        version = latest_pinned_version(binary)
    entry = versions.get(version, {}).get(arch)
    if not entry:
        raise ValueError(
            f"No pinned checksum for {binary} {version} ({arch}). "
            f"Pinned versions: {', '.join(versions)}"
        )
    return version, entry


def generate_secure_install_script(binary: str, version: str | None = None, arch: str = SUPPORTED_ARCH) -> str:
    """Generates a fail-closed, self-verifying installation bash script (R-21 / Auditor Finding 3-3).
    - Protects against symlink-race (R-50) using mktemp -d and an automatic trap cleanup.
    - Aborts with a non-zero exit code if checksum verification fails.
    - Uses the verified precompiled release archive, or the signed distro repository for
      iperf3/kcptun which have no trustworthy standalone release asset.
    """
    if binary in APT_PACKAGES:
        return _generate_apt_script(binary, APT_PACKAGES[binary])

    version, entry = _resolve_entry(binary, version, arch)
    expected_hash = entry["sha256"]
    url = entry["url"]
    archive_kind = entry["archive"]
    binaries = entry["binaries"]

    if archive_kind == "zip":
        archive_name = f"{binary}-{version}.zip"
        extract_cmd = f"unzip -q -o '{archive_name}' 2>/dev/null || python3 -m zipfile -e '{archive_name}' ."
    elif archive_kind == "gz":
        # Single gzip-compressed executable, not a tarball (chisel).
        archive_name = f"{binary}-{version}.gz"
        first = next(iter(binaries))
        extract_cmd = f"gzip -d -c '{archive_name}' > '{first}'"
    elif archive_kind == "raw":
        # Uncompressed single executable (hysteria): the download IS the
        # binary, so there is nothing to extract - install_bin finds it
        # by its own name and moves it into place. The archive name is
        # the binary name on purpose: install_bin searches by that name.
        archive_name = binary
        extract_cmd = "true"
    else:
        archive_name = f"{binary}-{version}.tar.gz"
        extract_cmd = f"tar -xzf '{archive_name}'"

    install_lines = []
    for src_name, dest in binaries.items():
        install_lines.append(f'install_bin "{src_name}" "{dest}"')
    install_block = "\n".join(install_lines)

    candidates = " ".join(f'"{u}"' for u in download_candidates(url))

    return f"""#!/usr/bin/env bash
set -euo pipefail

TMP_DIR=$(mktemp -d "/tmp/best_tunnel_{binary}_XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT
cd "$TMP_DIR"

fetch() {{
    # $1 is the output path; every remaining argument is a candidate source, tried in order.
    local out="$1"; shift
    local src
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        echo "[ERROR] Neither curl nor wget is available" >&2
        exit 1
    fi
    for src in "$@"; do
        echo "[INFO]   source: $src"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL --retry 3 --max-time 120 -o "$out" "$src" && return 0
        else
            wget -q --tries=3 --timeout=120 -O "$out" "$src" && return 0
        fi
        rm -f "$out"
    done
    # No source produced a file. Fail here rather than letting the checksum step report a
    # confusing "mismatch" against an empty download.
    echo "[ERROR] every download source failed for $out" >&2
    return 1
}}

install_bin() {{
    found=$(find . -maxdepth 3 -type f -name "$1" | head -n 1)
    if [ -z "$found" ]; then
        echo "[ERROR] Binary '$1' not found inside the verified archive!" >&2
        exit 1
    fi
    chmod 755 "$found"
    mv "$found" "$2"
    echo "[SUCCESS] installed $2"
}}

echo "[INFO] Downloading {binary} {version} (official release first, mirrors only on failure)..."
fetch "{archive_name}" {candidates}

echo "[INFO] Verifying SHA-256 checksum (R-21 / P0-2)..."
EXPECTED_HASH="{expected_hash}"
ACTUAL_HASH=$(sha256sum "{archive_name}" | awk '{{print $1}}')

if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
    echo "[SECURITY ERROR] SHA-256 mismatch for {binary}!" >&2
    echo "Expected: $EXPECTED_HASH" >&2
    echo "Actual:   $ACTUAL_HASH" >&2
    exit 1
fi

echo "[INFO] Checksum verified: $ACTUAL_HASH"
{extract_cmd}
{install_block}
echo "[SUCCESS] {binary} {version} securely verified and installed"
"""


def _generate_apt_script(binary: str, spec: dict) -> str:
    link_lines = [f'ln -sf "{src}" "{dest}"' for dest, src in spec["links"].items()]
    link_block = ("\n" + "\n".join(link_lines)) if link_lines else ""
    package = spec["package"]
    probe_cmd = spec["probe"]
    return f"""#!/usr/bin/env bash
set -euo pipefail

TMP_DIR=$(mktemp -d "/tmp/best_tunnel_{binary}_XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT
cd "$TMP_DIR"

echo "[INFO] Installing {binary} via the verified system package manager..."
if ! command -v {probe_cmd} >/dev/null 2>&1; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {package}
fi
{link_block}
{spec["verify"]}
"""


# Which managed binaries each protocol's units execute, per host. Both sides run the same
# package for every userspace transport here (frp's package installs frps and frpc; each
# host uses the half its role needs). GRE and ESP are kernel features (iproute2) and have
# no managed binary. This table is what lets the deploy path (engine.deploy_tunnel) ensure
# every binary it is about to start has passed the pinned-checksum install above - before
# F3, verify_and_install_binary was called only by tests and a scratch bootstrap script,
# so a production deploy started whatever happened to be on the host, unverified.
PROTOCOL_BINARIES = {
    "GRE": (),
    "ESP": (),
    "backhaul-wss": ("backhaul",),
    "rathole-noise": ("rathole",),
    "chisel-wss": ("chisel",),
    "frp-TLS": ("frp",),
    "wstunnel-v10": ("wstunnel",),
    "xray-reverse": ("xray",),
    "kcptun": ("kcptun",),
    "singbox-vless-reality": ("sing-box",),
    "singbox-ss-2022": ("sing-box",),
    "hysteria2": ("hysteria",),
}


def required_binaries(protocol: str) -> list[str]:
    """Managed binaries a protocol's deployment needs on each host ([] for kernel-only)."""
    return list(PROTOCOL_BINARIES.get(protocol, ()))


def verify_and_install_binary(runner, binary: str, version: str | None = None,
                              arch: str = SUPPORTED_ARCH, dry_run: bool = True) -> tuple[bool, str]:
    """Executes verified binary installation on a remote host (or mock runner)."""
    from mock_ssh import MockSSHClient
    is_mock = isinstance(runner, MockSSHClient)
    if dry_run or is_mock:
        resolved = version or (latest_pinned_version(binary) if binary in OFFICIAL_CHECKSUMS else "apt")
        return True, f"[MOCK] {binary} {resolved} SHA-256 verified and installed successfully."

    # F7 fast path: if every file the pinned release installs is already on the
    # host and hashes to the value the verified install produced, the binary is
    # proven - skip the re-download the full script would otherwise repeat on
    # every deploy. Any doubt (no pin recorded, file missing, hash mismatch,
    # probe error) falls through to the full verified install below.
    try:
        resolved_version, _entry = _resolve_entry(binary, version, arch)
        pins = PINNED_INSTALLED_SHA256.get((binary, resolved_version, arch))
    except ValueError:
        pins = None
    if pins:
        try:
            verified_in_place = True
            for path, want in pins.items():
                _rc, out, _err = runner.run(f"sha256sum {path}", best_effort=True)
                fields = out.split()
                got = fields[0].lower() if fields else ""
                if got != want:
                    verified_in_place = False
                    break
            if verified_in_place:
                return True, (f"[VERIFIED-EXISTING] {binary} {resolved_version} already "
                              f"installed; SHA-256 verified in place, download skipped.")
        except Exception:
            pass

    try:
        script = generate_secure_install_script(binary, version=version, arch=arch)
        _, out, _ = runner.run(script, check=True)
        return True, out
    except Exception as e:
        return False, f"Binary verification or installation failed: {str(e)}"
