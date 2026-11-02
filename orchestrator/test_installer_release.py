"""Verified-release installer support (C-Tunnel-style SHA256SUMS checks).

The installer downloads only itself, so the verification function lives
inside install.sh. These tests extract that exact function (between its
markers) and run it, plus drive scripts/build-release.sh end to end:
a tampered tarball, a missing entry or a malformed hash must all
refuse, and nothing may be installed on failure.
"""

import hashlib
import os
import re
import subprocess
import sys
import tarfile

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _verify_fn_source():
    text = open(os.path.join(REPO, "install.sh")).read()
    m = re.search(r"# -- verify-sha256 begin --\n(.*?\n)# -- verify-sha256 end --",
                  text, re.S)
    assert m, "verify markers moved in install.sh"
    return m.group(1)


def _run_verify(tmp_path, content, sums_text):
    f = tmp_path / "rahyaab-v9.9.9.tar.gz"
    f.write_bytes(content)
    sums = tmp_path / "SHA256SUMS"
    sums.write_text(sums_text)
    harness = tmp_path / "harness.sh"
    harness.write_text(
        "die() { echo \"DIE: $*\" >&2; exit 1; }\n"
        "ok() { :; }\n"
        + _verify_fn_source()
        + "verify_sha256_file \"%s\" \"%s\"\n" % (f, sums))
    return subprocess.run(["bash", str(harness)], capture_output=True, text=True)


def test_verify_accepts_matching_hash(tmp_path):
    content = b"rahyaab release bytes"
    digest = hashlib.sha256(content).hexdigest()
    r = _run_verify(tmp_path, content, "%s  rahyaab-v9.9.9.tar.gz\n" % digest)
    assert r.returncode == 0, r.stderr


def test_verify_refuses_tampered_content(tmp_path):
    content = b"rahyaab release bytes"
    digest = hashlib.sha256(b"something else").hexdigest()
    r = _run_verify(tmp_path, content, "%s  rahyaab-v9.9.9.tar.gz\n" % digest)
    assert r.returncode != 0
    assert "Nothing was changed" in r.stderr


def test_verify_refuses_missing_entry(tmp_path):
    content = b"rahyaab release bytes"
    digest = hashlib.sha256(content).hexdigest()
    r = _run_verify(tmp_path, content, "%s  other-file.tar.gz\n" % digest)
    assert r.returncode != 0


def test_verify_refuses_malformed_hash(tmp_path):
    content = b"rahyaab release bytes"
    for bad in ("xyz  rahyaab-v9.9.9.tar.gz\n",
                "abc123  rahyaab-v9.9.9.tar.gz\n"):
        r = _run_verify(tmp_path, content, bad)
        assert r.returncode != 0, bad


def test_build_release_produces_verifiable_tarball(tmp_path):
    src = tmp_path / "src"
    (src / "hub").mkdir(parents=True)
    (src / "hub" / "main.py").write_text("# hub\n")
    (src / "install.sh").write_text("#!/usr/bin/env bash\nVERSION=\"9.9.9\"\n")
    cache = src / "__pycache__"
    cache.mkdir()
    (cache / "junk.pyc").write_bytes(b"\x00")
    (src / "stale.bak-20260101").write_text("stale")
    out = tmp_path / "dist"
    r = subprocess.run(["bash", os.path.join(REPO, "scripts", "build-release.sh"),
                        "v9.9.9", str(src), str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    tarball = out / "rahyaab-v9.9.9.tar.gz"
    assert tarball.exists() and (out / "SHA256SUMS").exists()
    check = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=str(out),
                           capture_output=True, text=True)
    assert check.returncode == 0, check.stdout + check.stderr
    with tarfile.open(tarball) as tf:
        names = tf.getnames()
    assert "./hub/main.py" in names
    assert not any("__pycache__" in n or n.endswith(".bak-20260101") for n in names)
