#!/usr/bin/env python3
"""L7 probe deployed on the Iran host, shared by the benchmark engine and the failover health checker.

Installed outside /tmp (PROBE_PATH) so it survives benchmark teardown: the health checker must be
able to probe a tunnel long after the benchmark that measured it has cleaned up.
"""

PROBE_PATH = "/usr/local/bin/best_probe.py"
USER_AGENT = "BestTunnelBench/2.0"

# Per-request timeouts inside each probe mode, as they appear in PROBE_SOURCE below.
REQUEST_TIMEOUT_S = {"lat": 3.0, "loss": 1.5, "stability": 2.0}
# Samples per mode, and the sleep between them.
SAMPLE_COUNT = {"lat": 10, "loss": 30}
INTER_SLEEP_S = 0.05

# Stability observation window. Deliberately fixed so `survived` is a property of the tunnel,
# not of how long the rest of the benchmark happened to take.
STABILITY_SAMPLES = 30
STABILITY_INTERVAL = 1.0
STABILITY_WINDOW = STABILITY_SAMPLES * STABILITY_INTERVAL
# Consecutive failed samples that mark a real outage (as opposed to random loss,
# which is already accounted for by the quadratic loss penalty in scoring.py).
OUTAGE_GAP = 3

# Wall-clock budget the orchestrator must give a probe command before its SSH read gives up.
# Paramiko's channel timeout fires when a probe prints nothing for that long, and every mode here
# prints only at the end, so the budget is samples x (request timeout + interval). This is not
# theoretical: the stability window needs ~90s while the SSH default was 30s, so on live hosts the
# sustained-availability step raised TimeoutError and the whole benchmark was recorded as an
# execution error - for every protocol, no matter how healthy the tunnel was.
def cmd_timeout(sub: str, *extra, margin: float = 1.3, floor: float = 20.0) -> float:
    """Seconds to allow for `cmd(sub, ...)`, with margin, never below `floor`."""
    if sub in ("lat", "loss"):
        # F9: a failed plain-HTTP attempt is retried as a TLS handshake at up
        # to half the request timeout, so a sample's worst case is 1.5x.
        worst = SAMPLE_COUNT[sub] * (REQUEST_TIMEOUT_S[sub] * 1.5 + INTER_SLEEP_S)
    elif sub == "stability":
        samples = int(extra[0]) if extra else STABILITY_SAMPLES
        interval = float(extra[1]) if len(extra) > 1 else STABILITY_INTERVAL
        worst = samples * (REQUEST_TIMEOUT_S[sub] * 1.5 + interval)
    elif sub == "ladder":
        # The ladder step carries its own request timeout as its last argument.
        worst = float(extra[-1]) + 5.0 if extra else 25.0
    else:
        worst = floor
    return max(floor, round(worst * margin, 1))

PROBE_SOURCE = r'''
# best-probe v2 (tls-fallback)
import sys, math, time, urllib.request, socket, ssl

USER_AGENT = "BestTunnelBench/2.0"


def _tls_ok(host, port, timeout):
    # F9: the deploy gate learned in F8 that a TLS-first backend (an Xray
    # inbound) drops plain HTTP silently, so a failed HTTP fetch is not
    # proof of a dead tunnel. A completed TLS handshake is: the path
    # carried a real cryptographic negotiation end to end. The SNI is a
    # public name because REALITY-style backends route by it; the
    # certificate is not verified because the probe measures the path,
    # not the identity of what answers.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname="www.google.com") as tls:
                return tls.version() is not None
    except Exception:
        return False


def fetch(host, port, path, timeout):
    url = "http://{}:{}{}".format(host, port, path)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception:
        if _tls_ok(host, port, max(0.5, timeout / 2.0)):
            # Deliberately not the requested body: the ladder compares
            # lengths, so a TLS-answered step still fails its length
            # check (fail-closed) while lat/loss/stability count the
            # sample as what it is - a working path to a TLS service.
            return b"tls-handshake-ok"
        raise


cmd = sys.argv[1]
host = sys.argv[2]
port = int(sys.argv[3])

if cmd == "lat":
    lats = []
    for _ in range(10):
        t0 = time.time()
        try:
            fetch(host, port, "/test_1k", 3)
            lats.append((time.time() - t0) * 1000.0)
        except Exception:
            pass
        time.sleep(0.05)
    if lats:
        avg = sum(lats) / len(lats)
        var = sum((x - avg) ** 2 for x in lats) / len(lats)
        print("AVG:{:.2f} MDEV:{:.2f} OK:{}/10".format(avg, math.sqrt(var), len(lats)))
    else:
        # Never print a number here: the old 999.00 sentinel parsed cleanly and was scored as a
        # measured latency (overhead_ratio 23.66 on the first live xray-reverse run), so it was
        # indistinguishable from a real result. No completed sample is a failed measurement.
        print("AVG:NOSAMPLE MDEV:NOSAMPLE OK:0/10")

elif cmd == "loss":
    total = 30
    ok = 0
    for _ in range(total):
        try:
            fetch(host, port, "/test_1k", 1.5)
            ok += 1
        except Exception:
            pass
        time.sleep(0.05)
    print("LOSS:{:.1f} OK:{}".format(((total - ok) / float(total)) * 100.0, ok))

elif cmd == "ladder":
    path = sys.argv[4]
    exp_len = int(sys.argv[5])
    timeout = int(sys.argv[6])
    t0 = time.time()
    try:
        data = fetch(host, port, path, timeout)
        dt = time.time() - t0
        if len(data) == exp_len:
            print("LADDER_STEP_OK in {:.3f}s".format(dt))
        else:
            print("LADDER_LEN_MISMATCH:{}!={}".format(len(data), exp_len))
    except Exception as e:
        print("LADDER_ERR:{} in {:.3f}s".format(str(e)[:50], time.time() - t0))

elif cmd == "stability":
    total = int(sys.argv[4])
    interval = float(sys.argv[5])
    gap = int(sys.argv[6])
    flags = []
    for _ in range(total):
        ok = False
        try:
            fetch(host, port, "/test_1k", 2)
            ok = True
        except Exception:
            pass
        flags.append(ok)
        time.sleep(interval)
    # Serviceable duration: window ends at the first run of `gap` consecutive failures.
    survived = total * interval
    for i in range(0, len(flags) - gap + 1):
        if not any(flags[i:i + gap]):
            survived = i * interval
            break
    print("STAB_OK:{} STAB_TOTAL:{} STAB_SURVIVED:{:.1f}".format(
        sum(1 for f in flags if f), len(flags), survived))

else:
    print("UNKNOWN_CMD:" + cmd)
    sys.exit(2)
'''.strip()


def install_script(path: str = PROBE_PATH) -> str:
    """Shell command that (re)installs the probe with executable permissions."""
    return f"cat > {path} <<'BEST_PROBE_EOF'\n{PROBE_SOURCE}\nBEST_PROBE_EOF\nchmod 755 {path}"


PROBE_VERSION_MARKER = "best-probe v2 (tls-fallback)"


def ensure_probe(runner, path: str = PROBE_PATH) -> bool:
    """Installs the probe when absent OR stale, so health checks are self-sufficient.

    Presence alone used to be enough, which would have pinned every host to the
    pre-F9 HTTP-only probe forever: the version marker is what lets an installed
    probe be recognised as outdated and replaced. Returns False when the probe
    could not be made available, letting callers fail safe (report an outage)
    instead of misreading an empty probe result as a healthy tunnel.
    """
    _, out, _ = runner.run(
        f"grep -q '{PROBE_VERSION_MARKER}' {path} 2>/dev/null && echo BEST_PROBE_CURRENT",
        best_effort=True)
    if "BEST_PROBE_CURRENT" in out:
        return True
    rc, _, _ = runner.run(install_script(path), best_effort=True)
    return rc == 0


def cmd(sub: str, host: str, port: int, *extra) -> str:
    """Builds a probe invocation. Only literal, caller-validated arguments are interpolated."""
    parts = ["python3", PROBE_PATH, sub, str(host), str(int(port))]
    parts.extend(str(a) for a in extra)
    return " ".join(parts)


def stability_cmd(host: str, port: int) -> str:
    return cmd("stability", host, port, STABILITY_SAMPLES, STABILITY_INTERVAL, OUTAGE_GAP)
