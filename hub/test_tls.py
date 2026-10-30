"""Offline tests for public HTTPS mode: TLS serving, Secure cookies,
HSTS. The certificate is generated on the fly with openssl; the test
is skipped where openssl is unavailable.
"""

import http.client
import json
import shutil
import ssl
import subprocess
import threading

import pytest

from hub.server import serve
from hub.store import Store


@pytest.fixture()
def tls_server(tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", str(key), "-out", str(cert), "-days", "1",
                    "-nodes", "-subj", "/CN=127.0.0.1",
                    "-addext", "subjectAltName=IP:127.0.0.1"],
                   check=True, capture_output=True)
    store = Store(tmp_path / "hub.db")
    server = serve(store, host="127.0.0.1", port=0,
                   tls_cert=str(cert), tls_key=str(key))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.hub.worker.stop()


def https(port, method, path, body=None, cookie=None):
    ctx = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=ctx)
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    conn.request(method, path, body=json.dumps(body) if body is not None else None,
                 headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    headers_out = dict(resp.getheaders())
    conn.close()
    return resp.status, headers_out, json.loads(raw or b"{}")


def test_stalled_tls_handshake_does_not_wedge_server(tls_server):
    """A client that opens TCP without completing TLS must not wedge the hub.

    Regression test for the accept-thread wedge: with the listening socket
    wrapped in TLS, one stalled handshake blocked the accept thread forever
    (a blocking socket has no timeout) and the hub answered nothing
    afterwards. The fix wraps each accepted socket with a 5s handshake
    timeout, so the stalled connection fails alone and a normal HTTPS
    request still succeeds (after at most the 5s handshake timeout).
    """
    import socket
    port = tls_server
    stalled = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        status, _, body = https(port, "GET", "/api/health")
        assert status == 200 and body["ok"] is True
    finally:
        stalled.close()


def test_https_health_hsts_and_secure_cookie(tls_server):
    port = tls_server
    status, headers, body = https(port, "GET", "/api/health")
    assert status == 200 and body["ok"] is True
    assert "max-age=31536000" in headers.get("Strict-Transport-Security", "")
    status, _, _ = https(port, "POST", "/api/setup",
                         {"username": "admin", "password": "change-me-123"})
    assert status == 201
    status, headers, _ = https(port, "POST", "/api/login",
                               {"username": "admin", "password": "change-me-123"})
    assert status == 200
    assert "Secure" in headers.get("Set-Cookie", "")
