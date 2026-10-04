"""Deterministic local test infrastructure — no internet required.

Provides real in-process servers on 127.0.0.1:

* ``TlsServer``       — real TLS with a trustme-generated CA (valid / expired / self-signed)
* ``HttpServer``      — plain HTTP with scripted status codes
* ``HttpsServer``     — HTTP over the TLS server
* redirect chains     — http → https, http → http, and redirect loops

Tests point ``SSL_CERT_FILE`` at the generated CA so verification is real.
"""

from __future__ import annotations

import contextlib
import http.server
import os
import socket
import socketserver
import ssl
import tempfile
import threading
from datetime import datetime, timedelta, timezone

import trustme


class _CertFactory:
    """Lazily-generated CA and leaf certs; PEMs written to a temp dir."""

    def __init__(self):
        self._tmp = tempfile.mkdtemp(prefix="infra-check-test-")
        self.ca = trustme.CA()
        self.paths = {
            "ca": os.path.join(self._tmp, "ca.pem"),
        }
        with open(self.paths["ca"], "wb") as f:
            f.write(self.ca.cert_pem.bytes())

    def leaf(self, name, not_before=None, not_after=None):
        """Write a leaf cert + key; returns (cert_path, key_path)."""
        now = datetime.now(timezone.utc)
        cert = self.ca.issue_cert(
            "localhost",
            "127.0.0.1",
            common_name="localhost",
            not_before=not_before or (now - timedelta(days=1)),
            not_after=not_after or (now + timedelta(days=90)),
        )
        cert_path = os.path.join(self._tmp, f"{name}-cert.pem")
        key_path = os.path.join(self._tmp, f"{name}-key.pem")
        with open(cert_path, "wb") as f:
            f.write(cert.cert_chain_pems[0].bytes())
        with open(key_path, "wb") as f:
            f.write(cert.private_key_pem.bytes())
        return cert_path, key_path

    @property
    def ca_path(self) -> str:
        return self.paths["ca"]


_CERTS: _CertFactory | None = None
_CERTS_LOCK = threading.Lock()


def certs() -> _CertFactory:
    global _CERTS
    with _CERTS_LOCK:
        if _CERTS is None:
            _CERTS = _CertFactory()
        return _CERTS


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TcpServer(socketserver.ThreadingTCPServer):
    """Raw TCP server that accepts connections (for the TCP check)."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", _free_port()), _SilentHandler)


class _SilentHandler(socketserver.BaseRequestHandler):
    def handle(self):
        pass  # accept and hold open; nothing to say


class RefusedPort:
    """Context: a bound-then-closed port — connections are refused."""

    def __enter__(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(1)
        self.port = self._srv.getsockname()[1]
        self._srv.close()
        return self

    def __exit__(self, *exc):
        return False


class _ScriptedHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Serves scripted status codes/redirects per server instance config."""

    protocol_version = "HTTP/1.1"
    script: list = []  # populated per-server (status:int | location:str)

    def setup(self):
        super().setup()
        # httpx/httpcore close sockets without a TLS close_notify; the
        # resulting ConnectionResetError would spam test output on Windows.
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def handle(self):
        # httpx closes sockets without a TLS close_notify; the resulting
        # ConnectionResetError would spam test output on Windows.
        with contextlib.suppress(ConnectionError, ssl.SSLError, OSError):
            super().handle()

    def do_GET(self):
        if not self.server.script:  # type: ignore[attr-defined]
            self.send_error(500)
            return
        action = self.server.script.pop(0)  # type: ignore[attr-defined]
        if isinstance(action, int):
            body = b"ok"
            self.send_response(action)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(302)
            self.send_header("Location", action)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *args):
        pass  # keep test output clean


class _BaseHttpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class PlainHttpServer(_BaseHttpServer):
    """HTTP server with a scripted list of responses (status ints or location strs)."""

    def __init__(self, script):
        self.script = list(script)
        super().__init__(("127.0.0.1", _free_port()), _ScriptedHTTPHandler)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class TlsServer(_BaseHttpServer):
    """HTTPS server with a real trustme CA certificate."""

    def __init__(self, cert_path, key_path, script=(200,)):
        self.script = list(script)
        super().__init__(("127.0.0.1", _free_port()), _ScriptedHTTPHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        self.socket = ctx.wrap_socket(self.socket, server_side=True)

    @property
    def url(self):
        return f"https://127.0.0.1:{self.server_address[1]}"


class RedirectLoopServer(_BaseHttpServer):
    """Each response redirects to /next-N — infinite loop for the client."""

    def __init__(self):
        self.counter = 0
        handler = type("LoopHandler", (_LoopHandler,), {})
        super().__init__(("127.0.0.1", _free_port()), handler)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class _LoopHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self):
        with contextlib.suppress(ConnectionError, OSError):
            super().handle()

    def do_GET(self):
        self.server.counter += 1  # type: ignore[attr-defined]
        self.send_response(302)
        self.send_header("Location", f"/next-{self.server.counter}")  # type: ignore[attr-defined]
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class ServerCluster:
    """One-spin-up bundle of all local servers a test session needs."""

    def __init__(self):
        cf = certs()
        # Valid leaf (expires ~90 days), expired leaf, expiring-soon leaf (12 days).
        now = datetime.now(timezone.utc)
        self.valid_cert, self.valid_key = cf.leaf("valid")
        self.expired_cert, self.expired_key = cf.leaf(
            "expired",
            not_before=now - timedelta(days=30),
            not_after=now - timedelta(days=1),
        )
        self.soon_cert, self.soon_key = cf.leaf(
            "soon",
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=12),
        )

        self.tcp = TcpServer()
        self.https = TlsServer(self.valid_cert, self.valid_key, script=[200] * 32)
        self.https_500 = TlsServer(self.valid_cert, self.valid_key, script=[500] * 8)
        self.https_expired = TlsServer(self.expired_cert, self.expired_key, script=[200] * 8)
        self.https_soon = TlsServer(self.soon_cert, self.soon_key, script=[200] * 8)
        self.http = PlainHttpServer([200] * 32)
        self.http_404 = PlainHttpServer([404] * 8)
        self.http_500 = PlainHttpServer([500] * 8)
        self.http_to_https = PlainHttpServer(
            ["{HTTPS_URL}/"] + [200] * 32  # replaced at start()
        )
        self.http_to_http = PlainHttpServer(["/stay"] + [200] * 32)
        self.loop = RedirectLoopServer()

        for srv in self._all():
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    def _all(self):
        return [
            self.tcp,
            self.https,
            self.https_500,
            self.https_expired,
            self.https_soon,
            self.http,
            self.http_404,
            self.http_500,
            self.http_to_https,
            self.http_to_http,
            self.loop,
        ]

    def start(self):
        # Resolve the http->https redirect target now that https URL is known.
        self.http_to_https.script[0] = self.https.url + "/"
        return self

    def shutdown_all(self):
        for srv in self._all():
            srv.shutdown()
            srv.server_close()


_CLUSTER: ServerCluster | None = None
_CLUSTER_LOCK = threading.Lock()


def cluster() -> ServerCluster:
    """Session-wide lazily-started bundle of local servers."""
    global _CLUSTER
    with _CLUSTER_LOCK:
        if _CLUSTER is None:
            _CLUSTER = ServerCluster().start()
        return _CLUSTER
