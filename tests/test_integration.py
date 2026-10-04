"""Integration tests against real local servers — offline, deterministic.

These exercise the REAL networking stack: actual sockets, real TLS
handshakes against trustme-generated certificates (valid, expiring,
expired), real HTTP responses, redirect chains and a redirect loop.
``SSL_CERT_FILE`` points at the local CA so verification is genuine.
"""

from __future__ import annotations

import pytest

from infra_check.engine import Status, Thresholds
from infra_check.registry import run_checks

from .local_servers import RefusedPort, cluster

MIN_TIMEOUT = Thresholds.merge(Thresholds(), timeout=5.0)


def ca_path() -> str:
    from .local_servers import certs

    return certs().ca_path


@pytest.fixture(autouse=True)
def trust_local_ca(monkeypatch):
    """Point the system SSL trust at the test CA — verification stays ON."""
    monkeypatch.setenv("SSL_CERT_FILE", ca_path())


class TestTcpIntegration:
    def test_connect_to_real_listener(self):
        from infra_check.checks.tcp import check_tcp

        c = cluster()
        port = c.tcp.server_address[1]
        result = check_tcp("127.0.0.1", port, MIN_TIMEOUT)
        assert result.status is Status.PASS
        assert result.data["connect_ms"] >= 0

    def test_connection_refused(self):
        from infra_check.checks.tcp import check_tcp

        with RefusedPort() as rp:
            result = check_tcp("127.0.0.1", rp.port, MIN_TIMEOUT)
        assert result.status is Status.FAIL
        assert "connect failed" in result.detail

    def test_timeout_on_silent_host(self):
        """A non-routable address must hit the timeout, not hang."""
        from infra_check.checks.tcp import check_tcp

        t = Thresholds.merge(Thresholds(), timeout=0.5)
        # 10.255.255.1: reserved, typically unroutable — connect times out.
        result = check_tcp("10.255.255.1", 81, t)
        assert result.status is Status.FAIL


class TestTlsIntegration:
    def test_valid_cert_handshake(self):
        from infra_check.checks.tls import run_tls_checks

        c = cluster()
        port = c.https.server_address[1]
        results = {r.name: r for r in run_tls_checks("127.0.0.1", port, MIN_TIMEOUT)}
        assert results["tls"].status is Status.PASS
        assert results["certificate"].status is Status.PASS
        assert results["certificate"].data["days_left"] in (89, 90)

    def test_single_handshake_for_both_checks(self):
        """Integration-level guard: tls+certificate share one connection."""
        from infra_check.checks import tls as tls_module

        c = cluster()
        port = c.https.server_address[1]
        original = tls_module._handshake
        calls = {"n": 0}

        def counting(target, prt, thresholds):
            calls["n"] += 1
            return original(target, prt, thresholds)

        tls_module._handshake = counting
        try:
            results = run_tls_results(port)
        finally:
            tls_module._handshake = original
        assert calls["n"] == 1
        assert len(results) == 2

    def test_expired_cert_fails_verification(self):
        from infra_check.checks.tls import run_tls_checks

        c = cluster()
        port = c.https_expired.server_address[1]
        results = {r.name: r for r in run_tls_checks("127.0.0.1", port, MIN_TIMEOUT)}
        assert results["tls"].status is Status.FAIL
        assert "CERTIFICATE_VERIFY_FAILED" in results["tls"].detail

    def test_expiring_cert_warns(self):
        from infra_check.checks.tls import run_tls_checks

        c = cluster()
        port = c.https_soon.server_address[1]
        results = {r.name: r for r in run_tls_checks("127.0.0.1", port, MIN_TIMEOUT)}
        assert results["certificate"].status is Status.WARN
        assert results["certificate"].data["days_left"] in (11, 12)

    def test_no_verify_tls_accepts_expired_cert(self):
        """Diagnostic mode: expired cert must not fail the tls check."""
        from infra_check.checks.tls import run_tls_checks

        c = cluster()
        port = c.https_expired.server_address[1]
        t = Thresholds.merge(MIN_TIMEOUT, verify_tls=False)
        results = {r.name: r for r in run_tls_checks("127.0.0.1", port, t)}
        assert results["tls"].status is Status.PASS
        assert results["certificate"].status is Status.SKIP


def run_tls_results(port):
    from infra_check.checks.tls import run_tls_checks

    return run_tls_checks("127.0.0.1", port, MIN_TIMEOUT)


class TestHttpIntegration:
    def test_https_200(self):
        from infra_check.checks.http import check_http

        c = cluster()
        port = c.https.server_address[1]
        results = {r.name: r for r in check_http("127.0.0.1", port, MIN_TIMEOUT, scheme="https")}
        assert results["http"].status is Status.PASS
        assert results["http"].data["status_code"] == 200
        assert results["latency"].status is Status.PASS
        assert results["redirect"].status is Status.SKIP

    def test_https_500_fails(self):
        from infra_check.checks.http import check_http

        c = cluster()
        port = c.https_500.server_address[1]
        results = {r.name: r for r in check_http("127.0.0.1", port, MIN_TIMEOUT, scheme="https")}
        assert results["http"].status is Status.FAIL
        assert results["http"].data["status_code"] == 500

    def test_http_404_fails(self):
        from infra_check.checks.http import check_http

        c = cluster()
        port = c.http_404.server_address[1]
        results = {r.name: r for r in check_http("127.0.0.1", port, MIN_TIMEOUT)}
        assert results["http"].status is Status.FAIL

    def test_http_500_fails(self):
        from infra_check.checks.http import check_http

        c = cluster()
        port = c.http_500.server_address[1]
        results = {r.name: r for r in check_http("127.0.0.1", port, MIN_TIMEOUT)}
        assert results["http"].status is Status.FAIL

    def test_redirect_to_https_passes(self):
        from infra_check.checks.http import check_http

        c = cluster()
        c.http_to_https.script[0] = c.https.url + "/"
        port = c.http_to_https.server_address[1]
        results = {r.name: r for r in check_http("127.0.0.1", port, MIN_TIMEOUT)}
        assert results["http"].status is Status.PASS
        assert results["redirect"].status is Status.PASS
        assert results["redirect"].data["hops"] == 1

    def test_redirect_staying_http_fails(self):
        """http -> http redirect chain: documented FAIL (stays on http)."""
        from infra_check.checks.http import check_http

        c = cluster()
        c.http_to_http.script = [f"http://127.0.0.1:{c.http_to_http.server_address[1]}/stay", 200]
        port = c.http_to_http.server_address[1]
        results = {r.name: r for r in check_http("127.0.0.1", port, MIN_TIMEOUT)}
        assert results["redirect"].status is Status.FAIL
        assert results["redirect"].data["hops"] == 1

    def test_no_redirect_on_http_warns(self):
        from infra_check.checks.http import check_http

        c = cluster()
        port = c.http.server_address[1]
        results = {r.name: r for r in check_http("127.0.0.1", port, MIN_TIMEOUT)}
        assert results["redirect"].status is Status.WARN

    def test_redirect_loop_fails_cleanly(self):
        from infra_check.checks.http import check_http

        c = cluster()
        port = c.loop.server_address[1]
        results = {r.name: r for r in check_http("127.0.0.1", port, MIN_TIMEOUT)}
        assert results["http"].status is Status.FAIL
        assert results["latency"].status is Status.SKIP
        assert results["redirect"].status is Status.SKIP


class TestFullPipelineIntegration:
    """End-to-end: registry orchestration over real local servers."""

    def test_healthy_target(self):
        c = cluster()
        port = c.https.server_address[1]
        report = run_checks(
            "127.0.0.1",
            port,
            MIN_TIMEOUT,
            ("dns", "tcp", "tls", "certificate", "http", "latency"),
            scheme="https",
        )
        by = {r.name: r for r in report.checks}
        assert by["tcp"].status is Status.PASS
        assert by["tls"].status is Status.PASS
        assert by["certificate"].status is Status.PASS
        assert by["http"].status is Status.PASS
        assert report.verdict.value == "HEALTHY"

    def test_expired_cert_target_unhealthy(self):
        c = cluster()
        port = c.https_expired.server_address[1]
        report = run_checks(
            "127.0.0.1", port, MIN_TIMEOUT, ("tcp", "tls", "certificate", "http"),
            scheme="https",
        )
        by = {r.name: r for r in report.checks}
        assert by["tls"].status is Status.FAIL
        assert by["certificate"].status is Status.FAIL
        assert report.verdict.value == "UNHEALTHY"

    def test_refused_target_short_circuits(self):
        with RefusedPort() as rp:
            report = run_checks("127.0.0.1", rp.port, MIN_TIMEOUT, ("tcp", "tls", "http"))
        by = {r.name: r for r in report.checks}
        assert by["tcp"].status is Status.FAIL
        assert by["tls"].status is Status.SKIP
        assert by["http"].status is Status.SKIP


class TestDnsTimeoutGuard:
    def test_pool_timeout_is_bounded(self):
        """DNS against a black hole must return within ~timeout seconds."""
        import time

        from infra_check.checks.dns import check_dns

        t = Thresholds.merge(Thresholds(), timeout=0.5)
        start = time.perf_counter()
        # ".invalid" is RFC-reserved: resolution fails fast, but through the pool.
        result = check_dns("blackhole.invalid", t)
        elapsed = time.perf_counter() - start
        assert result.status is Status.FAIL
        assert elapsed < 5.0  # pool path exercised, no hang
