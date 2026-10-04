"""Check-module tests: every network layer mocked."""

from __future__ import annotations

import pytest

from infra_check.engine import Status, Thresholds


class TestDns:
    def test_pass(self, mock_dns):
        from infra_check.checks.dns import check_dns

        result = check_dns("example.com")
        assert result.status is Status.PASS
        assert result.data["ipv4"] == ["93.184.216.34"]
        assert len(result.data["ipv6"]) == 1
        assert result.data["dns_ms"] >= 0

    def test_fail(self, mock_dns_failure):
        from infra_check.checks.dns import check_dns

        result = check_dns("example.com")
        assert result.status is Status.FAIL
        assert "resolution failed" in result.detail

    def test_timeout_is_bounded(self, mock_dns_timeout):
        from infra_check.checks.dns import check_dns

        t = Thresholds.merge(Thresholds(), timeout=0.2)
        result = check_dns("example.com", t)
        assert result.status is Status.FAIL
        assert "timed out" in result.detail


class TestTcp:
    def test_pass(self, mock_tcp_ok):
        from infra_check.checks.tcp import check_tcp

        result = check_tcp("example.com", 443, Thresholds())
        assert result.status is Status.PASS
        assert "connected" in result.detail
        assert result.data["connect_ms"] >= 0

    def test_fail(self, mock_tcp_fail):
        from infra_check.checks.tcp import check_tcp

        result = check_tcp("example.com", 443, Thresholds())
        assert result.status is Status.FAIL
        assert "connect failed" in result.detail


class TestTls:
    def test_pass(self, mock_tls_ok):
        from infra_check.checks.tls import check_tls

        result = check_tls("example.com", 443, Thresholds())
        assert result.status is Status.PASS
        assert result.data["protocol"] == "TLSv1.3"
        assert result.data["cipher"] == "TLS_AES_256_GCM_SHA384"

    def test_fail(self, mock_tls_fail):
        from infra_check.checks.tls import check_tls

        result = check_tls("expired.example", 443, Thresholds())
        assert result.status is Status.FAIL
        assert "handshake failed" in result.detail

    def test_no_verify_tls_passes_self_signed(self, monkeypatch):
        """With verification off, an untrusted handshake must not fail the tls check."""
        from infra_check.checks import tls as tls_module
        from infra_check.checks.tls import check_tls

        def _handshake(target, port, thresholds):
            assert thresholds.verify_tls is False, "context must be built with verification off"
            return tls_module.TlsInfo(
                protocol="TLSv1.3",
                cipher="TLS_AES_256_GCM_SHA384",
                not_before=None,
                not_after=None,
                subject_cn=None,
                issuer_org=None,
                sans=[],
            )

        monkeypatch.setattr(tls_module, "_handshake", _handshake)
        t = Thresholds.merge(Thresholds(), verify_tls=False)
        result = check_tls("self-signed.local", 8443, t)
        assert result.status is Status.PASS


class TestCertificate:
    def test_pass_90_days(self, mock_tls_ok):
        from infra_check.checks.tls import check_certificate

        result = check_certificate("example.com", 443, Thresholds())
        assert result.status is Status.PASS
        assert result.data["days_left"] in (89, 90)  # sub-day truncation
        assert result.data["issuer"] == "Fake CA Inc"
        assert result.data["subject"] == "example.com"
        assert result.data["sans"] == ["example.com", "www.example.com"]
        assert result.data["valid_from"] is not None

    def test_warn_15_days(self, mock_tls_warn):
        from infra_check.checks.tls import check_certificate

        result = check_certificate("example.com", 443, Thresholds())
        assert result.status is Status.WARN
        assert result.data["days_left"] in (14, 15)

    def test_fail_on_ssl_error(self, mock_tls_fail):
        from infra_check.checks.tls import check_certificate

        result = check_certificate("example.com", 443, Thresholds())
        assert result.status is Status.FAIL

    def test_custom_warn_threshold(self, mock_tls_warn):
        from infra_check.checks.tls import check_certificate

        t = Thresholds.merge(Thresholds(), cert_warn_days=10)
        result = check_certificate("example.com", 443, t)
        assert result.status is Status.PASS

    def test_no_verify_tls_reports_skip(self, monkeypatch):
        """Cert fields are unparseable without verification — must SKIP, not guess."""
        from infra_check.checks import tls as tls_module
        from infra_check.checks.tls import check_certificate

        def _handshake(target, port, thresholds):
            return tls_module.TlsInfo(
                protocol="TLSv1.3",
                cipher="x",
                not_before=None,
                not_after=None,
                subject_cn=None,
                issuer_org=None,
                sans=[],
            )

        monkeypatch.setattr(tls_module, "_handshake", _handshake)
        t = Thresholds.merge(Thresholds(), verify_tls=False)
        result = check_certificate("example.com", 443, t)
        assert result.status is Status.SKIP
        assert "no-verify-tls" in result.detail

    def test_date_parsing_is_locale_safe(self):
        """getpeercert dates are English regardless of host locale."""
        from infra_check.checks.tls import TlsInfo

        info = TlsInfo(
            protocol="TLSv1.3",
            cipher="x",
            not_before="May  1 12:00:00 2026 GMT",
            not_after="May  9 12:00:00 2027 GMT",
            subject_cn=None,
            issuer_org=None,
            sans=[],
        )
        assert info.expires_utc is not None and info.expires_utc.year == 2027
        assert info.valid_from_utc is not None and info.valid_from_utc.month == 5


class TestTlsSharedHandshake:
    def test_run_tls_checks_single_handshake(self, mock_tls_ok):
        """tls + certificate must share ONE handshake (registry calls run_tls_checks)."""
        from infra_check.engine import Thresholds as T
        from infra_check.registry import run_checks

        calls = mock_tls_ok
        t = T()
        report = run_checks("example.com", 443, t, ("tls", "certificate"))
        by_name = {c.name: c for c in report.checks}
        assert by_name["tls"].status is Status.PASS
        assert by_name["certificate"].status is Status.PASS
        assert calls["n"] == 1, "both checks must derive from a single handshake"


class TestHttp:
    @pytest.fixture
    def mock_http_200(self, monkeypatch):
        from tests.conftest import make_http_client

        monkeypatch.setattr(
            "infra_check.checks.http.httpx.Client",
            make_http_client(status_code=200, reason="OK", final_url="https://example.com/"),
        )

    @pytest.fixture
    def mock_http_500(self, monkeypatch):
        from tests.conftest import make_http_client

        monkeypatch.setattr(
            "infra_check.checks.http.httpx.Client",
            make_http_client(
                status_code=500, reason="Internal Server Error", final_url="https://example.com/"
            ),
        )

    def test_http_200_pass(self, mock_http_200):
        from infra_check.checks.http import check_http

        results = {r.name: r for r in check_http("example.com", 443, Thresholds())}
        assert results["http"].status is Status.PASS
        assert results["latency"].status is Status.PASS
        assert results["latency"].data["latency_ms"] >= 0
        # https target: redirect check present and SKIP, never absent (stable schema).
        assert results["redirect"].status is Status.SKIP

    def test_http_500_fail(self, mock_http_500):
        from infra_check.checks.http import check_http

        results = {r.name: r for r in check_http("example.com", 443, Thresholds())}
        assert results["http"].status is Status.FAIL

    def test_returns_exactly_three_results(self, mock_http_200):
        from infra_check.checks.http import check_http

        results = check_http("example.com", 443, Thresholds())
        assert [r.name for r in results] == ["http", "latency", "redirect"]

    def test_scheme_8443_is_https(self, mock_http_200, monkeypatch):
        """Port 8443 must use https, not http (the old scheme-inference bug)."""
        from tests.conftest import make_http_client

        monkeypatch.setattr(
            "infra_check.checks.http.httpx.Client",
            make_http_client(
            status_code=200, reason="OK", final_url="https://example.com:8443/"
        ),
        )
        from infra_check.checks.http import _url

        assert _url("example.com", 8443) == "https://example.com:8443"
        assert _url("example.com", 443) == "https://example.com"
        assert _url("example.com", 80) == "http://example.com"
        assert _url("example.com", 8080) == "http://example.com:8080"

    def test_http_redirect_to_https(self, monkeypatch):
        from tests.conftest import make_http_client

        monkeypatch.setattr(
            "infra_check.checks.http.httpx.Client",
            make_http_client(
                status_code=200,
                reason="OK",
                final_url="https://example.com/",
                history=["hop"],
            ),
        )
        from infra_check.checks.http import check_http

        results = {r.name: r for r in check_http("example.com", 80, Thresholds())}
        assert results["redirect"].status is Status.PASS
        assert results["redirect"].data["hops"] == 1

    def test_http_stays_on_http_warns(self, monkeypatch):
        from tests.conftest import make_http_client

        monkeypatch.setattr(
            "infra_check.checks.http.httpx.Client",
            make_http_client(
                status_code=200,
                reason="OK",
                final_url="http://example.com/stay",
                history=[],
            ),
        )
        from infra_check.checks.http import check_http

        results = {r.name: r for r in check_http("example.com", 80, Thresholds())}
        assert results["redirect"].status is Status.WARN

    def test_transport_failure_skips_latencies(self, monkeypatch):
        import httpx as _httpx

        class ExplodingClient:
            def __init__(self, *a, **kw):
                pass

            def stream(self, method, url):
                raise _httpx.ConnectError("refused")

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        monkeypatch.setattr("infra_check.checks.http.httpx.Client", ExplodingClient)
        from infra_check.checks.http import check_http

        results = {r.name: r for r in check_http("example.com", 443, Thresholds())}
        assert results["http"].status is Status.FAIL
        assert results["latency"].status is Status.SKIP
        assert results["redirect"].status is Status.SKIP

    def test_slow_response_warns_latency(self, monkeypatch):
        from tests.conftest import make_http_client

        monkeypatch.setattr(
            "infra_check.checks.http.httpx.Client",
            make_http_client(
                status_code=200, reason="OK", final_url="https://example.com/", delay=0.4
            ),
        )
        from infra_check.checks.http import check_http

        results = {r.name: r for r in check_http("example.com", 443, Thresholds())}
        assert results["latency"].status is Status.WARN
        assert results["latency"].data["latency_ms"] >= 300
