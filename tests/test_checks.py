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

    def test_fail(self, mock_dns_failure):
        from infra_check.checks.dns import check_dns

        result = check_dns("nope.invalid")
        assert result.status is Status.FAIL
        assert "resolution failed" in result.detail


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


class TestCertificate:
    def test_pass_90_days(self, mock_tls_ok):
        from infra_check.checks.tls import check_certificate

        result = check_certificate("example.com", 443, Thresholds())
        assert result.status is Status.PASS
        assert result.data["days_left"] in (89, 90)  # sub-day truncation
        assert result.data["issuer"] == "Fake CA Inc"

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


class TestHttp:
    @pytest.fixture
    def mock_http_200(self, monkeypatch):
        class FakeResponse:
            status_code = 200
            reason_phrase = "OK"
            url = "https://example.com/"
            history = []

        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            def get(self, url):
                return FakeResponse()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        monkeypatch.setattr("infra_check.checks.http.httpx.Client", FakeClient)

    @pytest.fixture
    def mock_http_500(self, monkeypatch):
        class FakeResponse:
            status_code = 500
            reason_phrase = "Internal Server Error"
            url = "https://example.com/"
            history = []

        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            def get(self, url):
                return FakeResponse()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        monkeypatch.setattr("infra_check.checks.http.httpx.Client", FakeClient)

    def test_http_200_pass(self, mock_http_200):
        from infra_check.checks.http import check_http

        results = {r.name: r for r in check_http("example.com", 443, Thresholds())}
        assert results["http"].status is Status.PASS
        assert results["latency"].status is Status.PASS
        assert "redirect" not in results  # https target: no redirect check

    def test_http_500_fail(self, mock_http_500):
        from infra_check.checks.http import check_http

        results = {r.name: r for r in check_http("example.com", 443, Thresholds())}
        assert results["http"].status is Status.FAIL
