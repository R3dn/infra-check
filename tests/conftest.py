"""Shared fixtures: all network layers are mocked — tests never hit live endpoints."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture
def mock_dns(monkeypatch):
    """Successful DNS resolution returning one IPv4 and one IPv6 address."""

    def _fake_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)


@pytest.fixture
def mock_dns_failure(monkeypatch):
    def _fail(host, port, *args, **kwargs):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _fail)


def _make_tls_handshake(days_left=90):
    from infra_check.checks.tls import TlsInfo

    def _handshake(target, port, thresholds):
        expires = datetime.now(timezone.utc) + timedelta(days=days_left)
        return TlsInfo(
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            not_after=expires.strftime("%b %d %H:%M:%S %Y GMT"),
            issuer_org="Fake CA Inc",
        )

    return _handshake


@pytest.fixture
def mock_tls_ok(monkeypatch):
    monkeypatch.setattr(
        "infra_check.checks.tls._handshake", _make_tls_handshake(days_left=90)
    )


@pytest.fixture
def mock_tls_warn(monkeypatch):
    monkeypatch.setattr(
        "infra_check.checks.tls._handshake", _make_tls_handshake(days_left=15)
    )


@pytest.fixture
def mock_tls_fail(monkeypatch):
    def _handshake(target, port, thresholds):
        raise ssl.SSLError("CERTIFICATE_VERIFY_FAILED")

    monkeypatch.setattr("infra_check.checks.tls._handshake", _handshake)


class FakeConn:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def mock_tcp_ok(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: FakeConn())


@pytest.fixture
def mock_tcp_fail(monkeypatch):
    def _fail(addr, timeout):
        raise OSError("Connection refused")

    monkeypatch.setattr(socket, "create_connection", _fail)


def make_http_client(status_code=200, reason="OK", final_url="https://example.com/", history=None):
    """Build an httpx.Client substitute with a canned response."""
    import httpx

    class FakeResponse:
        pass

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def get(self, url):
            resp = FakeResponse()
            resp.status_code = status_code
            resp.reason_phrase = reason
            resp.url = httpx.URL(final_url)
            resp.history = history or []
            return resp

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    return FakeClient


@pytest.fixture
def mock_http_200(monkeypatch):
    monkeypatch.setattr(
        "infra_check.checks.http.httpx.Client", make_http_client(status_code=200, reason="OK")
    )
