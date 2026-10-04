"""Shared fixtures: all network layers are mocked — tests never hit live endpoints."""

from __future__ import annotations

import socket
import ssl
import time
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


@pytest.fixture
def mock_dns_timeout(monkeypatch):
    """Resolution that blocks past the timeout — exercises the bounded lookup."""

    def _hang(host, port, *args, **kwargs):
        time.sleep(5)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _hang)


def _make_tls_info(days_left=90, protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384"):
    from infra_check.checks.tls import TlsInfo

    now = datetime.now(timezone.utc)
    return TlsInfo(
        protocol=protocol,
        cipher=cipher,
        not_before=(now - timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT"),
        not_after=(now + timedelta(days=days_left)).strftime("%b %d %H:%M:%S %Y GMT"),
        subject_cn="example.com",
        issuer_org="Fake CA Inc",
        sans=["example.com", "www.example.com"],
    )


def _patch_handshake(monkeypatch, days_left=90):
    """Patch tls._handshake to return a TlsInfo with the given validity."""
    from infra_check.checks import tls as tls_module

    info = _make_tls_info(days_left=days_left)
    calls = {"n": 0}

    def _handshake(target, port, thresholds):
        calls["n"] += 1
        return info

    monkeypatch.setattr(tls_module, "_handshake", _handshake)
    return calls


@pytest.fixture
def mock_tls_ok(monkeypatch):
    return _patch_handshake(monkeypatch, days_left=90)


@pytest.fixture
def mock_tls_warn(monkeypatch):
    return _patch_handshake(monkeypatch, days_left=15)


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


def make_http_client(
    status_code=200,
    reason="OK",
    final_url="https://example.com/",
    history=None,
    delay=0.0,
):
    """Build an httpx.Client substitute with a canned streaming response."""

    class FakeResponse:
        pass

    class FakeStream:
        def __init__(self, resp):
            self._resp = resp

        def __enter__(self):
            if delay:
                time.sleep(delay)
            return self._resp

        def __exit__(self, *exc):
            return False

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def stream(self, method, url):
            resp = FakeResponse()
            resp.status_code = status_code
            resp.reason_phrase = reason
            resp.url = final_url
            resp.history = history or []
            return FakeStream(resp)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    return FakeClient


class _FakeURL:
    """Minimal str-like url (streaming tests patch httpx.URL parsing away)."""


def make_http_result(status_code=200, reason="OK", final_url="https://example.com/", history=None):
    return make_http_client(status_code, reason, final_url, history)


@pytest.fixture
def mock_http_200(monkeypatch):
    monkeypatch.setattr(
        "infra_check.checks.http.httpx.Client",
        make_http_client(status_code=200, reason="OK"),
    )


def healthy_http_patch(
    monkeypatch,
    final_url="https://example.com/",
    history=None,
    status_code=200,
    reason="OK",
):
    """Patch the HTTP layer for a canned response (used by CLI tests)."""
    monkeypatch.setattr(
        "infra_check.checks.http.httpx.Client",
        make_http_client(
            status_code=status_code, reason=reason, final_url=final_url, history=history
        ),
    )
