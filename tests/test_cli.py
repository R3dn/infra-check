"""CLI end-to-end tests via Click's test runner — fully mocked, no live endpoints."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from infra_check.cli import main


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def healthy_stack(mock_dns, mock_tcp_ok, mock_tls_ok, monkeypatch):
    """Wire every check to its passing mock and mock HTTP 200."""
    from tests.conftest import make_http_client

    monkeypatch.setattr(
        "infra_check.checks.http.httpx.Client",
        make_http_client(status_code=200, reason="OK", final_url="https://example.com/"),
    )


class TestHumanOutput:
    def test_healthy_exit_zero(self, runner, healthy_stack):
        result = runner.invoke(main, ["example.com"])
        assert result.exit_code == 0
        assert "HEALTHY" in result.output
        assert "Dns" in result.output
        assert "Certificate" in result.output

    def test_dns_only_failure(self, runner, mock_dns_failure):
        result = runner.invoke(main, ["nope.invalid"])
        assert result.exit_code == 2
        assert "UNHEALTHY" in result.output

    def test_multiple_targets_print_summary(self, runner, healthy_stack):
        result = runner.invoke(main, ["a.com", "b.com"])
        assert result.exit_code == 0
        assert "2 healthy" in result.output

    def test_port_80_skips_tls(self, runner, healthy_stack):
        # Port 80 forces http:// where the healthy_stack mock returns an https URL;
        # httpx.URL re-parsing keeps it valid for the redirect check.
        result = runner.invoke(main, ["example.com", "--port", "80", "--json"])
        assert result.exit_code in (0, 1, 2)
        payload = json.loads(result.output)
        names = {c["name"]: c for c in payload["targets"][0]["checks"]}
        assert names["tls"]["status"] == "SKIP"
        assert names["certificate"]["status"] == "SKIP"


class TestJsonOutput:
    def test_json_healthy(self, runner, healthy_stack):
        result = runner.invoke(main, ["example.com", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["tool"] == "infra-check"
        assert payload["summary"]["overall"] == "HEALTHY"
        assert payload["targets"][0]["target"] == "example.com"
        names = [c["name"] for c in payload["targets"][0]["checks"]]
        assert "dns" in names and "tls" in names and "certificate" in names

    def test_json_failure_envelope(self, runner, mock_dns_failure):
        result = runner.invoke(main, ["nope.invalid", "--json"])
        assert result.exit_code == 2
        payload = json.loads(result.output)
        assert payload["summary"]["overall"] == "UNHEALTHY"
        assert payload["targets"][0]["overall"] == "UNHEALTHY"


class TestFlags:
    def test_check_subset(self, runner, healthy_stack):
        result = runner.invoke(main, ["--checks", "dns,http", "example.com", "--json"])
        assert result.exit_code == 0
        names = {c["name"] for c in json.loads(result.output)["targets"][0]["checks"]}
        assert names == {"dns", "http"}

    def test_unknown_check_rejected(self, runner, healthy_stack):
        result = runner.invoke(main, ["--checks", "bogus", "example.com"])
        assert result.exit_code == 2
        assert "unknown checks" in result.output

    def test_fail_on_never_softens_warn(
        self, runner, mock_dns, mock_tcp_ok, mock_tls_warn, monkeypatch
    ):
        from tests.conftest import make_http_client

        monkeypatch.setattr(
            "infra_check.checks.http.httpx.Client",
            make_http_client(status_code=200, reason="OK", final_url="https://example.com/"),
        )

        result = runner.invoke(main, ["example.com", "--json", "--fail-on", "never"])
        payload = json.loads(result.output)
        assert payload["summary"]["overall"] == "DEGRADED"  # cert 15 days -> WARN
        assert result.exit_code == 0  # but never fails CI

    def test_fail_on_warn_hardens(self, runner, mock_dns, mock_tcp_ok, mock_tls_warn, monkeypatch):
        from tests.conftest import make_http_client

        monkeypatch.setattr(
            "infra_check.checks.http.httpx.Client",
            make_http_client(status_code=200, reason="OK", final_url="https://example.com/"),
        )

        result = runner.invoke(main, ["example.com", "--fail-on", "warn"])
        assert result.exit_code == 1

    def test_version(self, runner):
        from infra_check import __version__

        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_help(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "--json" in result.output
        assert "--fail-on" in result.output
