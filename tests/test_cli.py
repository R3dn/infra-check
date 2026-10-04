"""CLI tests via Click's test runner — fully mocked, no live endpoints.

Click 8.5's ``Result.output`` merges stdout and stderr; ``result.stderr``
is available separately. Exit-code contract: 0 healthy, 1 degraded,
2 unhealthy, 64 usage error, 70 internal error.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from infra_check.cli import EXIT_INTERNAL, EXIT_USAGE
from infra_check.cli import check_command as main


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


@pytest.fixture
def warn_stack(mock_dns, mock_tcp_ok, mock_tls_warn, monkeypatch):
    """Passing stack except a certificate nearing expiry (WARN)."""
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
        result = runner.invoke(main, ["example.com", "--port", "80", "--json"])
        payload = json.loads(result.output)
        names = {c["name"]: c for c in payload["targets"][0]["checks"]}
        assert names["tls"]["status"] == "SKIP"
        assert names["certificate"]["status"] == "SKIP"
        # Stable schema: redirect check always present on http runs.
        assert names["redirect"]["status"] in ("PASS", "WARN", "FAIL")

    def test_redirect_check_present_on_https_skip(self, runner, healthy_stack):
        """The redirect result must never silently vanish from the report."""
        result = runner.invoke(main, ["example.com", "--json"])
        payload = json.loads(result.output)
        names = {c["name"]: c for c in payload["targets"][0]["checks"]}
        assert names["redirect"]["status"] == "SKIP"


class TestJsonOutput:
    def test_json_healthy(self, runner, healthy_stack):
        result = runner.invoke(main, ["example.com", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["tool"] == "infra-check"
        assert payload["summary"]["overall"] == "HEALTHY"
        assert payload["targets"][0]["target"] == "example.com"
        names = [c["name"] for c in payload["targets"][0]["checks"]]
        # Default run always reports the same seven checks.
        assert names == ["dns", "tcp", "tls", "certificate", "http", "latency", "redirect"]

    def test_json_failure_envelope(self, runner, mock_dns_failure):
        result = runner.invoke(main, ["nope.invalid", "--json"])
        assert result.exit_code == 2
        payload = json.loads(result.output)
        assert payload["summary"]["overall"] == "UNHEALTHY"
        assert payload["targets"][0]["overall"] == "UNHEALTHY"


class TestShortCircuit:
    def test_dns_failure_skips_downstream(self, runner, mock_dns_failure):
        """One DNS failure, one report line — downstream checks SKIP."""
        result = runner.invoke(main, ["nope.invalid", "--json"])
        payload = json.loads(result.output)
        checks = {c["name"]: c for c in payload["targets"][0]["checks"]}
        assert checks["dns"]["status"] == "FAIL"
        assert checks["tcp"]["status"] == "SKIP"
        assert checks["tls"]["status"] == "SKIP"
        assert checks["certificate"]["status"] == "SKIP"
        assert checks["http"]["status"] == "SKIP"
        assert checks["latency"]["status"] == "SKIP"
        assert checks["redirect"]["status"] == "SKIP"
        assert payload["summary"]["overall"] == "UNHEALTHY"

    def test_tcp_failure_skips_tls_http(self, runner, mock_dns, mock_tcp_fail):
        result = runner.invoke(main, ["example.com", "--json"])
        payload = json.loads(result.output)
        checks = {c["name"]: c for c in payload["targets"][0]["checks"]}
        assert checks["dns"]["status"] == "PASS"
        assert checks["tcp"]["status"] == "FAIL"
        assert checks["tls"]["status"] == "SKIP"
        assert checks["http"]["status"] == "SKIP"


class TestFlags:
    def test_check_subset(self, runner, healthy_stack):
        result = runner.invoke(main, ["--checks", "dns,http", "example.com", "--json"])
        assert result.exit_code == 0
        names = {c["name"] for c in json.loads(result.output)["targets"][0]["checks"]}
        assert names == {"dns", "http", "latency", "redirect"}

    def test_unknown_check_rejected(self, runner, healthy_stack):
        result = runner.invoke(main, ["--checks", "bogus", "example.com"])
        assert result.exit_code == EXIT_USAGE
        assert "unknown checks" in result.output

    def test_fail_on_never_softens_warn(self, runner, warn_stack):
        result = runner.invoke(main, ["example.com", "--json", "--fail-on", "never"])
        payload = json.loads(result.output)
        assert payload["summary"]["overall"] == "DEGRADED"  # cert 15 days -> WARN
        assert result.exit_code == 0  # but never fails CI

    def test_fail_on_error_exits_1_on_warn(self, runner, warn_stack):
        result = runner.invoke(main, ["example.com", "--fail-on", "error"])
        assert result.exit_code == 1

    def test_fail_on_error_is_default(self, runner, warn_stack):
        result = runner.invoke(main, ["example.com"])
        assert result.exit_code == 1

    def test_no_verify_tls_warns_on_stderr(self, runner, healthy_stack):
        result = runner.invoke(main, ["example.com", "--no-verify-tls", "--json"])
        assert "verification is DISABLED" in result.stderr
        # JSON on stdout stays parseable despite the stderr warning.
        payload = json.loads(result.stdout)
        assert payload["tool"] == "infra-check"

    def test_no_verify_tls_cert_check_skips(self, runner, mock_dns, mock_tcp_ok, monkeypatch):
        """--no-verify-tls: tls check passes, certificate check SKIPs."""
        from infra_check.checks import tls as tls_module
        from tests.conftest import _make_tls_info, make_http_client

        info = _make_tls_info(days_left=90)
        # getpeercert returns {} without verification: model that.
        empty = tls_module.TlsInfo(
            protocol=info.protocol,
            cipher=info.cipher,
            not_before=None,
            not_after=None,
            subject_cn=None,
            issuer_org=None,
            sans=[],
        )
        monkeypatch.setattr(tls_module, "_handshake", lambda t, p, th: empty)
        monkeypatch.setattr(
            "infra_check.checks.http.httpx.Client",
            make_http_client(status_code=200, reason="OK", final_url="https://example.com/"),
        )
        result = runner.invoke(main, ["example.com", "--no-verify-tls", "--json"])
        payload = json.loads(result.stdout)
        checks = {c["name"]: c for c in payload["targets"][0]["checks"]}
        assert checks["tls"]["status"] == "PASS"
        assert checks["certificate"]["status"] == "SKIP"

    def test_port_validation_exits_64_via_entry_point(self, monkeypatch):
        """The real console entry point maps usage errors to exit 64."""
        import sys

        from infra_check.cli import main as entry_point

        monkeypatch.setattr(sys, "argv", ["infra-check", "example.com", "--port", "99999"])
        try:
            entry_point()
        except SystemExit as e:
            assert e.code == EXIT_USAGE
        else:
            raise AssertionError("entry point must exit")

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
        assert "--no-verify-tls" in result.output


class TestInternalErrors:
    def test_unexpected_exception_exits_70(self, runner, monkeypatch):
        """A tool crash must not masquerade as a health verdict."""
        import infra_check.cli as cli_module

        def _boom(target, port, thresholds, checks):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(cli_module, "run_checks", _boom)
        result = runner.invoke(main, ["example.com"])
        assert result.exit_code == EXIT_INTERNAL
        assert "internal error" in result.output
