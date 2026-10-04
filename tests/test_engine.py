"""Engine unit tests: pure logic, no I/O."""

from __future__ import annotations

from infra_check.engine import (
    EXIT_DEGRADED,
    EXIT_OK,
    EXIT_UNHEALTHY,
    Status,
    TargetReport,
    Thresholds,
    Verdict,
    aggregate_verdict,
    build_envelope,
    classify_cert,
    classify_latency,
    classify_redirect,
    exit_code,
)
from infra_check.registry import ALL_CHECKS, normalize_selection


def _report(statuses: dict[str, Status], target="example.com", port=443) -> TargetReport:
    from infra_check.engine import CheckResult

    report = TargetReport(target=target, port=port)
    for name, status in statuses.items():
        report.add(CheckResult(name=name, status=status, detail=""))
    return report


class TestClassification:
    def test_latency_pass(self):
        assert classify_latency(50, Thresholds()) is Status.PASS

    def test_latency_warn(self):
        assert classify_latency(500, Thresholds()) is Status.WARN

    def test_latency_fail(self):
        assert classify_latency(1500, Thresholds()) is Status.FAIL

    def test_cert_pass(self):
        assert classify_cert(143, Thresholds()) is Status.PASS

    def test_cert_warn_below_30(self):
        assert classify_cert(20, Thresholds()) is Status.WARN

    def test_cert_fail_below_7(self):
        assert classify_cert(3, Thresholds()) is Status.FAIL

    def test_cert_fail_expired(self):
        assert classify_cert(-1, Thresholds()) is Status.FAIL

    def test_custom_thresholds(self):
        t = Thresholds.merge(Thresholds(), cert_warn_days=60, latency_fail_ms=2000.0)
        assert t.cert_warn_days == 60
        assert t.latency_fail_ms == 2000.0
        assert t.cert_fail_days == 7  # unchanged

    def test_merge_none_overrides_ignored(self):
        t = Thresholds.merge(Thresholds(), cert_warn_days=None, verify_tls=None)
        assert t.cert_warn_days == 30
        assert t.verify_tls is True

    def test_merge_verify_tls_false(self):
        t = Thresholds.merge(Thresholds(), verify_tls=False)
        assert t.verify_tls is False

    def test_redirect_to_https_pass(self):
        assert classify_redirect(followed_https=True, final_https=True) is Status.PASS

    def test_redirect_stays_http_fail(self):
        assert classify_redirect(followed_https=True, final_https=False) is Status.FAIL

    def test_no_redirect_http_warn(self):
        assert classify_redirect(followed_https=False, final_https=False) is Status.WARN


class TestVerdictAggregation:
    def test_healthy(self):
        report = _report({"dns": Status.PASS, "tcp": Status.PASS})
        assert report.verdict is Verdict.HEALTHY

    def test_degraded_on_warn(self):
        report = _report({"dns": Status.PASS, "latency": Status.WARN})
        assert report.verdict is Verdict.DEGRADED

    def test_unhealthy_on_fail(self):
        report = _report({"dns": Status.PASS, "tls": Status.FAIL})
        assert report.verdict is Verdict.UNHEALTHY

    def test_skip_does_not_degrade(self):
        report = _report({"dns": Status.PASS, "tls": Status.SKIP})
        assert report.verdict is Verdict.HEALTHY

    def test_aggregate_multi_target(self):
        healthy = _report({"dns": Status.PASS})
        degraded = _report({"dns": Status.WARN})
        unhealthy = _report({"dns": Status.FAIL})
        assert aggregate_verdict([healthy, degraded]) is Verdict.DEGRADED
        assert aggregate_verdict([healthy, unhealthy]) is Verdict.UNHEALTHY
        assert aggregate_verdict([healthy]) is Verdict.HEALTHY


class TestExitCodes:
    def test_healthy_exit_0(self):
        assert exit_code([_report({"dns": Status.PASS})], "error") == EXIT_OK

    def test_degraded_exit_1_by_default(self):
        assert exit_code([_report({"dns": Status.WARN})], "error") == EXIT_DEGRADED

    def test_degraded_exit_0_when_never(self):
        assert exit_code([_report({"dns": Status.WARN})], "never") == EXIT_OK

    def test_unhealthy_exit_2(self):
        assert exit_code([_report({"dns": Status.FAIL})], "never") == EXIT_UNHEALTHY

    def test_worst_exit_wins(self):
        reports = [_report({"dns": Status.WARN}), _report({"dns": Status.FAIL})]
        assert exit_code(reports, "error") == EXIT_UNHEALTHY


class TestEnvelope:
    def test_envelope_shape(self):
        reports = [_report({"dns": Status.PASS})]
        env = build_envelope(reports)
        assert env["tool"] == "infra-check"
        assert env["summary"] == {"targets": 1, "overall": "HEALTHY"}
        assert env["targets"][0]["target"] == "example.com"
        assert env["targets"][0]["overall"] == "HEALTHY"

    def test_envelope_checks_serialize(self):
        reports = [_report({"dns": Status.PASS, "latency": Status.WARN})]
        env = build_envelope(reports)
        statuses = [c["status"] for c in env["targets"][0]["checks"]]
        assert statuses == ["PASS", "WARN"]

    def test_envelope_is_json_serializable(self):
        import json

        json.dumps(build_envelope([_report({"dns": Status.PASS})]))


class TestCheckSelection:
    def test_default_is_all_checks(self):
        assert normalize_selection(None) == ALL_CHECKS
        assert normalize_selection([]) == ALL_CHECKS

    def test_subset_keeps_canonical_order(self):
        assert normalize_selection(["http", "dns"]) == ("dns", "http")

    def test_comma_string_split(self):
        assert normalize_selection(["dns,tcp"]) == ("dns", "tcp")

    def test_unknown_check_raises(self):
        import pytest

        with pytest.raises(ValueError, match="unknown checks"):
            normalize_selection(["dns,notacheck"])
