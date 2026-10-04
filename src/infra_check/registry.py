"""Check registry: ordered checks and target orchestration.

Checks are dependent by nature (DNS → TCP → TLS → HTTP): a failed
upstream check short-circuits its dependents to SKIP so a single
failure is reported once instead of being re-attempted — and
mis-attributed — by every downstream check.
"""

from __future__ import annotations

from collections.abc import Iterable

from infra_check.checks import http as http_check
from infra_check.checks import tcp as tcp_check
from infra_check.checks import tls as tls_check
from infra_check.engine import CheckResult, Status, TargetReport, Thresholds

#: Canonical check order as shown in reports.
ALL_CHECKS = ("dns", "tcp", "tls", "certificate", "http", "latency", "redirect")

#: Ports where a TLS handshake is not expected.
NON_TLS_PORTS = (80,)

#: Reasons a dependent check is skipped when its upstream dependency failed.
SKIP_NO_DNS = "skipped: dns failed"
SKIP_NO_TCP = "skipped: tcp failed"


def normalize_selection(selected: Iterable[str] | None) -> tuple[str, ...]:
    """Validate a --checks selection against known check names."""
    if not selected:
        return ALL_CHECKS
    names = tuple(
        name.strip().lower() for chunk in selected for name in chunk.split(",") if name.strip()
    )
    unknown = [n for n in names if n not in ALL_CHECKS]
    if unknown:
        allowed = ", ".join(ALL_CHECKS)
        raise ValueError(f"unknown checks: {', '.join(unknown)} (choose from {allowed})")
    # Keep canonical order regardless of user input order.
    return tuple(n for n in ALL_CHECKS if n in names)


def _skip(name: str, reason: str) -> CheckResult:
    return CheckResult(name=name, status=Status.SKIP, detail=reason)


def run_checks(
    target: str,
    port: int,
    thresholds: Thresholds,
    checks: tuple[str, ...],
    scheme: str | None = None,
) -> TargetReport:
    """Run the selected checks against one target and build its report.

    ``scheme`` overrides port-based inference for the HTTP request URL.
    """
    report = TargetReport(target=target, port=port)

    dns_failed = False
    if "dns" in checks:
        from infra_check.checks import dns as dns_check

        result = dns_check.check_dns(target, thresholds)
        report.add(result)
        dns_failed = result.status is Status.FAIL

    tcp_failed = dns_failed
    if "tcp" in checks:
        if dns_failed:
            report.add(_skip("tcp", SKIP_NO_DNS))
        else:
            result = tcp_check.check_tcp(target, port, thresholds)
            report.add(result)
            tcp_failed = result.status is Status.FAIL

    tls_requested = [c for c in checks if c in ("tls", "certificate")]
    if tls_requested:
        if port in NON_TLS_PORTS:
            for name in tls_requested:
                report.add(_skip(name, f"not applicable on port {port}"))
        elif dns_failed:
            for name in tls_requested:
                report.add(_skip(name, SKIP_NO_DNS))
        elif tcp_failed:
            for name in tls_requested:
                report.add(_skip(name, SKIP_NO_TCP))
        else:
            # Single handshake shared by both the tls and certificate checks.
            info = tls_check.run_tls_checks(target, port, thresholds)
            for result in info:
                if result.name in tls_requested:
                    report.add(result)

    http_requested = [c for c in checks if c in ("http", "latency", "redirect")]
    if http_requested:
        if dns_failed:
            for name in http_requested:
                report.add(_skip(name, SKIP_NO_DNS))
        elif tcp_failed:
            for name in http_requested:
                report.add(_skip(name, SKIP_NO_TCP))
        else:
            for result in http_check.check_http(target, port, thresholds, scheme=scheme):
                report.add(result)

    return report
