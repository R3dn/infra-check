"""Check registry: ordered checks and target orchestration."""

from __future__ import annotations

from collections.abc import Iterable

from infra_check.checks import dns, http, tcp, tls
from infra_check.engine import CheckResult, Status, TargetReport, Thresholds

#: Canonical check order as shown in reports.
ALL_CHECKS = ("dns", "tcp", "tls", "certificate", "http", "latency", "redirect")

#: Ports where a TLS handshake is not expected.
NON_TLS_PORTS = (80,)


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


def run_checks(
    target: str, port: int, thresholds: Thresholds, checks: tuple[str, ...]
) -> TargetReport:
    """Run the selected checks against one target and build its report."""
    report = TargetReport(target=target, port=port)

    if "dns" in checks:
        report.add(dns.check_dns(target))

    if "tcp" in checks:
        report.add(tcp.check_tcp(target, port, thresholds))

    tls_requested = [c for c in checks if c in ("tls", "certificate")]
    if tls_requested:
        if port in NON_TLS_PORTS:
            for name in tls_requested:
                report.add(
                    CheckResult(
                        name=name, status=Status.SKIP, detail=f"not applicable on port {port}"
                    )
                )
        else:
            if "tls" in tls_requested:
                report.add(tls.check_tls(target, port, thresholds))
            if "certificate" in tls_requested:
                report.add(tls.check_certificate(target, port, thresholds))

    http_requested = [c for c in checks if c in ("http", "latency", "redirect")]
    if http_requested:
        for result in http.check_http(target, port, thresholds):
            if result.name in http_requested:
                report.add(result)
            elif result.name == "http" and result.status is Status.FAIL:
                # Surface HTTP transport failure even when only latency/redirect was requested.
                report.add(result)

    return report
