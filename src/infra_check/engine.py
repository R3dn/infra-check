"""Check engine: result model, thresholds, aggregation and exit codes."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from infra_check import __version__


class Status(str, Enum):
    """Outcome of a single check."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"

    @property
    def symbol(self) -> str:
        return {self.PASS: "\u2713", self.WARN: "!", self.FAIL: "\u2717", self.SKIP: "-"}[self]


class Verdict(str, Enum):
    """Overall health of one target."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"


# Exit codes usable from CI.
EXIT_OK = 0
EXIT_DEGRADED = 1
EXIT_UNHEALTHY = 2

#: Aggregation order used when reducing statuses to a verdict.
_SEVERITY = {Status.FAIL: 3, Status.WARN: 2, Status.PASS: 1, Status.SKIP: 0}


@dataclass(frozen=True)
class Thresholds:
    """Configurable warning/failure limits."""

    cert_warn_days: int = 30
    cert_fail_days: int = 7
    latency_warn_ms: float = 300.0
    latency_fail_ms: float = 1000.0
    timeout: float = 10.0

    @staticmethod
    def merge(base: Thresholds, **overrides: float | int | None) -> Thresholds:
        """Return a copy of ``base`` with non-None overrides applied."""
        values = {
            k: v for k, v in overrides.items() if v is not None and hasattr(base, k)
        }
        return Thresholds(**{**base.__dict__, **values})  # type: ignore[arg-type]


def classify_latency(ms: float, t: Thresholds) -> Status:
    if ms >= t.latency_fail_ms:
        return Status.FAIL
    if ms >= t.latency_warn_ms:
        return Status.WARN
    return Status.PASS


def classify_cert(days_left: int, t: Thresholds) -> Status:
    if days_left < t.cert_fail_days:
        return Status.FAIL
    if days_left < t.cert_warn_days:
        return Status.WARN
    return Status.PASS


def classify_redirect(followed_https: bool, final_https: bool) -> Status:
    """http -> https redirect (or plain https) is healthy; staying on http is not."""
    if final_https:
        return Status.PASS
    return Status.FAIL if followed_https else Status.WARN


@dataclass
class CheckResult:
    """A single named check outcome."""

    name: str
    status: Status
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
            "data": self.data,
        }


@dataclass
class TargetReport:
    """All check results for one target."""

    target: str
    port: int
    checks: list[CheckResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)

    def add(self, result: CheckResult) -> None:
        self.checks.append(result)

    def by_name(self, name: str) -> CheckResult | None:
        return next((c for c in self.checks if c.name == name), None)

    @property
    def verdict(self) -> Verdict:
        statuses = [c.status for c in self.checks if c.status is not Status.SKIP]
        if any(s is Status.FAIL for s in statuses):
            return Verdict.UNHEALTHY
        if any(s is Status.WARN for s in statuses):
            return Verdict.DEGRADED
        return Verdict.HEALTHY

    def worst_status(self) -> Status:
        return max(
            (c.status for c in self.checks if c.status is not Status.SKIP),
            key=lambda s: _SEVERITY[s],
            default=Status.SKIP,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "port": self.port,
            "overall": self.verdict.value,
            "checks": [c.to_dict() for c in self.checks],
        }


def aggregate_verdict(reports: list[TargetReport]) -> Verdict:
    verdicts = [r.verdict for r in reports]
    if Verdict.UNHEALTHY in verdicts:
        return Verdict.UNHEALTHY
    if Verdict.DEGRADED in verdicts:
        return Verdict.DEGRADED
    return Verdict.HEALTHY


def exit_code(reports: list[TargetReport], fail_on: str) -> int:
    """Map aggregate result to a process exit code.

    ``fail_on``: ``"error"`` -> non-zero only on FAIL (DEGRADED exits 1),
    ``"warn"`` -> non-zero on WARN as well, ``"never"`` -> always 0.
    """
    verdict = aggregate_verdict(reports)
    if verdict is Verdict.UNHEALTHY:
        return EXIT_UNHEALTHY
    if verdict is Verdict.DEGRADED:
        return EXIT_DEGRADED if fail_on in ("error", "warn") else EXIT_OK
    return EXIT_OK


def build_envelope(reports: list[TargetReport]) -> dict[str, Any]:
    """Machine-readable JSON envelope for one or more targets."""
    from datetime import datetime, timezone

    return {
        "tool": "infra-check",
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {
            "targets": len(reports),
            "overall": aggregate_verdict(reports).value,
        },
        "targets": [r.to_dict() for r in reports],
    }
