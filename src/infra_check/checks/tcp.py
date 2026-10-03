"""TCP connectivity check."""

from __future__ import annotations

import socket
import time

from infra_check.engine import CheckResult, Status, Thresholds


def check_tcp(target: str, port: int, thresholds: Thresholds) -> CheckResult:
    start = time.perf_counter()
    try:
        with socket.create_connection((target, port), timeout=thresholds.timeout):
            elapsed_ms = (time.perf_counter() - start) * 1000
    except OSError as exc:
        return CheckResult(
            name="tcp",
            status=Status.FAIL,
            detail=f"connect failed: {exc}",
        )

    return CheckResult(
        name="tcp",
        status=Status.PASS,
        detail=f"connected in {elapsed_ms:.0f} ms",
        data={"connect_ms": round(elapsed_ms, 1)},
    )
