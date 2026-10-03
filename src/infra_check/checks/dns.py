"""DNS resolution check."""

from __future__ import annotations

import socket

from infra_check.engine import CheckResult, Status


def check_dns(target: str) -> CheckResult:
    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(target, None)}
    except socket.gaierror as exc:
        return CheckResult(
            name="dns",
            status=Status.FAIL,
            detail=f"resolution failed: {exc}",
        )

    ordered = sorted(addrs)
    ipv4 = [a for a in ordered if "." in a]
    ipv6 = [a for a in ordered if ":" in a]
    data: dict[str, list[str]] = {}
    if ipv4:
        data["ipv4"] = ipv4
    if ipv6:
        data["ipv6"] = ipv6
    return CheckResult(
        name="dns",
        status=Status.PASS,
        detail=", ".join(ordered[:3]) + (" ..." if len(ordered) > 3 else ""),
        data=data,
    )
