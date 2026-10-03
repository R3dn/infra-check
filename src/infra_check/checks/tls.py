"""TLS handshake and certificate expiry checks."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from infra_check.engine import CheckResult, Status, Thresholds, classify_cert


@dataclass(frozen=True)
class TlsInfo:
    """Facts captured during a verified TLS handshake."""

    protocol: str
    cipher: str
    not_after: str | None
    issuer_org: str | None


def _handshake(target: str, port: int, thresholds: Thresholds) -> TlsInfo:
    """Open a verified TLS connection and capture facts; raises on any TLS failure."""
    ctx = ssl.create_default_context()
    with (
        socket.create_connection((target, port), timeout=thresholds.timeout) as sock,
        ctx.wrap_socket(sock, server_hostname=target) as tls_sock,
    ):
            tls_sock.do_handshake()
            cipher_pair = tls_sock.cipher()
            cert = tls_sock.getpeercert()
            issuer = None
            for entry in cert.get("issuer", ()):  # type: ignore[union-attr]
                try:
                    key, value = entry
                except (TypeError, ValueError):
                    continue
                if key == "organizationName" and value:
                    issuer = value
                    break
            return TlsInfo(
                protocol=tls_sock.version() or "unknown",
                cipher=cipher_pair[0] if cipher_pair else "unknown",
                not_after=cert.get("notAfter"),  # type: ignore[union-attr]
                issuer_org=issuer,
            )


def _fail(name: str, exc: Exception) -> CheckResult:
    return CheckResult(name=name, status=Status.FAIL, detail=f"handshake failed: {exc}")


def check_tls(target: str, port: int, thresholds: Thresholds) -> CheckResult:
    try:
        info = _handshake(target, port, thresholds)
    except (ssl.SSLError, OSError) as exc:
        return _fail("tls", exc)

    return CheckResult(
        name="tls",
        status=Status.PASS,
        detail=f"{info.protocol}, cipher {info.cipher}",
        data={"protocol": info.protocol, "cipher": info.cipher},
    )


def check_certificate(target: str, port: int, thresholds: Thresholds) -> CheckResult:
    try:
        info = _handshake(target, port, thresholds)
    except (ssl.SSLError, OSError) as exc:
        return _fail("certificate", exc)

    if not info.not_after:
        return CheckResult(
            name="certificate",
            status=Status.FAIL,
            detail="certificate exposes no expiry date",
        )

    expires = datetime.strptime(info.not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_left = (expires - datetime.now(timezone.utc)).days
    status = classify_cert(days_left, thresholds)

    return CheckResult(
        name="certificate",
        status=status,
        detail=f"expires in {days_left} days ({expires.date().isoformat()})",
        data={
            "days_left": days_left,
            "expires": expires.date().isoformat(),
            "issuer": info.issuer_org,
        },
    )
