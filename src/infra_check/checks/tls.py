"""TLS handshake and certificate checks.

Both checks share one verified handshake per target: ``run_tls_checks``
performs the connection once and derives the ``tls`` and ``certificate``
results from the same captured facts.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from infra_check.engine import CheckResult, Status, Thresholds, classify_cert

#: Parsed shape returned by ``SSLSocket.getpeercert()`` (untyped in typeshed).
CertDict = dict[str, Any]


@dataclass(frozen=True)
class TlsInfo:
    """Facts captured during a (verified or unverified) TLS handshake."""

    protocol: str
    cipher: str
    not_before: str | None
    not_after: str | None
    subject_cn: str | None
    issuer_org: str | None
    sans: list[str]

    @property
    def expires_utc(self) -> datetime | None:
        """Locale-safe parse of ``notAfter`` (getpeercert dates are always English)."""
        if not self.not_after:
            return None
        return datetime.fromtimestamp(
            ssl.cert_time_to_seconds(self.not_after), tz=timezone.utc
        )

    @property
    def valid_from_utc(self) -> datetime | None:
        if not self.not_before:
            return None
        return datetime.fromtimestamp(
            ssl.cert_time_to_seconds(self.not_before), tz=timezone.utc
        )


def _issuer_org(cert: CertDict) -> str | None:
    for rdn in cert.get("issuer", ()):
        if not isinstance(rdn, tuple):
            continue
        for key, value in rdn:
            if key == "organizationName" and isinstance(value, str) and value:
                return value
    return None


def _subject_cn(cert: CertDict) -> str | None:
    for rdn in cert.get("subject", ()):
        if not isinstance(rdn, tuple):
            continue
        for key, value in rdn:
            if key == "commonName" and isinstance(value, str) and value:
                return value
    return None


def _sans(cert: CertDict) -> list[str]:
    sans = cert.get("subjectAltName", ())
    return [v for k, v in sans if k == "DNS" and isinstance(v, str)]


def _handshake(target: str, port: int, thresholds: Thresholds) -> TlsInfo:
    """Open a TLS connection and capture facts; raises on any TLS failure.

    Verification is on by default. With ``verify_tls`` disabled — the
    ``--no-verify-tls`` diagnostic switch — the handshake succeeds against
    untrusted (e.g. self-signed) certificates; Python does not parse
    certificate fields without verification, so cert facts are ``None``
    and the certificate check reports SKIP.
    """
    ctx = ssl.create_default_context()
    if not thresholds.verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((target, port), timeout=thresholds.timeout) as sock,
        ctx.wrap_socket(sock, server_hostname=target) as tls_sock,
    ):
        tls_sock.do_handshake()
        cipher_pair = tls_sock.cipher()
        cert: CertDict = tls_sock.getpeercert() or {}
        return TlsInfo(
            protocol=tls_sock.version() or "unknown",
            cipher=cipher_pair[0] if cipher_pair else "unknown",
            not_before=cert.get("notBefore"),
            not_after=cert.get("notAfter"),
            subject_cn=_subject_cn(cert) or None,
            issuer_org=_issuer_org(cert) or None,
            sans=_sans(cert),
        )


def _fail(name: str, exc: Exception) -> CheckResult:
    return CheckResult(name=name, status=Status.FAIL, detail=f"handshake failed: {exc}")


def _tls_result(info: TlsInfo) -> CheckResult:
    return CheckResult(
        name="tls",
        status=Status.PASS,
        detail=f"{info.protocol}, cipher {info.cipher}",
        data={"protocol": info.protocol, "cipher": info.cipher},
    )


def _cert_result(info: TlsInfo, thresholds: Thresholds) -> CheckResult:
    if not thresholds.verify_tls:
        return CheckResult(
            name="certificate",
            status=Status.SKIP,
            detail="skipped: TLS verification disabled (--no-verify-tls)",
        )
    expires = info.expires_utc
    if not expires:
        return CheckResult(
            name="certificate",
            status=Status.FAIL,
            detail="certificate exposes no expiry date",
        )

    days_left = (expires - datetime.now(timezone.utc)).days
    status = classify_cert(days_left, thresholds)
    valid_from = info.valid_from_utc
    return CheckResult(
        name="certificate",
        status=status,
        detail=f"expires in {days_left} days ({expires.date().isoformat()})",
        data={
            "days_left": days_left,
            "expires": expires.date().isoformat(),
            "valid_from": valid_from.date().isoformat() if valid_from else None,
            "subject": info.subject_cn,
            "issuer": info.issuer_org,
            "sans": info.sans,
        },
    )


def run_tls_checks(target: str, port: int, thresholds: Thresholds) -> list[CheckResult]:
    """Derive the ``tls`` and ``certificate`` results from a single handshake."""
    try:
        info = _handshake(target, port, thresholds)
    except (ssl.SSLError, OSError) as exc:
        return [_fail("tls", exc), _fail("certificate", exc)]
    return [_tls_result(info), _cert_result(info, thresholds)]


def check_tls(target: str, port: int, thresholds: Thresholds) -> CheckResult:
    """Single-shot TLS check (kept for direct/test use)."""
    return run_tls_checks(target, port, thresholds)[0]


def check_certificate(target: str, port: int, thresholds: Thresholds) -> CheckResult:
    """Single-shot certificate check (kept for direct/test use)."""
    return run_tls_checks(target, port, thresholds)[1]
