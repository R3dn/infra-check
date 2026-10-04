"""HTTP status, latency and redirect checks.

Latency is measured as **time to first byte**: the request is streamed and
the timer stops once response headers arrive — the response body is never
downloaded. Redirects are followed; the redirect check reports where the
chain ended (a chain that lands on https is healthy, one that stays on
http is not).

The request scheme is inferred from the port (443/8443 -> https) unless an
explicit ``scheme`` is given, e.g. by tests pinning https on an
non-standard port.
"""

from __future__ import annotations

import time

import httpx

from infra_check.engine import CheckResult, Status, Thresholds, classify_latency, classify_redirect

#: Ports whose traffic is TLS-encrypted; used for scheme inference.
TLS_PORTS = (443, 8443)


def _client(thresholds: Thresholds) -> httpx.Client:
    return httpx.Client(
        timeout=thresholds.timeout,
        follow_redirects=True,
        verify=thresholds.verify_tls,
    )


def _url(target: str, port: int, scheme: str | None = None) -> str:
    scheme = scheme or ("https" if port in TLS_PORTS else "http")
    url = f"{scheme}://{target}"
    if port not in (80, 443):
        url = f"{url}:{port}"
    return url


def _transport_failure(exc: Exception) -> list[CheckResult]:
    return [
        CheckResult(name="http", status=Status.FAIL, detail=f"request failed: {exc}"),
        CheckResult(name="latency", status=Status.SKIP, detail="skipped: request failed"),
        CheckResult(name="redirect", status=Status.SKIP, detail="skipped: request failed"),
    ]


def check_http(
    target: str, port: int, thresholds: Thresholds, scheme: str | None = None
) -> list[CheckResult]:
    """Run HTTP, latency and redirect checks; returns exactly three results."""
    url = _url(target, port, scheme)
    with _client(thresholds) as client:
        start = time.perf_counter()
        try:
            with client.stream("GET", url) as response:
                # Time to first byte: headers arrived; the body is never read.
                elapsed_ms = (time.perf_counter() - start) * 1000
                code = response.status_code
                reason = response.reason_phrase
                final_url = str(response.url)
                hops = len(response.history)
        except httpx.HTTPError as exc:
            return _transport_failure(exc)

    http_status = Status.PASS if code < 400 else Status.FAIL
    http_result = CheckResult(
        name="http",
        status=http_status,
        detail=f"HTTP {code} {reason}",
        data={"status_code": code, "reason": reason},
    )
    latency_result = CheckResult(
        name="latency",
        status=classify_latency(elapsed_ms, thresholds),
        detail=f"{elapsed_ms:.0f} ms",
        data={"latency_ms": round(elapsed_ms, 1)},
    )

    # Redirect: only meaningful when the initial request was plain http.
    if url.startswith("http://"):
        final_https = final_url.startswith("https://")
        redirect_status = classify_redirect(followed_https=hops > 0, final_https=final_https)
        if hops > 0:
            detail = f"redirected to {final_url} ({hops} hop(s))"
        else:
            detail = "no redirect; stayed on http"
        redirect_result = CheckResult(
            name="redirect",
            status=redirect_status,
            detail=detail,
            data={"final_url": final_url, "hops": hops},
        )
    else:
        redirect_result = CheckResult(
            name="redirect",
            status=Status.SKIP,
            detail="not applicable: initial request is https",
        )

    return [http_result, latency_result, redirect_result]
