"""HTTP status, latency and redirect checks."""

from __future__ import annotations

import time

import httpx

from infra_check.engine import CheckResult, Status, Thresholds, classify_latency, classify_redirect


def _client(thresholds: Thresholds) -> httpx.Client:
    return httpx.Client(
        timeout=thresholds.timeout,
        follow_redirects=True,
        # We validate TLS ourselves via the tls checks; keep HTTP errors
        # (4xx/5xx) as responses instead of exceptions.
        verify=True,
    )


def check_http(target: str, port: int, thresholds: Thresholds) -> list[CheckResult]:
    """Run HTTP, latency and redirect checks; returns 2-3 results."""
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{target}"
    if port not in (80, 443):
        url = f"{scheme}://{target}:{port}"

    results: list[CheckResult] = []
    with _client(thresholds) as client:
        try:
            start = time.perf_counter()
            response = client.get(url)
            elapsed_ms = (time.perf_counter() - start) * 1000
        except httpx.HTTPError as exc:
            return [
                CheckResult(name="http", status=Status.FAIL, detail=f"request failed: {exc}"),
                CheckResult(
                    name="latency", status=Status.SKIP, detail="skipped: request failed"
                ),
                CheckResult(
                    name="redirect", status=Status.SKIP, detail="skipped: request failed"
                ),
            ]

        code = response.status_code
        http_status = Status.PASS if code < 400 else Status.FAIL
        results.append(
            CheckResult(
                name="http",
                status=http_status,
                detail=f"HTTP {code} {response.reason_phrase}",
                data={"status_code": code, "reason": response.reason_phrase},
            )
        )

        latency_status = classify_latency(elapsed_ms, thresholds)
        results.append(
            CheckResult(
                name="latency",
                status=latency_status,
                detail=f"{elapsed_ms:.0f} ms",
                data={"latency_ms": round(elapsed_ms, 1)},
            )
        )

        if scheme == "http":
            final_scheme = response.url.scheme
            followed = len(response.history) > 0
            on_https = final_scheme == "https"
            redirect_status = classify_redirect(followed_https=followed, final_https=on_https)
            results.append(
                CheckResult(
                    name="redirect",
                    status=redirect_status,
                    detail=(
                        f"redirected to {response.url} ({len(response.history)} hop(s))"
                        if followed
                        else f"no redirect; stayed on {response.url.scheme}"
                    ),
                    data={
                        "final_url": str(response.url),
                        "hops": len(response.history),
                    },
                )
            )

    return results
