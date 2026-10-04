# Changelog

All notable changes to infra-check are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [semantic versioning](https://semver.org/).

## [0.1.0] - 2026-10-03

First public release.

### Added

- Core checks against any target: DNS resolution, TCP connectivity, TLS
  handshake, HTTP status, certificate expiry, response latency and
  http→https redirect verification.
- Three-state results (`PASS` / `WARN` / `FAIL`) plus `SKIP` when a check is
  not applicable (e.g. TLS on port 80), aggregated into a per-target and
  overall verdict: `HEALTHY` / `DEGRADED` / `UNHEALTHY`.
- CI-friendly exit codes: 0 healthy, 1 degraded, 2 unhealthy, 64 usage
  error, 70 internal error — with `--fail-on error|never` to control how
  warnings gate CI. Usage errors go to stderr.
- `--scheme http|https` override for the HTTP request scheme (default
  inferred from port: 443/8443 -> https).
- `--no-verify-tls` diagnostic switch: skips certificate verification for
  internal/self-signed endpoints, prints a prominent warning, and reports
  the certificate check as SKIP (cert fields are unparseable without
  verification).
- Configurable thresholds: `--cert-warn-days`, `--cert-fail-days`,
  `--latency-warn-ms`, `--latency-fail-ms`, plus `--timeout`, `--port`,
  `--checks` subset selection and multi-target runs.
- `--json` machine-readable envelope (`tool`, `version`, `timestamp`,
  `summary`, `targets`) with per-phase timings (`dns_ms`, `connect_ms`,
  `latency_ms`) and certificate detail (`days_left`, `expires`,
  `valid_from`, `subject`, `issuer`, `sans`). The check list for a default
  run is always the same seven checks in the same order.
- Latency measured as time to first byte: streamed request, response body
  never downloaded.
- `tls` and `certificate` checks share a single verified TLS handshake per
  run; certificate date parsing is locale-safe.
- Failed upstream checks short-circuit dependents to SKIP (dns ->
  tcp/tls/http, tcp -> tls/http): one failure is reported once, not
  re-attempted per layer.
- DNS resolution bounded by `--timeout` (worker thread + deadline).
- Reusable GitHub composite Action (`R3dn/infra-check@v0`) with `version`
  and `scheme` inputs and a `report` output, writing the report to
  `$GITHUB_STEP_SUMMARY`.
- Full test suite: mocked unit tests plus an offline integration suite with
  real local infrastructure (trustme CA, valid/expiring/expired certs,
  local TCP/TLS/HTTP servers, redirect chains and loops) — never hits live
  endpoints.
- CI: ruff, strict mypy, test matrix (ubuntu + windows × Python 3.10–3.13)
  with a 90% coverage floor, wheel smoke test, and PyPI publishing via OIDC
  trusted publishing with GitHub Release creation on tags.

[0.1.0]: https://github.com/R3dn/infra-check/releases/tag/v0.1.0
