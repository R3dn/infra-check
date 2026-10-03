# Changelog

All notable changes to infra-check are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [semantic versioning](https://semver.org/).

## [1.0.0] - 2026-10-03

### Added

- Core checks against any target: DNS resolution, TCP connectivity, TLS
  handshake, HTTP status, certificate expiry, response latency and
  http→https redirect verification.
- Three-state results (`PASS` / `WARN` / `FAIL`) plus `SKIP` when a check is
  not applicable (e.g. TLS on port 80), aggregated into a per-target and
  overall verdict: `HEALTHY` / `DEGRADED` / `UNHEALTHY`.
- CI-friendly exit codes: 0 healthy, 1 degraded, 2 unhealthy, with
  `--fail-on error|warn|never` to control how warnings gate CI.
- Configurable thresholds: `--cert-warn-days`, `--cert-fail-days`,
  `--latency-warn-ms`, `--latency-fail-ms`, plus `--timeout`, `--port`,
  `--checks` subset selection and multi-target runs.
- `--json` machine-readable envelope (`tool`, `version`, `timestamp`,
  `summary`, `targets`) for pipelines and dashboards.
- Reusable GitHub composite Action (`R3dn/infra-check@v1`) writing a report
  to `$GITHUB_STEP_SUMMARY`.
- Full test suite (mocked — never hits live endpoints) with a 90% coverage
  floor, ruff lint, CI matrix (ubuntu + windows × Python 3.10–3.13) and
  PyPI publishing via OIDC trusted publishing.

[1.0.0]: https://github.com/R3dn/infra-check/releases/tag/v1.0.0
