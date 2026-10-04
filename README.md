# infra-check

**One command, full infrastructure health: DNS → TCP → TLS → HTTP → certificate → latency → redirect.**

[![CI](https://github.com/R3dn/infra-check/actions/workflows/ci.yml/badge.svg)](https://github.com/R3dn/infra-check/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/infra-health-check.svg)](https://pypi.org/project/infra-health-check/)
[![PyPI downloads](https://img.shields.io/pypi/dm/infra-health-check.svg)](https://pypi.org/project/infra-health-check/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-%3E%3D3.10-green.svg)](pyproject.toml)

## Introduction | مقدمة

**English:**

infra-check is an open-source infrastructure health checker. One command
verifies the full chain — DNS, TCP, TLS, HTTP, certificate expiry, latency
and https redirects — with a clear report, JSON output and CI-friendly exit
codes. Use it before a launch, during an incident, or as a gate in your
CI/CD pipeline.

**العربية:**

أداة فحص صحة البنية التحتية مفتوحة المصدر، مبنية بلغة بايثون لخدمة مجتمع
الحوسبة السحابية السعودي. أمر واحد يفحص: **DNS** و**اتصال TCP** و**مصافحة
TLS** وحالة HTTP وانتهاء الشهادة وزمن الاستجابة وإعادة التوجيه إلى HTTPS —
مع تقرير واضح ونتائج JSON وكود خروج مناسب لخطوط CI/CD. لماذا هذه الأداة؟
قبل إطلاق أي خدمة أو أثناء تشخيص حادث، تحتاج إلى إجابة سريعة على سؤال واحد:
*هل بنيتي التحتية سليمة؟* — هذه الأداة تجيبك في ثوانٍ، وتصلح للاستخدام
اليدوي أو ضمن GitHub Actions.

```bash
pip install infra-health-check
infra-check example.com
```

## What it does

```text
$ infra-check example.com

+----------- Infrastructure Health Report - example.com:443 -----------+
|   Check          Result    Detail                                      |
|   Dns             PASS     104.20.23.154, 172.66.147.243,              |
|                            2606:4700:10::6814:179a ...                 |
|   Tcp             PASS     connected in 74 ms                          |
|   Tls             PASS     TLSv1.3, cipher TLS_AES_256_GCM_SHA384      |
|   Certificate     PASS     expires in 83 days (2026-12-25)             |
|   Http            PASS     HTTP 200 OK                                 |
|   Latency         PASS     240 ms                                       |
|   Redirect        SKIP     not applicable: initial request is https    |
+--------------------------- Overall: HEALTHY ---------------------------+
```

Every check returns `PASS`, `WARN` or `FAIL` (`SKIP` when not applicable) with an
aggregate verdict:

| Verdict | Meaning | Exit code |
|---|---|---|
| `HEALTHY` | every check passed | 0 |
| `DEGRADED` | warnings present (e.g. cert < 30 days, latency > 300 ms) | 1 |
| `UNHEALTHY` | at least one failure | 2 |

Usage errors (bad flags, invalid port) exit **64**; internal tool errors exit **70** —
so CI can always tell "my pipeline is misconfigured" from "my site is down".

## Install

**From PyPI:**

```bash
pip install infra-health-check
```

**From source:**

```bash
git clone https://github.com/R3dn/infra-check.git
cd infra-check
pip install .
```

Requires Python >= 3.10. Works on Linux, macOS and Windows.

## Usage

```bash
infra-check example.com                     # full sweep, default port 443
infra-check example.com --port 8080         # custom port (scheme inferred: 443/8443 -> https)
infra-check example.com --port 8443 --scheme https   # force the request scheme
infra-check example.com --json              # machine-readable output
infra-check --checks dns,http example.com   # run a subset
infra-check a.com b.com                     # multiple targets
infra-check example.com --fail-on never     # only FAIL exits non-zero (warnings exit 0)
infra-check example.com --timeout 5         # tighter per-check timeout
infra-check internal.local --no-verify-tls  # diagnostic: skip cert verification (prints a warning)
```

### Thresholds

Warnings and failures are configurable:

| Flag | Default | Meaning |
|---|---|---|
| `--cert-warn-days` | 30 | WARN when certificate expires in fewer days |
| `--cert-fail-days` | 7 | FAIL when certificate expires in fewer days |
| `--latency-warn-ms` | 300 | WARN above this latency |
| `--latency-fail-ms` | 1000 | FAIL above this latency |

### Checks

| Check | PASS | WARN | FAIL |
|---|---|---|---|
| DNS | resolves (bounded by `--timeout`) | — | no record / timeout |
| TCP | port open | — | refused / timeout |
| TLS | verified handshake | — | handshake / validation failure |
| Certificate | ≥ 30 days left | 7–29 days | < 7 days or expired |
| HTTP | 2xx / 3xx | — | 4xx / 5xx |
| Latency | < 300 ms (time to first byte) | 300–1000 ms | ≥ 1000 ms |
| Redirect | ends on https | no redirect on http | redirected but stays on http |

On port 80 (or any non-TLS context), TLS and certificate checks are skipped with
`SKIP` rather than failing; the redirect check verifies an http→https upgrade.
When an upstream check fails, downstream checks are **skipped** — one failure is
reported once, not mis-attributed by every layer below it.

`--no-verify-tls` is a diagnostic switch for internal/self-signed endpoints: the
TLS check passes and the certificate check reports `SKIP` (certificate fields
cannot be parsed without verification). It always prints a visible warning.

### Latency semantics

The latency check measures **time to first byte**: DNS + TCP + TLS (if any) +
request up to the arrival of response headers. The response body is never
downloaded. Per-phase timings are in the JSON `data` fields (`dns_ms`,
`connect_ms`, `latency_ms`).

### JSON output

```bash
infra-check example.com --json
```

```json
{
  "tool": "infra-check",
  "version": "0.1.0",
  "timestamp": "2026-10-03T18:05:58+00:00",
  "summary": { "targets": 1, "overall": "HEALTHY" },
  "targets": [
    {
      "target": "example.com",
      "port": 443,
      "overall": "HEALTHY",
      "checks": [
        {
          "name": "dns", "status": "PASS",
          "detail": "104.20.23.154, ...",
          "data": { "dns_ms": 4.8, "ipv4": ["104.20.23.154"], "ipv6": ["..."] }
        },
        {
          "name": "certificate", "status": "PASS",
          "detail": "expires in 83 days (2026-12-25)",
          "data": {
            "days_left": 83, "expires": "2026-12-25", "valid_from": "2026-09-26",
            "subject": "example.com", "issuer": "SSL Corporation",
            "sans": ["example.com", "*.example.com"]
          }
        }
      ]
    }
  ]
}
```

The schema is a contract: a default run always reports the same seven checks, in
the same order, each with `name`/`status`/`detail`/`data`. Keys are only added,
never renamed or removed, without a major version bump.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | HEALTHY |
| 1 | DEGRADED (0 with `--fail-on never`) |
| 2 | UNHEALTHY |
| 64 | usage error (bad flags, invalid input) |
| 70 | internal tool error |

## Use in CI (GitHub Actions)

This repo ships a reusable composite action:

```yaml
- name: Infrastructure health check
  uses: R3dn/infra-check@v0
  with:
    targets: example.com
    port: 443
    fail-on: error
```

The report is appended to `$GITHUB_STEP_SUMMARY` and the JSON report path is
exposed as the `report` output. See `examples/ci-usage.yml`.

Or run it directly in any workflow:

```yaml
- run: pip install infra-health-check && infra-check $TARGET --json
```

## Architecture

```text
src/infra_check/cli.py          (Click wiring, Rich rendering, --json, exit codes)
    ↓
src/infra_check/registry.py     (check selection & orchestration per target,
                                  DNS/TCP failure short-circuiting)
    ↓
src/infra_check/checks/         dns.py   socket.getaddrinfo (bounded by --timeout)
                               tcp.py   socket.create_connection
                               tls.py   verified ssl handshake, shared by tls+cert checks
                               http.py  httpx streaming GET (TTFB, no body download)
    ↓
src/infra_check/engine.py       (Status/Verdict model, thresholds, aggregation,
                                  JSON envelope — pure logic, no I/O, fully unit-tested)
```

The engine is pure logic with no network I/O; all network code lives in the check
modules. Unit tests mock every socket/SSL/HTTP layer; a separate integration
suite runs real handshakes and HTTP exchanges against in-process local servers
(trustme CA, ephemeral ports) — the suite never hits live endpoints and works
offline.

## Security notes

infra-check only connects to the target you name, on the port you choose. It
makes no other outbound calls and stores nothing. TLS verification is **on by
default**; `--no-verify-tls` is the only switch and prints a warning when used.
The CLI performs **no destination filtering** (localhost and private ranges are
valid targets for administrators) — do not expose it to untrusted input; any
SSRF protection belongs in the wrapping service. See [SECURITY.md](SECURITY.md).

## Development

```bash
git clone https://github.com/R3dn/infra-check.git
cd infra-check
python -m venv .venv && .venv/Scripts/pip install -e . pytest pytest-cov trustme mypy ruff build   # Windows
# source .venv/bin/activate && pip install -e . pytest pytest-cov trustme mypy ruff build         # Linux/macOS
python -m pytest          # unit + integration tests (offline, no live endpoints)
ruff check .              # lint
python -m mypy            # strict type check
python -m build           # build sdist + wheel
```

## Roadmap

- [x] `--scheme` override and correct 8443 handling
- [ ] `--checks` preset aliases (e.g. `web`, `full`)
- [ ] Chain analysis: full redirect-hop audit with per-hop latency
- [ ] Security headers check (HSTS, CSP)
- [ ] IPv6 connectivity dual-stack reporting

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Ground rules: checks must fail loudly with
actionable detail, and no check may guess — a check that cannot run reports SKIP,
never PASS.

## License

[MIT](LICENSE) — © 2026 Redn Alsidrah
