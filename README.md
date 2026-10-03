# infra-check

**One command, full infrastructure health: DNS → TCP → TLS → HTTP → certificate → latency → redirect.**

[![CI](https://github.com/R3dn/infra-check/actions/workflows/ci.yml/badge.svg)](https://github.com/R3dn/infra-check/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/infra-check.svg)](https://pypi.org/project/infra-check/)
[![PyPI downloads](https://img.shields.io/pypi/dm/infra-check.svg)](https://pypi.org/project/infra-check/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-%3E%3D3.10-green.svg)](pyproject.toml)

## مقدمة

أداة فحص صحة البنية التحتية مفتوحة المصدر، مبنية بلغة بايثون لخدمة مجتمع الحوسبة
السحابية السعودي. أمر واحد يفحص: **DNS** و**اتصال TCP** و**مصافحة TLS** و
**حالة HTTP** و**انتهاء شهادة التشفين** و**زمن الاستجابة** و**إعادة التوجيه
إلى HTTPS** — مع تقرير واضح ونتائج JSON وكود خروج مناسب لخطوط CI/CD.

لماذا هذه الأداة؟ قبل إطلاق أي خدمة أو أثناء تشخيص حادث، تحتاج إلى إجابة سريعة
على سؤال واحد: *هل بنيتي التحتية سليمة؟* — هذه الأداة تجيبك في ثوانٍ بأمر واحد،
وتصلح للاستخدام اليدوي أو ضمن GitHub Actions.

```bash
pip install infra-check
infra-check example.com
```

## What it does

```text
$ infra-check example.com

Infrastructure Health Report — example.com:443
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Check        Result  Detail
 Dns          ✓       23.215.0.138, 23.215.0.136 ...
 Tcp          ✓       connected in 12 ms
 Tls          ✓       TLSv1.3, cipher TLS_AES_256_GCM_SHA384
 Http         ✓       HTTP 200 OK
 Certificate  ✓       expires in 143 days (2027-02-19)
 Latency      ✓       84 ms
 Redirect     -       not applicable on port 443
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Overall: HEALTHY
```

Every check returns `PASS`, `WARN` or `FAIL` with an aggregate verdict:

| Verdict | Meaning | Exit code |
|---|---|---|
| `HEALTHY` | every check passed | 0 |
| `DEGRADED` | warnings present (e.g. cert < 30 days, latency > 300 ms) | 1 |
| `UNHEALTHY` | at least one failure | 2 |

## Install

**From PyPI:**

```bash
pip install infra-check
```

**From source:**

```bash
git clone https://github.com/R3dn/infra-check.git
cd infra-check
pip install .
```

Requires Python >= 3.10.

## Usage

```bash
infra-check example.com                     # full sweep, default port 443
infra-check example.com --port 8080         # custom port (TLS auto-skipped on 80)
infra-check example.com --json              # machine-readable output
infra-check --checks dns,http example.com   # run a subset
infra-check a.com b.com                     # multiple targets
infra-check example.com --fail-on warn       # treat WARN as non-zero exit too
infra-check example.com --timeout 5         # tighter per-check timeout
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
| DNS | resolves | — | no record |
| TCP | port open | — | refused / timeout |
| TLS | verified handshake | — | handshake / validation failure |
| Certificate | ≥ 30 days left | 7–29 days | < 7 days or expired |
| HTTP | 2xx / 3xx | — | 4xx / 5xx |
| Latency | < 300 ms | 300–1000 ms | ≥ 1000 ms |
| Redirect | ends on https | no redirect on http | stays on http |

On port 80 (or any non-TLS context), TLS and certificate checks are skipped with
`SKIP` rather than failing; the redirect check verifies an http→https upgrade.

### JSON output

```bash
infra-check example.com --json
```

```json
{
  "tool": "infra-check",
  "version": "1.0.0",
  "timestamp": "2026-10-03T12:00:00+00:00",
  "summary": { "targets": 1, "overall": "HEALTHY" },
  "targets": [
    {
      "target": "example.com",
      "port": 443,
      "overall": "HEALTHY",
      "checks": [
        { "name": "dns", "status": "PASS", "detail": "93.184.216.34", "data": { "ipv4": ["93.184.216.34"] } },
        { "name": "certificate", "status": "PASS", "detail": "expires in 143 days (2027-02-19)", "data": { "days_left": 143 } }
      ]
    }
  ]
}
```

## Use in CI (GitHub Actions)

This repo ships a reusable composite action:

```yaml
- name: Infrastructure health check
  uses: R3dn/infra-check@v1
  with:
    targets: example.com
    port: 443
    fail-on: error
```

The report is appended to `$GITHUB_STEP_SUMMARY`. See `examples/ci-usage.yml`.

Or run it directly in any workflow:

```yaml
- run: pip install infra-check && infra-check $TARGET --json
```

The exit code (0/1/2) maps cleanly to CI pass/fail — see the table above.

## Architecture

```text
src/infra_check/cli.py          (Click wiring, Rich rendering, --json, exit codes)
    ↓
src/infra_check/registry.py     (check selection & orchestration per target)
    ↓
src/infra_check/checks/         dns.py   socket.getaddrinfo
                               tcp.py   socket.create_connection
                               tls.py   ssl context + getpeercert
                               http.py  httpx GET (latency, status, redirect)
    ↓
src/infra_check/engine.py       (Status/Verdict model, thresholds, aggregation,
                                 JSON envelope — pure logic, no I/O, fully unit-tested)
```

The engine is pure logic with no network I/O; all network code lives in the check
modules. Tests mock every socket/SSL/HTTP layer — the suite never hits live endpoints.

## Development

```bash
git clone https://github.com/R3dn/infra-check.git
cd infra-check
python -m venv .venv && .venv/Scripts/pip install -e . --group dev   # Windows
python -m pytest          # unit tests (mocked, no live endpoints)
ruff check .              # lint
python -m build          # build sdist + wheel
```

## Roadmap

- [ ] `--checks` preset aliases (e.g. `web`, `full`)
- [ ] Chain analysis: full redirect-hop audit with per-hop latency
- [ ] Security headers check (HSTS, CSP)
- [ ] IPv6 connectivity dual-stack reporting
- [ ] SARIF output for GitHub code scanning

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Ground rules: checks must fail loudly with
actionable detail, and no check may guess — a check that cannot run reports SKIP,
never PASS.

## Security

infra-check only connects to the target you name, on the port you choose. It makes
no other outbound calls and stores nothing. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) — © 2026 Redn Alsidrah
