# Contributing to infra-check

Thanks for helping improve infra-check — built for the Saudi cloud community and
anyone who runs infrastructure that needs to stay healthy.

## Ground rules

1. **Checks must fail loudly with actionable detail.** A FAIL message should tell
   the operator what broke and where to look. Never swallow an exception into a
   vague "something went wrong".
2. **A check that cannot run reports SKIP — never PASS.** No guessing. If TLS is
   not applicable on a port, that's SKIP. If we can't inspect the certificate,
   that's SKIP (with `--no-verify-tls`) or FAIL (when verification is on), never
   an assumed OK.
3. **Tests never hit live endpoints.** Unit tests mock every network layer; the
   integration suite runs against in-process local servers
   (`tests/local_servers.py`: trustme CA, ephemeral ports, scripted responses).
   A test that requires real internet access is a bug. Live verification is
   manual, done before releases against well-known targets.
4. **Exit codes are a contract.** 0 = healthy, 1 = degraded, 2 = unhealthy,
   64 = usage error, 70 = internal error. CI pipelines depend on them;
   changes require a breaking-version bump (minor bump while pre-1.0,
   major bump from 1.0 onward).
5. **The JSON envelope is a contract.** Keys are consumed by CI and other tools.
   The check list for a default run is always the same seven checks in the same
   order. Add keys; don't rename or remove them without a breaking-version bump
   (minor bump while pre-1.0, major bump from 1.0 onward).

## Development setup

```bash
git clone https://github.com/R3dn/infra-check.git
cd infra-check
python -m venv .venv
.venv/Scripts/pip install -e . pytest pytest-cov trustme mypy ruff build   # Windows
# source .venv/bin/activate && pip install -e . pytest pytest-cov trustme mypy ruff build  # Linux/macOS
```

## Before you submit a PR

```bash
ruff check .            # must pass
python -m mypy          # strict; must pass
python -m pytest        # must pass; add tests for any new behavior
python -m pytest --cov=infra_check   # coverage should stay >= 90%
python -m build         # package must build cleanly
```

CI runs the same on ubuntu + windows × Python 3.10–3.13, plus a coverage floor,
a strict mypy job and a wheel smoke test.

## Adding a new check

1. Implement it in `src/infra_check/checks/<name>.py`, returning a `CheckResult`
   (or a small list of them, like `http`).
2. Register the name in `ALL_CHECKS` in `src/infra_check/registry.py`
   (order = report order).
3. Wire it into `run_checks`, honoring the user's `--checks` selection and the
   upstream short-circuit rules (dns -> tcp/tls/http; tcp -> tls/http).
4. Add mocked unit tests in `tests/test_checks.py` **and** a real local-server
   test in `tests/test_integration.py` covering PASS/WARN/FAIL paths.
5. Update the README check table and the JSON envelope docs if the shape changed.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`) — keeps the
CHANGELOG easy to generate.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md) — do not open a public issue for vulnerabilities.
