# Security Policy

## Design

infra-check deliberately keeps a minimal attack surface:

- It connects **only to the target you name, on the port you choose**. No
  telemetry, no update pings, no third-party calls.
- It stores **nothing** on disk — no cache, no config, no credentials.
- It runs with **no privileges** and needs none.
- **TLS verification is on by default** and there is exactly one way to turn it
  off: the `--no-verify-tls` diagnostic flag, which prints a prominent warning
  and reports the certificate check as SKIP. There is no config file, env var
  or hidden switch that silently disables verification.
- The HTTP check never downloads response bodies (streamed request closed at
  headers) and follows redirects to their https destination only.

## Threat model

The CLI performs **no destination filtering**: localhost, RFC1918 and
link-local addresses are legitimate targets for administrators testing internal
infrastructure. This is the same model as `curl` or `nmap` — the person running
the command chooses the target. Consequences:

- Do not wrap the CLI in an internet-facing service without adding SSRF
  protections (target allowlists, private-range blocking, redirect
  re-validation) **in the wrapper**. The CLI itself will happily connect to
  `127.0.0.1`, `169.254.169.254` or any private range it is pointed at, and
  follows redirects.
- In CI, pass explicit, trusted target names.

## Supported versions

| Version | Supported |
|---|---|
| 1.x | yes |

## Reporting a vulnerability

Found something? Please report it privately:

1. Use GitHub's **"Report a vulnerability"** option in the
   [Security](https://github.com/R3dn/infra-check/security) tab, or
2. Open an advisory via security advisories on the repository.

Please do **not** open a public issue for anything security-sensitive.
Aim to respond within 72 hours.

## Scope

- The CLI itself and the GitHub Action in this repo.
- Out of scope: vulnerabilities in the targets you point the tool at, or in
  Python/your runtime.
