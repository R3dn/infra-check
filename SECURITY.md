# Security Policy

## Design

infra-check deliberately keeps a minimal attack surface:

- It connects **only to the target you name, on the port you choose**. No
  telemetry, no update pings, no third-party calls.
- It stores **nothing** on disk — no cache, no config, no credentials.
- It runs with **no privileges** and needs none.

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
