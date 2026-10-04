"""infra-check command-line interface."""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from infra_check import __version__
from infra_check.engine import (
    EXIT_OK,
    Status,
    TargetReport,
    Thresholds,
    Verdict,
    build_envelope,
    exit_code,
)
from infra_check.registry import normalize_selection, run_checks

#: sysexits(3)-style codes for non-health outcomes. Health codes 0/1/2
#: are a documented contract (CONTRIBUTING.md) and remain unchanged.
EXIT_USAGE = 64
EXIT_INTERNAL = 70

_VERDICT_STYLE = {
    Verdict.HEALTHY: "bold green",
    Verdict.DEGRADED: "bold yellow",
    Verdict.UNHEALTHY: "bold red",
}
_STATUS_STYLE = {
    Status.PASS: "green",
    Status.WARN: "yellow",
    Status.FAIL: "red",
    Status.SKIP: "dim",
}
_ASCII_SYMBOLS = {
    Status.PASS: "PASS",
    Status.WARN: "WARN",
    Status.FAIL: "FAIL",
    Status.SKIP: "SKIP",
}

_STDOUT = Console()
_STDERR = Console(stderr=True)


def _status_symbols(console: Console) -> dict[Status, str]:
    if _supports_unicode(console):
        return {status: status.symbol for status in Status}
    return _ASCII_SYMBOLS


def _supports_unicode(console: Console) -> bool:
    """Rich on legacy Windows consoles may target a non-Unicode codepage."""
    encoding = getattr(console.file, "encoding", None) or sys.stdout.encoding or "utf-8"
    try:
        "\u2713\u2717".encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def _render_report(report: TargetReport, console: Console) -> None:
    title = f"Infrastructure Health Report - {report.target}:{report.port}"
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("Check", style="bold")
    table.add_column("Result", justify="center")
    table.add_column("Detail")

    symbols = _status_symbols(console)
    for check in report.checks:
        table.add_row(
            check.name.capitalize(),
            f"[{_STATUS_STYLE[check.status]}]{symbols[check.status]}[/]",
            check.detail,
        )

    verdict = report.verdict
    console.print(
        Panel(
            table,
            title=title,
            subtitle=f"Overall: [{_VERDICT_STYLE[verdict]}]{verdict.value}[/]",
        )
    )


def _render_summary(reports: list[TargetReport], console: Console) -> None:
    if len(reports) < 2:
        return
    counts = {v: sum(1 for r in reports if r.verdict is v) for v in Verdict}
    parts = []
    if counts[Verdict.HEALTHY]:
        parts.append(f"[green]{counts[Verdict.HEALTHY]} healthy[/green]")
    if counts[Verdict.DEGRADED]:
        parts.append(f"[yellow]{counts[Verdict.DEGRADED]} degraded[/yellow]")
    if counts[Verdict.UNHEALTHY]:
        parts.append(f"[red]{counts[Verdict.UNHEALTHY]} unhealthy[/red]")
    console.print("Summary: " + " · ".join(parts))


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("targets", nargs=-1, required=True)
@click.option(
    "--port",
    default=443,
    show_default=True,
    type=click.IntRange(1, 65535),
    help="TCP port to check.",
)
@click.option(
    "--checks",
    default=None,
    help="Comma-separated subset, e.g. dns,tcp,tls,http.",
)
@click.option(
    "--scheme",
    type=click.Choice(["http", "https"]),
    default=None,
    help="Force the HTTP request scheme (default: inferred from port).",
)
@click.option("--timeout", default=None, type=float, help="Per-check timeout in seconds.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.option(
    "--fail-on",
    type=click.Choice(["error", "never"]),
    default="error",
    show_default=True,
    help=(
        "Exit-code policy for warnings: 'error' exits 1 on WARN, "
        "'never' only exits non-zero on FAIL."
    ),
)
@click.option(
    "--no-verify-tls",
    is_flag=True,
    help="Skip TLS certificate verification (diagnostic only; certificate check reports SKIP).",
)
@click.option(
    "--cert-warn-days", default=None, type=int, help="Warn below N days of cert validity."
)
@click.option(
    "--cert-fail-days", default=None, type=int, help="Fail below N days of cert validity."
)
@click.option(
    "--latency-warn-ms", default=None, type=float, help="Warn above N ms latency."
)
@click.option(
    "--latency-fail-ms", default=None, type=float, help="Fail above N ms latency."
)
@click.version_option(__version__, prog_name="infra-check")
def check_command(
    targets: tuple[str, ...],
    port: int,
    checks: str | None,
    scheme: str | None,
    timeout: float | None,
    as_json: bool,
    fail_on: str,
    no_verify_tls: bool,
    cert_warn_days: int | None,
    cert_fail_days: int | None,
    latency_warn_ms: float | None,
    latency_fail_ms: float | None,
) -> None:
    """Check infrastructure health for one or more TARGETS (domains or IPs).

    Examples:

    \b
        infra-check example.com
        infra-check example.com --port 443 --json
        infra-check --checks dns,http example.com
        infra-check a.com b.com --fail-on never
    """
    try:
        selected = normalize_selection(checks.split(",") if checks else None)
    except ValueError as exc:
        _STDERR.print(f"[red]error:[/red] {exc}")
        sys.exit(EXIT_USAGE)

    thresholds = Thresholds.merge(
        Thresholds(),
        cert_warn_days=cert_warn_days,
        cert_fail_days=cert_fail_days,
        latency_warn_ms=latency_warn_ms,
        latency_fail_ms=latency_fail_ms,
        timeout=timeout,
        verify_tls=False if no_verify_tls else None,
    )

    if no_verify_tls:
        _STDERR.print(
            "[yellow]warning:[/yellow] TLS certificate verification is DISABLED (--no-verify-tls); "
            "the connection is still encrypted but the server identity is unverified."
        )

    try:
        reports = [
            run_checks(target, port, thresholds, selected, scheme=scheme) for target in targets
        ]
    except Exception as exc:  # noqa: BLE001 - surface internal errors distinctly
        _STDERR.print(f"[red]internal error:[/red] {type(exc).__name__}: {exc}")
        sys.exit(EXIT_INTERNAL)

    if as_json:
        click.echo(json.dumps(build_envelope(reports), indent=2))
    else:
        for report in reports:
            _render_report(report, _STDOUT)
        _render_summary(reports, _STDOUT)

    code = exit_code(reports, fail_on)
    if code == EXIT_OK:
        sys.exit(0)
    sys.exit(code)


def main() -> None:
    """Console entry point: usage errors exit 64, distinct from health codes."""
    try:
        check_command(standalone_mode=False)
    except click.exceptions.UsageError as exc:
        exc.show()
        sys.exit(EXIT_USAGE)
    except click.exceptions.Exit as exc:
        sys.exit(exc.exit_code)


if __name__ == "__main__":
    main()
