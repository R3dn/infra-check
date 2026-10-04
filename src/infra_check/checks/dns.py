"""DNS resolution check.

``socket.getaddrinfo`` is a blocking libc call with no timeout parameter.
To honor ``--timeout`` we run resolution in a worker thread and join with
a deadline; on expiry the check fails as a resolution timeout. (The worker
thread is left to finish in the background — the underlying syscall cannot
be interrupted safely, but it no longer blocks the run.)
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any

from infra_check.engine import CheckResult, Status, Thresholds

#: Module-level pool: at most one resolver thread per run, reusing one worker.
_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="infra-check-dns")


def _resolve(target: str) -> list[tuple[Any, ...]]:
    return list(socket.getaddrinfo(target, None))


def check_dns(target: str, thresholds: Thresholds | None = None) -> CheckResult:
    t = thresholds or Thresholds()
    start = time.perf_counter()
    fut: Future[list[tuple[Any, ...]]] = _POOL.submit(_resolve, target)
    try:
        infos = fut.result(timeout=t.timeout)
    except FutureTimeoutError:  # distinct from builtin TimeoutError on 3.10
        return CheckResult(
            name="dns",
            status=Status.FAIL,
            detail=f"resolution timed out after {t.timeout:.0f} s",
        )
    except socket.gaierror as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return CheckResult(
            name="dns",
            status=Status.FAIL,
            detail=f"resolution failed: {exc}",
            data={"dns_ms": round(elapsed_ms, 1)},
        )
    except OSError as exc:
        return CheckResult(
            name="dns",
            status=Status.FAIL,
            detail=f"resolver error: {exc}",
        )
    elapsed_ms = (time.perf_counter() - start) * 1000

    addrs = {info[4][0] for info in infos}
    ordered = sorted(addrs)
    ipv4 = [a for a in ordered if "." in a]
    ipv6 = [a for a in ordered if ":" in a]
    data: dict[str, object] = {"dns_ms": round(elapsed_ms, 1)}
    if ipv4:
        data["ipv4"] = ipv4
    if ipv6:
        data["ipv6"] = ipv6
    return CheckResult(
        name="dns",
        status=Status.PASS,
        detail=", ".join(ordered[:3]) + (" ..." if len(ordered) > 3 else ""),
        data=data,
    )
