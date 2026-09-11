#!/usr/bin/env python3
"""Run one local preflight command with a hard wall-clock deadline.

This helper is intentionally small and uses only Python's standard library.
It writes combined stdout/stderr to the caller-selected log, starts the child
in its own process group, and attempts process-group termination on timeout.
Only the direct child is waited on; descendant cleanup is best effort.
"""

from __future__ import annotations

import os
import math
import signal
import subprocess
import sys


TIMEOUT_EXIT = 124
CLEANUP_EXIT = 125
JOIN_TIMEOUT_SECONDS = 1.0


def fail(message: str, status: int = 2) -> int:
    print(f"m7-run-bounded: {message}", file=sys.stderr)
    return status


def signal_group(process: subprocess.Popen, signal_number: int, label: str, log) -> bool:
    try:
        os.killpg(process.pid, signal_number)
    except ProcessLookupError:
        log.write(f"m7-run-bounded: {label} process group no longer exists\n".encode())
    except OSError as error:
        log.write(f"m7-run-bounded: {label} process group failed: {error}\n".encode())
        log.flush()
        return False
    else:
        log.write(f"m7-run-bounded: sent {label} to the child process group\n".encode())
    log.flush()
    return True


def terminate_and_reap(process: subprocess.Popen, log) -> bool:
    log.write(b"m7-run-bounded: timeout; sending SIGTERM to the child process group\n")
    log.flush()
    signal_group(process, signal.SIGTERM, "SIGTERM", log)
    direct_child_reaped = False
    try:
        process.wait(timeout=JOIN_TIMEOUT_SECONDS)
        direct_child_reaped = True
    except subprocess.TimeoutExpired:
        pass

    # Attempt SIGKILL even when the leader exited after SIGTERM.  A process
    # group may still contain a descendant, while a missing group is harmless.
    kill_attempt_ok = signal_group(process, signal.SIGKILL, "SIGKILL", log)
    if not kill_attempt_ok:
        log.write(b"m7-run-bounded: cleanup failure; SIGKILL could not be sent to the child process group\n")
        log.flush()
        return False
    if not direct_child_reaped:
        try:
            process.wait(timeout=JOIN_TIMEOUT_SECONDS)
            direct_child_reaped = True
        except subprocess.TimeoutExpired:
            log.write(
                b"m7-run-bounded: cleanup failure; direct child did not exit after bounded SIGKILL wait; "
                b"descendant cleanup is unverified\n"
            )
            log.flush()
            return False

    log.write(
        b"m7-run-bounded: direct child reaped; descendant cleanup remains best effort and is unverified\n"
    )
    log.flush()
    return True


def main(argv) -> int:
    if len(argv) < 4:
        return fail("usage: m7-run-bounded.py TIMEOUT_SECONDS LOG_PATH COMMAND [ARG...]")

    try:
        timeout_seconds = float(argv[1])
    except ValueError:
        return fail(f"invalid timeout: {argv[1]!r}")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        return fail("timeout must be a finite value greater than zero")

    log_path = argv[2]
    command = argv[3:]
    try:
        log = open(log_path, "wb")
    except OSError as error:
        return fail(f"cannot open log {log_path!r}: {error}")

    with log:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as error:
            log.write(f"m7-run-bounded: cannot start command: {error}\n".encode())
            return 127

        try:
            status = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            if not terminate_and_reap(process, log):
                return CLEANUP_EXIT
            return TIMEOUT_EXIT

    return status


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
