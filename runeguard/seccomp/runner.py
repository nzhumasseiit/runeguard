"""Subprocess runner that applies seccomp before execing the agent."""

from __future__ import annotations

import os
import platform
import sys

from ..policy import Policy
from .filter import apply_seccomp_from_policy


def run_with_seccomp(
    argv: list[str],
    policy: Policy,
    *,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> int:
    if platform.system() != "Linux":
        raise RuntimeError("seccomp enforcement is Linux-only")

    child_pid = os.fork()

    if child_pid == 0:
        try:
            if cwd:
                os.chdir(cwd)
            apply_seccomp_from_policy(policy)
        except Exception as exc:
            print(f"[RuneGuard] seccomp apply failed: {exc}", file=sys.stderr)
            os._exit(1)

        try:
            if env is not None:
                os.execvpe(argv[0], argv, env)
            else:
                os.execvp(argv[0], argv)
        except Exception as exc:
            print(f"[RuneGuard] exec failed: {exc}", file=sys.stderr)
            os._exit(1)

    _, status = os.waitpid(child_pid, 0)
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        print(f"[RuneGuard] child killed by signal {sig}", file=sys.stderr)
        return 128 + sig
    return 1
