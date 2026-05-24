import os
import subprocess
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from .interceptor import InterceptorConfig, RuneGuardInterceptor
from ..policy import Policy


@dataclass(frozen=True)
class SandboxConfig:
    cwd: Path | None = None
    use_preload: bool = False
    interceptor: InterceptorConfig = field(default_factory=InterceptorConfig)


class SandboxRunner:
    """Runs commands with optional RuneGuard process interception."""

    def __init__(self, config: SandboxConfig | None = None, policy: Policy | None = None):
        self.config = config or SandboxConfig()
        self.policy = policy or Policy({})

    def run(self, argv: list[str]) -> subprocess.CompletedProcess:
        env = None
        if self.config.use_preload:
            env = RuneGuardInterceptor(self.config.interceptor).env()

        env = filter_child_env(self.policy, env)
        return subprocess.run(
            argv,
            cwd=self.config.cwd,
            env=env,
            check=False,
        )


def filter_child_env(
    policy: Policy,
    env: dict[str, str] | None = None,
) -> dict[str, str]:
    filtered = dict(os.environ if env is None else env)

    if policy.allowed_env_vars:
        allowed = set(policy.allowed_env_vars)
        filtered = {
            name: value
            for name, value in filtered.items()
            if name in allowed
        }

    for name in list(filtered):
        if any(fnmatch(name, pattern) for pattern in policy.env_var_strip_pattern):
            filtered.pop(name, None)

    return filtered
