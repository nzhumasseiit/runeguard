import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .interceptor import InterceptorConfig, RuneGuardInterceptor


@dataclass(frozen=True)
class SandboxConfig:
    cwd: Path | None = None
    use_preload: bool = False
    interceptor: InterceptorConfig = field(default_factory=InterceptorConfig)


class SandboxRunner:
    """Runs commands with optional RuneGuard process interception."""

    def __init__(self, config: SandboxConfig | None = None):
        self.config = config or SandboxConfig()

    def run(self, argv: list[str]) -> subprocess.CompletedProcess:
        env = None
        if self.config.use_preload:
            env = RuneGuardInterceptor(self.config.interceptor).env()

        return subprocess.run(
            argv,
            cwd=self.config.cwd,
            env=env,
            check=False,
        )
