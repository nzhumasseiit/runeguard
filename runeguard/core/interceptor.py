import os
import platform
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class InterceptorConfig:
    shim_path: Path = Path("runeguard/shim/rg_preload.so")
    socket_path: str = "/tmp/runeguard.sock"
    policy_path: str = "policies/default.yaml"
    fail_closed: bool = True


class RuneGuardInterceptor:
    """Builds process environments for the LD_PRELOAD shim."""

    def __init__(self, config: InterceptorConfig | None = None):
        self.config = config or InterceptorConfig()

    def available(self) -> bool:
        return platform.system() == "Linux" and self.config.shim_path.exists()

    def env(self, base_env: dict[str, str] | None = None) -> dict[str, str]:
        if not self.available():
            raise RuntimeError(
                f"LD_PRELOAD shim is not available at {self.config.shim_path}; "
                "build it on Linux with `runeguard shim build`."
            )

        env = dict(base_env or os.environ)
        existing_preload = env.get("LD_PRELOAD")
        preload_entries = [str(self.config.shim_path)]
        if existing_preload:
            preload_entries.append(existing_preload)

        env["LD_PRELOAD"] = " ".join(preload_entries)
        env["RUNEGUARD_SOCKET"] = self.config.socket_path
        env["RUNEGUARD_POLICY"] = self.config.policy_path
        env["RUNEGUARD_FAIL_CLOSED"] = "1" if self.config.fail_closed else "0"
        return env
