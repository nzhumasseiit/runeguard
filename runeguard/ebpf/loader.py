import platform
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from runeguard.policy import Policy


DEFAULT_LOADER_NAME = "runeguard-ebpf-loader"


@dataclass
class EbpfConfig:
    mode: str = "trace"
    policy: str = "policies/default.yaml"
    loader_path: Path | None = None


class EbpfTracer:
    """libbpf/CO-RE syscall visibility and optional kernel enforcement wrapper."""

    def __init__(self, config: EbpfConfig | None = None):
        self.config = config or EbpfConfig()

    def start(self):
        if platform.system() != "Linux":
            raise RuntimeError("RuneGuard eBPF requires Linux")

        loader = self._resolve_loader()
        with tempfile.TemporaryDirectory(prefix="runeguard-ebpf-") as temp_dir:
            blocked_paths_path = self._write_blocked_paths_file(Path(temp_dir))
            argv = [
                str(loader),
                self.config.mode,
                str(blocked_paths_path),
                "--policy",
                self.config.policy,
            ]
            return subprocess.run(argv, check=False).returncode

    def _write_blocked_paths_file(self, directory: Path) -> Path:
        blocked_paths_path = directory / "blocked_paths.txt"
        policy = Policy.from_file(self.config.policy)
        content = "".join(f"{path}\n" for path in policy.protected_paths)
        blocked_paths_path.write_text(content, encoding="utf-8")
        return blocked_paths_path

    def _resolve_loader(self) -> Path:
        if self.config.loader_path:
            loader = self.config.loader_path
            if loader.exists():
                return loader
            raise RuntimeError(f"RuneGuard eBPF loader not found: {loader}")

        packaged = Path(__file__).with_name(DEFAULT_LOADER_NAME)
        if packaged.exists():
            return packaged

        discovered = shutil.which(DEFAULT_LOADER_NAME)
        if discovered:
            return Path(discovered)

        raise RuntimeError(
            "RuneGuard eBPF loader not found. Build it with `make -C ebpf` on Linux "
            "or put runeguard-ebpf-loader on PATH."
        )


def main():
    EbpfTracer().start()


if __name__ == "__main__":
    main()
