import subprocess
from pathlib import Path

from .base import GuardedAgent


class GuardedLangChainTools(GuardedAgent):
    """Small adapter for LangChain-style callable tools."""

    def read_file(self, path: str) -> str:
        return self.guarded_call(
            "read_file",
            lambda path: Path(path).read_text(encoding="utf-8"),
            path=path,
        )

    def write_file(self, path: str, content: str):
        return self.guarded_call(
            "write_file",
            lambda path, content: Path(path).write_text(content, encoding="utf-8"),
            path=path,
            content=content,
        )

    def shell(self, command: str) -> subprocess.CompletedProcess:
        return self.guarded_call(
            "shell",
            lambda command: subprocess.run(
                command,
                shell=True,
                check=False,
                capture_output=True,
                text=True,
            ),
            command=command,
        )
