from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .decision import Decision, DecisionType


@dataclass(frozen=True)
class OpaConfig:
    policy: str
    query: str = "data.runeguard.allow"
    command: str = "opa"


class OpaPolicyBackend:
    """Optional Open Policy Agent backend for enterprise policy checks."""

    def __init__(self, config: OpaConfig):
        self.config = config

    def decide(self, tool_name: str, kwargs: dict[str, Any]) -> Decision:
        if not self.config.policy:
            return Decision(DecisionType.BLOCK, "OPA policy path is required")

        if shutil.which(self.config.command) is None:
            return Decision(DecisionType.BLOCK, f"OPA executable not found: {self.config.command}")

        policy_path = Path(self.config.policy)
        if not policy_path.exists():
            return Decision(DecisionType.BLOCK, f"OPA policy file not found: {policy_path}")

        payload = {"tool": tool_name, "input": kwargs}
        argv = [
            self.config.command,
            "eval",
            "--format=json",
            "--stdin-input",
            "--data",
            str(policy_path),
            self.config.query,
        ]
        completed = subprocess.run(
            argv,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            reason = completed.stderr.strip() or completed.stdout.strip() or "OPA evaluation failed"
            return Decision(DecisionType.BLOCK, reason)

        try:
            value = _first_expression_value(json.loads(completed.stdout))
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            return Decision(DecisionType.BLOCK, f"invalid OPA result: {exc}")

        if isinstance(value, dict):
            allow = bool(value.get("allow", False))
            reason = str(value.get("reason") or ("allowed by OPA policy" if allow else "blocked by OPA policy"))
        else:
            allow = bool(value)
            reason = "allowed by OPA policy" if allow else "blocked by OPA policy"

        return Decision(DecisionType.ALLOW if allow else DecisionType.BLOCK, reason)


def _first_expression_value(result: dict) -> Any:
    return result["result"][0]["expressions"][0]["value"]
