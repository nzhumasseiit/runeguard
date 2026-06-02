from pathlib import Path


GITHUB_WORKFLOW = """name: RuneGuard

on:
  pull_request:
  push:
    branches: [main]

jobs:
  runeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AI agent with RuneGuard
        uses: runeguard/action@v1
        with:
          command: YOUR_AGENT_COMMAND_HERE
          profile: ci
"""


def initialize_github_ci(root: Path, *, force: bool = False) -> Path:
    workflow_path = root / ".github" / "workflows" / "runeguard.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    if workflow_path.exists() and not force:
        raise FileExistsError(".github/workflows/runeguard.yml already exists; use --force to overwrite it")
    workflow_path.write_text(GITHUB_WORKFLOW, encoding="utf-8")
    return workflow_path
