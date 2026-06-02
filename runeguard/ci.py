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
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install RuneGuard
        run: |
          if [ -f pyproject.toml ]; then
            python -m pip install -e .
          else
            python -m pip install runeguard
          fi
      - name: Check RuneGuard policy
        run: runeguard check
      - name: Scan repository
        run: runeguard scan --json .
      - name: Upload RuneGuard audit log
        if: always() && hashFiles('.runeguard/audit.jsonl') != ''
        uses: actions/upload-artifact@v4
        with:
          name: runeguard-audit
          path: .runeguard/audit.jsonl
"""


def initialize_github_ci(root: Path, *, force: bool = False) -> Path:
    workflow_path = root / ".github" / "workflows" / "runeguard.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    if workflow_path.exists() and not force:
        raise FileExistsError(".github/workflows/runeguard.yml already exists; use --force to overwrite it")
    workflow_path.write_text(GITHUB_WORKFLOW, encoding="utf-8")
    return workflow_path
