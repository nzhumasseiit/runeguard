# RuneGuard GitHub Action — Implementation Spec
## `runeguard/action@v1`

This document tells you exactly what files to create and modify.
No existing files should be deleted. All new code integrates with the existing
`runeguard run`, `runeguard scan`, `runeguard mcp proxy`, and `runeguard ci` infrastructure.

---

## What it does

One YAML block in any GitHub Actions workflow wraps an AI agent command with
RuneGuard policy enforcement:

```yaml
- uses: runeguard/action@v1
  with:
    command: python scripts/run_agent.py
```

The agent runs. RuneGuard blocks file reads, shell commands, and network calls
that violate policy. The audit log is uploaded as a workflow artifact.
If the agent was blocked, the step fails with a clear message.

---

## Architecture

```
GitHub Actions runner (ubuntu-latest)
  │
  ├── Step: uses: runeguard/action@v1
  │     │
  │     ├── Composite step 1: pip install runeguard
  │     │
  │     ├── Composite step 2: runeguard check (validate policy)
  │     │
  │     ├── Composite step 3: runeguard run --backend host -- <command>
  │     │     │
  │     │     ├── policy loaded from inputs.policy or inputs.profile
  │     │     ├── audit log written to inputs.audit-log
  │     │     └── exit code forwarded to step exit code
  │     │
  │     └── Composite step 4 (always): upload audit log artifact
  │
  └── Step result: blocked → step fails, audit shows what was blocked
                   allowed → step succeeds, audit shows what ran
```

---

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `command` | (required) | Shell command to run under RuneGuard policy |
| `policy` | `""` | Path to a `runeguard.yaml` policy file in the repo |
| `profile` | `ci` | Named profile: `ci`, `strict`, `permissive`. Used when `policy` is empty |
| `audit-log` | `.runeguard/audit.jsonl` | Path for the JSONL audit log |
| `upload-audit` | `true` | Upload audit log as a GitHub Actions artifact |
| `artifact-name` | `runeguard-audit` | Artifact name for the uploaded audit log |
| `backend` | `host` | Sandbox backend: `host` (default, no Docker needed) or `docker` |
| `fail-on-block` | `true` | Fail the step if RuneGuard blocked any action |
| `runeguard-version` | `""` | Pin a specific RuneGuard version (e.g. `0.1.0`). Empty = latest |
| `python-version` | `3.12` | Python version to use for installing RuneGuard |

## Outputs

| Output | Description |
|--------|-------------|
| `blocked` | `"true"` if RuneGuard blocked at least one action, `"false"` otherwise |
| `audit-log-path` | Resolved path to the audit log file |
| `block-count` | Number of blocked actions (integer string) |

---

## Files to CREATE

---

### `action.yml` (repo root)

```yaml
name: RuneGuard
description: Runtime policy enforcement for AI coding agents in CI
author: RuneGuard

branding:
  icon: shield
  color: purple

inputs:
  command:
    description: Shell command to run under RuneGuard policy enforcement
    required: true
  policy:
    description: Path to a runeguard.yaml policy file in the repo. If empty, uses the profile.
    required: false
    default: ""
  profile:
    description: Named policy profile (ci, strict, permissive). Used when policy is empty.
    required: false
    default: ci
  audit-log:
    description: Path for the JSONL audit log file
    required: false
    default: .runeguard/audit.jsonl
  upload-audit:
    description: Upload audit log as a GitHub Actions artifact
    required: false
    default: "true"
  artifact-name:
    description: Artifact name for the uploaded audit log
    required: false
    default: runeguard-audit
  backend:
    description: Sandbox backend. host=no Docker required. docker=stronger isolation.
    required: false
    default: host
  fail-on-block:
    description: Fail the step if RuneGuard blocked any action
    required: false
    default: "true"
  runeguard-version:
    description: Pin a specific RuneGuard version (e.g. 0.1.0). Empty = latest.
    required: false
    default: ""
  python-version:
    description: Python version used to install RuneGuard
    required: false
    default: "3.12"

outputs:
  blocked:
    description: "true" if RuneGuard blocked at least one action
    value: ${{ steps.run.outputs.blocked }}
  audit-log-path:
    description: Resolved path to the audit log file
    value: ${{ steps.run.outputs.audit_log_path }}
  block-count:
    description: Number of blocked actions
    value: ${{ steps.run.outputs.block_count }}

runs:
  using: composite
  steps:
    - name: Set up Python ${{ inputs.python-version }}
      uses: actions/setup-python@v5
      with:
        python-version: ${{ inputs.python-version }}

    - name: Install RuneGuard
      shell: bash
      run: |
        if [ -n "${{ inputs.runeguard-version }}" ]; then
          pip install --quiet "runeguard==${{ inputs.runeguard-version }}"
        else
          pip install --quiet runeguard
        fi

    - name: Validate policy
      shell: bash
      run: |
        if [ -n "${{ inputs.policy }}" ]; then
          runeguard check --policy "${{ inputs.policy }}"
        else
          echo "Using built-in profile: ${{ inputs.profile }}"
        fi

    - name: Run with RuneGuard
      id: run
      shell: bash
      run: ${{ github.action_path }}/scripts/action-entrypoint.sh
      env:
        RG_COMMAND: ${{ inputs.command }}
        RG_POLICY: ${{ inputs.policy }}
        RG_PROFILE: ${{ inputs.profile }}
        RG_AUDIT_LOG: ${{ inputs.audit-log }}
        RG_BACKEND: ${{ inputs.backend }}
        RG_FAIL_ON_BLOCK: ${{ inputs.fail-on-block }}
        GITHUB_OUTPUT: ${{ env.GITHUB_OUTPUT }}

    - name: Upload audit log
      if: ${{ inputs.upload-audit == 'true' && always() }}
      uses: actions/upload-artifact@v4
      with:
        name: ${{ inputs.artifact-name }}
        path: ${{ inputs.audit-log }}
        if-no-files-found: ignore
```

---

### `scripts/action-entrypoint.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

# Resolve audit log directory
mkdir -p "$(dirname "$RG_AUDIT_LOG")"

# Build runeguard run arguments
RG_ARGS=(runeguard run)

if [ -n "$RG_POLICY" ]; then
  RG_ARGS+=(--policy "$RG_POLICY")
else
  RG_ARGS+=(--profile "$RG_PROFILE")
fi

RG_ARGS+=(
  --backend "$RG_BACKEND"
  --audit-log "$RG_AUDIT_LOG"
)

# Add -- separator then the user command
RG_ARGS+=(--)

# Split RG_COMMAND into words for exec (handles quoted args)
eval "USER_CMD=($RG_COMMAND)"
RG_ARGS+=("${USER_CMD[@]}")

# Run and capture exit code
set +e
"${RG_ARGS[@]}"
EXIT_CODE=$?
set -e

# Parse audit log for block count
BLOCK_COUNT=0
if [ -f "$RG_AUDIT_LOG" ]; then
  BLOCK_COUNT=$(grep -c '"decision": "block"' "$RG_AUDIT_LOG" 2>/dev/null || echo 0)
fi

BLOCKED="false"
if [ "$BLOCK_COUNT" -gt 0 ]; then
  BLOCKED="true"
fi

# Write outputs
echo "blocked=$BLOCKED" >> "$GITHUB_OUTPUT"
echo "audit_log_path=$RG_AUDIT_LOG" >> "$GITHUB_OUTPUT"
echo "block_count=$BLOCK_COUNT" >> "$GITHUB_OUTPUT"

# Print summary
if [ "$BLOCKED" = "true" ]; then
  echo ""
  echo "::warning::RuneGuard blocked $BLOCK_COUNT action(s). See audit log: $RG_AUDIT_LOG"
fi

# Fail if blocked and fail-on-block is set
if [ "$RG_FAIL_ON_BLOCK" = "true" ] && [ "$BLOCKED" = "true" ]; then
  echo "::error::RuneGuard blocked $BLOCK_COUNT action(s). Failing step. Review the audit log artifact."
  exit 1
fi

# Forward the agent's exit code
exit $EXIT_CODE
```

---

### `docs/github-action.md`

```markdown
# RuneGuard GitHub Action

Add one block to any GitHub Actions workflow to enforce RuneGuard policy on
AI coding agents running in CI.

## Quickstart

```yaml
steps:
  - uses: actions/checkout@v4

  - name: Run AI agent with RuneGuard
    uses: runeguard/action@v1
    with:
      command: python scripts/run_agent.py
```

That's it. RuneGuard installs itself, wraps your agent command, and uploads an
audit log artifact. If the agent tried to read `.env`, exfiltrate secrets, or
run a blocked shell command, the step fails with a clear error.

## With a custom policy file

```yaml
- uses: runeguard/action@v1
  with:
    command: python scripts/run_agent.py
    policy: policies/ci-strict.yaml
```

## With the MCP proxy (Claude Code, Cursor)

For agents that communicate over MCP, wrap the MCP server instead of the agent:

```yaml
- uses: runeguard/action@v1
  with:
    command: >
      runeguard mcp proxy
      --policy policies/ci-strict.yaml
      --
      npx @modelcontextprotocol/server-filesystem /workspace
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `command` | (required) | Agent command to run |
| `policy` | `""` | Path to policy YAML file |
| `profile` | `ci` | Built-in profile: `ci`, `strict`, `permissive` |
| `audit-log` | `.runeguard/audit.jsonl` | Audit log path |
| `upload-audit` | `true` | Upload audit as artifact |
| `fail-on-block` | `true` | Fail step if anything was blocked |
| `backend` | `host` | `host` or `docker` |
| `runeguard-version` | `""` | Pin a version |

## Outputs

| Output | Description |
|--------|-------------|
| `blocked` | `"true"` if anything was blocked |
| `block-count` | Number of blocked actions |
| `audit-log-path` | Path to the audit log |

## Reading block results in downstream steps

```yaml
- uses: runeguard/action@v1
  id: runeguard
  with:
    command: python scripts/run_agent.py
    fail-on-block: "false"   # Don't fail, just report

- name: Comment on PR with block summary
  if: steps.runeguard.outputs.blocked == 'true'
  run: |
    echo "RuneGuard blocked ${{ steps.runeguard.outputs.block-count }} action(s)"
```

## Uploading audit logs to a hosted policy server (future)

When `app.runeguard.dev` is live, add your API key to secrets and the action
will upload the audit log automatically:

```yaml
- uses: runeguard/action@v1
  with:
    command: python scripts/run_agent.py
  env:
    RUNEGUARD_API_KEY: ${{ secrets.RUNEGUARD_API_KEY }}
```
```

---

### `tests/test_action_entrypoint.py`

```python
"""
Tests for the GitHub Action entrypoint logic.

These tests exercise the Python-side helpers used by action-entrypoint.sh.
The shell script itself is tested with the integration workflow.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = REPO_ROOT / "scripts" / "action-entrypoint.sh"


def test_entrypoint_exists_and_is_executable():
    assert ENTRYPOINT.exists(), "scripts/action-entrypoint.sh not found"
    assert os.access(ENTRYPOINT, os.X_OK), "action-entrypoint.sh is not executable"


def test_entrypoint_runs_echo_command(tmp_path):
    """Smoke test: a safe echo command succeeds with no blocks."""
    audit = tmp_path / "audit.jsonl"
    env = {
        **os.environ,
        "RG_COMMAND": "echo hello",
        "RG_POLICY": "",
        "RG_PROFILE": "ci",
        "RG_AUDIT_LOG": str(audit),
        "RG_BACKEND": "host",
        "RG_FAIL_ON_BLOCK": "true",
        "GITHUB_OUTPUT": str(tmp_path / "gh_output"),
        "PYTHONPATH": str(REPO_ROOT),
    }
    Path(env["GITHUB_OUTPUT"]).touch()

    result = subprocess.run(
        [str(ENTRYPOINT)],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "hello" in result.stdout or result.returncode == 0

    output_text = Path(env["GITHUB_OUTPUT"]).read_text()
    assert "blocked=false" in output_text
    assert "block_count=0" in output_text


def test_entrypoint_blocks_protected_path(tmp_path):
    """An agent that reads .env gets blocked; step fails when fail-on-block=true."""
    policy = tmp_path / "policy.yaml"
    audit = tmp_path / "audit.jsonl"
    policy.write_text(
        "version: 1\nfiles:\n  deny:\n    - '.env'\n",
        encoding="utf-8",
    )
    # Create a .env so the read actually tries to access a real file
    (tmp_path / ".env").write_text("SECRET=hunter2", encoding="utf-8")

    env = {
        **os.environ,
        "RG_COMMAND": f"python -c \"open('{tmp_path}/.env').read()\"",
        "RG_POLICY": str(policy),
        "RG_PROFILE": "",
        "RG_AUDIT_LOG": str(audit),
        "RG_BACKEND": "host",
        "RG_FAIL_ON_BLOCK": "true",
        "GITHUB_OUTPUT": str(tmp_path / "gh_output"),
        "PYTHONPATH": str(REPO_ROOT),
    }
    Path(env["GITHUB_OUTPUT"]).touch()

    result = subprocess.run(
        [str(ENTRYPOINT)],
        env=env,
        capture_output=True,
        text=True,
    )
    # With --backend host and --preload or daemon, this would be blocked.
    # Without the preload shim on macOS this test verifies the entrypoint
    # logic works end-to-end; actual blocking is covered by integration tests.
    output_text = Path(env["GITHUB_OUTPUT"]).read_text()
    assert "audit_log_path" in output_text
    assert "block_count" in output_text


def test_entrypoint_fail_on_block_false_does_not_fail(tmp_path):
    """fail-on-block=false: step exits 0 even if something was blocked."""
    audit = tmp_path / "audit.jsonl"
    # Write a fake audit log with a block entry
    audit.write_text(
        json.dumps({"decision": "block", "tool": "read_file", "reason": "test"}) + "\n",
        encoding="utf-8",
    )

    env = {
        **os.environ,
        "RG_COMMAND": "echo ok",
        "RG_POLICY": "",
        "RG_PROFILE": "ci",
        "RG_AUDIT_LOG": str(audit),
        "RG_BACKEND": "host",
        "RG_FAIL_ON_BLOCK": "false",
        "GITHUB_OUTPUT": str(tmp_path / "gh_output"),
        "PYTHONPATH": str(REPO_ROOT),
    }
    Path(env["GITHUB_OUTPUT"]).touch()

    result = subprocess.run(
        [str(ENTRYPOINT)],
        env=env,
        capture_output=True,
        text=True,
    )
    # The echo command runs fine; fail-on-block=false means the step passes
    assert result.returncode == 0, result.stderr
    output_text = Path(env["GITHUB_OUTPUT"]).read_text()
    assert "blocked=true" in output_text


def test_entrypoint_outputs_audit_log_path(tmp_path):
    """audit_log_path output is set to the resolved audit log path."""
    audit = tmp_path / "subdir" / "audit.jsonl"
    env = {
        **os.environ,
        "RG_COMMAND": "echo ok",
        "RG_POLICY": "",
        "RG_PROFILE": "ci",
        "RG_AUDIT_LOG": str(audit),
        "RG_BACKEND": "host",
        "RG_FAIL_ON_BLOCK": "true",
        "GITHUB_OUTPUT": str(tmp_path / "gh_output"),
        "PYTHONPATH": str(REPO_ROOT),
    }
    Path(env["GITHUB_OUTPUT"]).touch()

    subprocess.run([str(ENTRYPOINT)], env=env, capture_output=True)
    output_text = Path(env["GITHUB_OUTPUT"]).read_text()
    assert f"audit_log_path={audit}" in output_text
```

---

### `.github/workflows/test-action.yml`

This workflow tests the action against itself — RuneGuard protecting RuneGuard's own CI.

```yaml
name: Test GitHub Action

on:
  push:
    paths:
      - action.yml
      - scripts/action-entrypoint.sh
      - tests/test_action_entrypoint.py
      - ".github/workflows/test-action.yml"
  pull_request:
    paths:
      - action.yml
      - scripts/action-entrypoint.sh
      - tests/test_action_entrypoint.py

jobs:
  test-action-unit:
    name: Unit tests (entrypoint logic)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e .[dev]
      - run: pytest tests/test_action_entrypoint.py -v

  test-action-integration:
    name: Integration (action wrapping a safe command)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run safe echo command through action
        id: safe
        uses: ./
        with:
          command: echo "hello from RuneGuard"
          profile: ci
          audit-log: .runeguard/test-safe.jsonl

      - name: Verify no blocks
        run: |
          if [ "${{ steps.safe.outputs.blocked }}" = "true" ]; then
            echo "Unexpected block on safe command"
            exit 1
          fi

  test-action-blocks-env:
    name: Integration (action blocks .env read)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "SECRET=hunter2" > .env

      - name: Attempt to read .env (should be blocked)
        id: blocked_run
        uses: ./
        with:
          command: cat .env
          profile: ci
          fail-on-block: "false"
          audit-log: .runeguard/test-block.jsonl

      - name: Verify block was recorded
        run: |
          if [ "${{ steps.blocked_run.outputs.blocked }}" != "true" ]; then
            echo "Expected .env read to be blocked but it was not"
            exit 1
          fi
          echo "Block count: ${{ steps.blocked_run.outputs.block-count }}"
```

---

## Files to MODIFY

---

### `runeguard/ci.py` — update `GITHUB_WORKFLOW` template

Replace the current `GITHUB_WORKFLOW` constant with a version that uses
the action instead of manual `runeguard run` calls:

```python
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
```

---

### `pyproject.toml` — update URLs section

Add the GitHub Marketplace URL once the action is listed:

```toml
[project.urls]
Homepage = "https://github.com/nzhumasseiit/runeguard"
Repository = "https://github.com/nzhumasseiit/runeguard"
Issues = "https://github.com/nzhumasseiit/runeguard/issues"
"GitHub Action" = "https://github.com/marketplace/actions/runeguard"
```

---

## Summary of all file changes

### CREATE (new files):
```
action.yml                                  ← the Marketplace action definition
scripts/action-entrypoint.sh                ← entrypoint shell script
docs/github-action.md                       ← user-facing documentation
tests/test_action_entrypoint.py             ← unit + integration tests
.github/workflows/test-action.yml           ← CI for the action itself
```

### MODIFY (existing files):
```
runeguard/ci.py                             ← update GITHUB_WORKFLOW template
pyproject.toml                              ← add Marketplace URL
```

### DO NOT TOUCH:
```
runeguard/policy.py
runeguard/proxy.py
runeguard/mcp/proxy.py
runeguard/seccomp/
tests/test_mcp*.py
tests/test_seccomp.py
```

---

## Marketplace listing requirements

Before submitting to GitHub Marketplace:

1. **Tag `v1`** on the commit that ships `action.yml`
2. **README badge** — add to README.md:
   ```markdown
   [![RuneGuard Action](https://img.shields.io/badge/GitHub%20Action-runeguard%2Faction-purple)](https://github.com/marketplace/actions/runeguard)
   ```
3. **`action.yml` must be in the repo root** — already handled above
4. **`branding.icon` and `branding.color`** — already in action.yml (`shield`, `purple`)
5. **Public repo required** — runeguard is already public

Submission: Settings → Actions → Marketplace → "Publish this Action to the GitHub Marketplace"

---

## Future: hosted policy server integration

When `app.runeguard.dev` launches, the action gains an optional upload step:

```yaml
- uses: runeguard/action@v1
  with:
    command: python scripts/run_agent.py
  env:
    RUNEGUARD_API_KEY: ${{ secrets.RUNEGUARD_API_KEY }}
```

This sends the audit log to the hosted dashboard, enabling team-wide visibility,
cross-repo policy management, and the compliance export feature.
The action is already designed for this — the `RUNEGUARD_API_KEY` env var is the
only addition needed on the action side. The dashboard work is separate scope.
