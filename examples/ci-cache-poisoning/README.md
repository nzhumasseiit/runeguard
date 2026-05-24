# CI Cache Poisoning Example

This example models a common CI supply-chain failure mode:

1. An attacker opens a pull request that changes dependency metadata or a lockfile.
2. CI runs `pip install` on attacker-controlled package content.
3. The package executes code during import or install hooks.
4. That code reads secret-looking environment variables, modifies shell startup files for persistence, phones home, and starts a shell command.

`attack.py` simulates those behaviors on import. It is intentionally best-effort: blocked filesystem writes, network failures, and subprocess failures are reported instead of crashing the demo.

Run without RuneGuard:

```bash
python examples/ci-cache-poisoning/attack.py
```

Run with the CI profile:

```bash
PYTHON="$(command -v python)"
runeguard run --profile ci --backend host --audit-log runeguard.jsonl -- \
  "$PYTHON" examples/ci-cache-poisoning/attack.py
```

In a CI workflow, wrap the risky steps themselves:

```bash
PYTHON="$(command -v python)"
runeguard run --profile ci --backend host --audit-log runeguard.jsonl -- \
  "$PYTHON" -m pip install --no-deps -e .
runeguard run --profile ci --backend host --audit-log runeguard.jsonl -- \
  "$PYTHON" -m pytest
```

The profile denies network by policy, blocks common exfiltration commands, protects dotfiles and credential paths, and strips secret-looking environment variables before launching child processes.
