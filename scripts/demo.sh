#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "== RuneGuard poisoned README demo =="
python -m runeguard.cli check --policy policies/default.yaml
python -m runeguard.cli demo --policy policies/default.yaml --audit-log .runeguard/demo.jsonl
echo
echo "== Audit summary =="
python -m runeguard.cli audit summary .runeguard/demo.jsonl
