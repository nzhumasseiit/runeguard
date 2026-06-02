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
