# Policy Schema v0.1

RuneGuard policy schema version `1` is frozen for v0.1. Do not change this
format casually; users need stable policy files.

```yaml
version: 1

sandbox:
  backend: docker
  network: deny
  readonly_workspace: true
  writable_paths:
    - tmp/
    - .cache/

files:
  deny:
    - ".env"
    - ".env.*"
    - "**/secrets/**"
    - "~/.ssh/**"
    - "~/.aws/**"
    - "~/.config/gcloud/**"
  allow:
    - "src/**"
    - "tests/**"
    - "README.md"

network:
  default: deny
  allow_domains:
    - "api.openai.com"
    - "github.com"

shell:
  deny_patterns:
    - "rm -rf"
    - "curl * | sh"
    - "nc "
    - "scp "
    - "ssh "
```

## Fields

- `version`: must be `1`.
- `sandbox.backend`: `docker` or `host`. Use `docker` for real sandboxing.
- `sandbox.network`: use `deny` for network disabled by default.
- `sandbox.readonly_workspace`: keep `true` unless using the explicit unsafe
  CLI compatibility flag.
- `sandbox.writable_paths`: workspace-relative paths mounted writable.
- `files.deny`: paths or globs removed from the Docker workspace view and
  blocked by policy-mode checks.
- `files.allow`: optional allowlist for files copied into the Docker workspace
  view. If omitted, all non-denied files are included.
- `network.default`: `deny` by default.
- `network.allow_domains`: domains allowed by policy/proxy network checks.
- `shell.deny_patterns`: shell command patterns blocked before execution.

## Backward Compatibility

RuneGuard still loads older flat policy files internally, but new projects
created with `runeguard init` use this schema.
