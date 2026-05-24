# Changelog

## v0.1.0

Initial early alpha release of RuneGuard.

### Added

- Working poisoned README demo.
- YAML policy engine for file, shell, and network decisions.
- Docker sandbox runner as the practical default backend.
- Host policy wrapper for local development and policy checks.
- Audit JSONL logs and `runeguard report` command.
- Process correlation metadata for audit records.
- Landlock backend, Linux-only and experimental, dependent on kernel support.
- libbpf/CO-RE eBPF source and loader interface, Linux-only and experimental, requiring local build and host privileges.
- OPA/Rego backend option.
- GitHub Actions CI and PyPI publish workflow.
