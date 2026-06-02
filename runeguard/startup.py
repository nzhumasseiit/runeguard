from pathlib import Path


STARTUP_POLICY = """# RuneGuard startup policy schema v0.1.
version: 1

policy:
  backend: yaml

sandbox:
  backend: docker
  fs_enforcement: none
  network: deny
  readonly_rootfs: true
  readonly_workspace: true
  writable_paths:
    - "src/"
    - "tests/"
    - "tmp/"
    - ".runeguard/"

files:
  deny:
    - ".env"
    - ".env.*"
    - "**/.env"
    - "**/.env.*"
    - "secrets/**"
    - "**/secrets/**"
    - ".git/**"
    - "~/.ssh/**"
    - "~/.aws/**"
    - "~/.config/gcloud/**"
    - "**/service-account*.json"
    - "**/*firebase*admin*.json"
    - "**/vercel*.json"
    - ".npmrc"
    - "**/.npmrc"
    - ".pypirc"
    - "**/.pypirc"
    - ".netrc"
    - "**/.netrc"
    - ".docker/config.json"
    - "**/.docker/config.json"
  allow:
    - "**"

network:
  default: deny
  allow_domains: []

shell:
  deny_patterns:
    - "rm -rf /"
    - "rm -rf ."
    - "sudo"
    - "curl * | sh"
    - "wget * | sh"
    - "nc "
    - "scp "
    - "ssh "
    - "chmod 777"
    - "env"
    - "printenv"
    - "cat .env"
    - "cat .env.*"
"""


STARTUP_README = """# RuneGuard local state

This directory stores local RuneGuard runtime state for this repository.

- `audit.jsonl` is append-only local audit data and should usually stay out of git.
- Run `runeguard scan .` before letting an AI coding agent touch the repo.
- Run `runeguard agent wrap --agent generic -- <command>` to execute through RuneGuard.
"""


SAFE_DEV_DOMAINS = [
    "github.com",
    "api.github.com",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
]


def initialize_startup_repo(
    root: Path,
    *,
    force: bool = False,
    allow_common_dev_network: bool = False,
) -> list[str]:
    root = root.resolve()
    policy_path = root / "runeguard.yaml"
    state_dir = root / ".runeguard"
    audit_path = state_dir / "audit.jsonl"
    readme_path = state_dir / "README.md"
    gitignore_path = root / ".gitignore"
    changes: list[str] = []

    if policy_path.exists() and not force:
        existing = policy_path.read_text(encoding="utf-8")
        if "RuneGuard startup policy" not in existing:
            raise FileExistsError("runeguard.yaml already exists; use --force to overwrite it")

    policy = STARTUP_POLICY
    if allow_common_dev_network:
        domains = "\n".join(f"    - \"{domain}\"" for domain in SAFE_DEV_DOMAINS)
        policy = policy.replace("  allow_domains: []", f"  allow_domains:\n{domains}")

    if force or not policy_path.exists() or policy_path.read_text(encoding="utf-8") != policy:
        policy_path.write_text(policy, encoding="utf-8")
        changes.append("runeguard.yaml")

    state_dir.mkdir(exist_ok=True)
    changes.append(".runeguard/")

    if not audit_path.exists():
        audit_path.touch()
        changes.append(".runeguard/audit.jsonl")

    if force or not readme_path.exists():
        readme_path.write_text(STARTUP_README, encoding="utf-8")
        changes.append(".runeguard/README.md")

    _ensure_gitignore_entry(gitignore_path, ".runeguard/audit.jsonl", changes)
    return changes


def _ensure_gitignore_entry(path: Path, entry: str, changes: list[str]):
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    lines = [line.strip() for line in existing.splitlines()]
    if entry in lines:
        return

    prefix = "" if not existing or existing.endswith("\n") else "\n"
    path.write_text(f"{existing}{prefix}{entry}\n", encoding="utf-8")
    changes.append(".gitignore")
