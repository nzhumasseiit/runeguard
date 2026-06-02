import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


HIGH_RISK_FILES = (
    ".github/workflows/",
    "dockerfile",
    "docker-compose",
    "vercel",
    "netlify",
    ".env",
    "auth",
    "payment",
    "security",
)

PACKAGE_FILES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Gemfile",
    "go.mod",
    "Cargo.toml",
}

SUSPICIOUS_COMMANDS = re.compile(r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sh|bash)\b|\brm\s+-rf\b|\bscp\b|\bnc\b")


@dataclass
class DiffRiskReport:
    score: str = "low"
    risky_files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def analyze_git_diff(repo: Path, *, diff_text: str | None = None) -> DiffRiskReport:
    if diff_text is None:
        diff_text = _load_git_diff(repo)
    return analyze_diff_text(diff_text)


def analyze_diff_text(diff_text: str) -> DiffRiskReport:
    report = DiffRiskReport()
    current_file = ""
    deleted_test_files = set()

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            current_file = parts[-1][2:] if len(parts) >= 4 and parts[-1].startswith("b/") else ""
            _check_file_path(report, current_file)
            continue

        if line.startswith("deleted file mode") and _looks_like_test(current_file):
            deleted_test_files.add(current_file)

        if not line.startswith("+") or line.startswith("+++"):
            continue

        added = line[1:]
        lower_file = current_file.lower()

        if Path(current_file).name in PACKAGE_FILES:
            _add_warning(report, f"New dependency or package metadata changed in {current_file}")
            _add_file(report, current_file)

        if SUSPICIOUS_COMMANDS.search(added):
            _add_warning(report, f"Suspicious shell command added in {current_file}")
            _add_file(report, current_file)

        if re.search(r"os\.environ|getenv|process\.env", added) and re.search(r"fetch|requests\.|httpx|axios|urllib|curl", added):
            _add_warning(report, f"Environment variable may be sent to network code in {current_file}")
            _add_file(report, current_file)

        if re.search(r"\.env|\.ssh|\.aws", added):
            _add_warning(report, f"Sensitive path access added in {current_file}")
            _add_file(report, current_file)

        if any(token in lower_file for token in ("auth", "payment", "security")):
            _add_warning(report, f"Security-sensitive code changed in {current_file}")
            _add_file(report, current_file)

    for test_file in sorted(deleted_test_files):
        _add_warning(report, f"Test file deleted: {test_file}")
        _add_file(report, test_file)

    _score(report)
    return report


def render_diff_risk(report: DiffRiskReport) -> str:
    lines = [f"Risk score: {report.score}"]
    lines.append("Risky files:")
    lines.extend(f"- {path}" for path in report.risky_files) if report.risky_files else lines.append("- none")
    lines.append("Warnings:")
    lines.extend(f"- {warning}" for warning in report.warnings) if report.warnings else lines.append("- none")
    suggestion = "runeguard scan" if report.score in {"medium", "high"} else "runeguard report .runeguard/audit.jsonl"
    lines.append(f"Suggested next command: {suggestion}")
    return "\n".join(lines)


def _load_git_diff(repo: Path) -> str:
    completed = subprocess.run(
        ["git", "diff", "--no-ext-diff"],
        cwd=repo,
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "git diff failed")
    return completed.stdout


def _check_file_path(report: DiffRiskReport, path: str):
    lower = path.lower()
    if Path(path).name in PACKAGE_FILES or any(token in lower for token in HIGH_RISK_FILES):
        _add_warning(report, f"Risk-sensitive file changed: {path}")
        _add_file(report, path)


def _looks_like_test(path: str) -> bool:
    lower = path.lower()
    return "/test" in lower or lower.startswith("test") or lower.endswith("_test.py") or lower.endswith(".test.ts")


def _add_file(report: DiffRiskReport, path: str):
    if path and path not in report.risky_files:
        report.risky_files.append(path)


def _add_warning(report: DiffRiskReport, warning: str):
    if warning not in report.warnings:
        report.warnings.append(warning)


def _score(report: DiffRiskReport):
    high_markers = ("Suspicious shell", "Environment variable", "Sensitive path", "Test file deleted")
    if any(warning.startswith(high_markers) for warning in report.warnings) or len(report.warnings) >= 4:
        report.score = "high"
    elif report.warnings:
        report.score = "medium"
