import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .redaction import preview_secret, redact_value


SECRET_REGEXES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("OpenAI API key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("Gemini/Google API key", re.compile(r"AIza[0-9A-Za-z_-]{30,}")),
    ("Stripe key", re.compile(r"(?:rk|sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("AWS access key", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    (
        "Private key block",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    ),
)

DANGEROUS_SCRIPT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("curl pipe shell", re.compile(r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sh|bash)\b")),
    ("rm -rf", re.compile(r"\brm\s+-rf\b")),
    ("scp", re.compile(r"\bscp\b")),
    ("netcat", re.compile(r"\bnc\b|\bnetcat\b")),
    ("secret exfiltration", re.compile(r"(?:cat|printenv|env)[^\n|;]*(?:\.env|SECRET|TOKEN|KEY)[^\n|;]*\|\s*(?:curl|wget|nc)\b", re.I)),
)

MCP_CONFIG_NAMES = {
    "mcp.json",
    "mcp.config.json",
    ".mcp.json",
    "claude_desktop_config.json",
}


@dataclass
class ScanFinding:
    severity: str
    kind: str
    path: str
    detail: str
    secret_preview: str | None = None


@dataclass
class ScanReport:
    root: str
    findings: list[ScanFinding] = field(default_factory=list)

    @property
    def high_risk(self) -> bool:
        return any(finding.severity == "high" for finding in self.findings)

    def to_json(self) -> str:
        return json.dumps(redact_value({
            "root": self.root,
            "high_risk": self.high_risk,
            "findings": [finding.__dict__ for finding in self.findings],
        }), indent=2, sort_keys=True)


def scan_path(path: Path) -> ScanReport:
    root = path.expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(str(path))

    report = ScanReport(root=str(root))
    files = [root] if root.is_file() else list(root.rglob("*"))

    for file_path in files:
        if not file_path.is_file() or _should_skip(file_path):
            continue

        rel = _relative(root, file_path)
        lower_name = file_path.name.lower()

        if lower_name == ".env" or lower_name.startswith(".env."):
            report.findings.append(ScanFinding("high", "env-file", rel, ".env-style file present"))

        if _is_firebase_service_account(file_path):
            report.findings.append(ScanFinding("high", "firebase-service-account", rel, "Firebase service account JSON present"))

        if file_path.name in MCP_CONFIG_NAMES or ".cursor/mcp" in str(file_path):
            report.findings.append(ScanFinding("medium", "mcp-config", rel, "MCP configuration file present"))

        text = _read_text(file_path)
        if text is None:
            continue

        for label, pattern in SECRET_REGEXES:
            for match in pattern.finditer(text):
                report.findings.append(
                    ScanFinding("high", "secret", rel, label, preview_secret(match.group(0)))
                )

        if file_path.name == "package.json":
            _scan_package_json(report, rel, text)

        if file_path.suffix in {".sh", ".bash", ".zsh"} or file_path.name in {"install", "postinstall"}:
            _scan_shell_text(report, rel, text)

        if ".github/workflows/" in str(file_path).replace("\\", "/"):
            _scan_workflow(report, rel, text)

        if file_path.name.lower().startswith("netlify") and "toml" in file_path.suffix.lower():
            if re.search(r"\[(?:context\.[^\]]+\.environment|build\.environment)\]|\b[A-Z0-9_]*(?:KEY|TOKEN|SECRET)\b", text):
                report.findings.append(ScanFinding("medium", "env-config", rel, "Netlify file contains env-like config"))

    return report


def render_scan_table(report: ScanReport) -> str:
    if not report.findings:
        return "RuneGuard scan: no serious issues found."

    rows = [("Severity", "Kind", "Path", "Detail")]
    for finding in report.findings:
        detail = finding.detail
        if finding.secret_preview:
            detail = f"{detail}: {finding.secret_preview}"
        rows.append((finding.severity, finding.kind, finding.path, detail))

    widths = [max(len(str(row[index])) for row in rows) for index in range(4)]
    lines = []
    for index, row in enumerate(rows):
        lines.append("  ".join(str(value).ljust(widths[col]) for col, value in enumerate(row)))
        if index == 0:
            lines.append("  ".join("-" * width for width in widths))
    return "\n".join(lines)


def _scan_package_json(report: ScanReport, rel: str, text: str):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        report.findings.append(ScanFinding("medium", "package-json", rel, "package.json is invalid JSON"))
        return

    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return

    for name, command in scripts.items():
        if not isinstance(command, str):
            continue
        for label, pattern in DANGEROUS_SCRIPT_PATTERNS:
            if pattern.search(command):
                report.findings.append(ScanFinding("high", "dangerous-package-script", rel, f"{name}: {label}"))


def _scan_shell_text(report: ScanReport, rel: str, text: str):
    for label, pattern in DANGEROUS_SCRIPT_PATTERNS:
        if pattern.search(text):
            report.findings.append(ScanFinding("high", "suspicious-shell", rel, label))


def _scan_workflow(report: ScanReport, rel: str, text: str):
    lower = text.lower()
    if any(token in lower for token in ("github.event.issue", "github.event.pull_request", "github.event.comment", "github.event.review")):
        if any(token in lower for token in ("openai", "anthropic", "gemini", "claude", "codex", "cursor")):
            report.findings.append(
                ScanFinding("high", "agentic-workflow-input", rel, "GitHub event text appears to flow into AI tooling")
            )


def _is_firebase_service_account(path: Path) -> bool:
    name = path.name.lower()
    if "firebase" in name and "admin" in name and path.suffix == ".json":
        return True
    if name.startswith("service-account") and path.suffix == ".json":
        return True
    return False


def _should_skip(path: Path) -> bool:
    parts = set(path.parts)
    return any(part in parts for part in {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache"})


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > 1024 * 1024:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _relative(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path)
