from pathlib import Path

from runeguard.diff_risk import analyze_diff_text
from runeguard.mcp.inspect import inspect_mcp_config
from runeguard.scan import scan_path


ROOT = Path(__file__).resolve().parents[1]


def test_examples_are_executable_fixtures():
    startup_report = scan_path(ROOT / "examples" / "startup_repo")
    workflow_report = scan_path(ROOT / "examples" / "agentic_github_action")
    mcp_servers = inspect_mcp_config(ROOT / "examples" / "mcp_config" / "mcp.json")
    diff_report = analyze_diff_text((ROOT / "examples" / "diff_risk" / "sample.diff").read_text(encoding="utf-8"))

    assert startup_report.high_risk
    assert workflow_report.high_risk
    assert mcp_servers[0].name == "local-files"
    assert diff_report.score == "high"
