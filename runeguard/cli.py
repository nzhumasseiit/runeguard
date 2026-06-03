import json
import os
import platform
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

import typer

from .audit import (
    build_report,
    render_pr_summary_markdown,
    render_report_html,
    render_report_json,
    render_report_markdown,
    render_summary_text,
    summarize_audit_log,
)
from .agent import AgentWrapConfig, run_agent, summarize_agent_run, validate_agent_command
from .approval import ApprovalManager, ApprovalPolicy
from .ci import initialize_github_ci
from .daemon import DEFAULT_SOCKET_PATH, RuneGuardDaemon
from .demo import run_demo
from .diff_risk import analyze_diff_text, analyze_git_diff, render_diff_risk
from .ebpf import EbpfConfig, EbpfTracer
from .integrity import load_key, verify_log
from .logger import decision_record
from .mcp.inspect import inspect_mcp_config, render_mcp_inspection
from .mcp.proxy import run_proxy
from .mcp.server import RuneGuardMCPServer
from .policy import Policy
from .proxy import RuneGuardProxy
from .scan import render_scan_table, scan_path
from .startup import initialize_startup_repo
from .core.docker import DockerSandboxConfig, DockerSandboxRunner, current_user_container_id
from .core.interceptor import DEFAULT_SHIM_PATH, InterceptorConfig, RuneGuardInterceptor
from .core.landlock import LandlockConfig, LandlockSandboxRunner, LandlockUnavailable, landlock_available
from .core.sandbox import filter_child_env
from .seccomp.runner import run_with_seccomp

app = typer.Typer(help="RuneGuard: runtime enforcement for AI agents.")
daemon_app = typer.Typer(help="Manage the RuneGuard policy daemon.")
shim_app = typer.Typer(help="Build and inspect the LD_PRELOAD shim.")
ebpf_app = typer.Typer(help="Run Linux eBPF tracing.")
mcp_app = typer.Typer(help="MCP proxy and server commands.")
audit_app = typer.Typer(help="Audit log commands.")
examples_app = typer.Typer(help="Runnable RuneGuard examples.")
startup_app = typer.Typer(help="Startup repository setup commands.")
agent_app = typer.Typer(help="Run AI coding agents through RuneGuard.")
git_app = typer.Typer(help="Git diff risk analysis.")
ci_app = typer.Typer(help="CI workflow generators.")

app.add_typer(daemon_app, name="daemon")
app.add_typer(shim_app, name="shim")
app.add_typer(ebpf_app, name="ebpf")
app.add_typer(mcp_app, name="mcp")
app.add_typer(audit_app, name="audit")
app.add_typer(examples_app, name="examples")
app.add_typer(startup_app, name="startup")
app.add_typer(agent_app, name="agent")
app.add_typer(git_app, name="git")
app.add_typer(ci_app, name="ci")


INIT_POLICY = """# RuneGuard policy schema v0.1. Keep version: 1 stable.
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

files:
  deny:
    - ".env"
    - ".env.*"
    - ".git/**"
    - "**/secrets/**"
    - "~/.ssh/**"
    - "~/.aws/**"
    - "~/.config/gcloud/**"
  allow:
    - "src/**"
    - "tests/**"
    - "tmp/**"
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
"""

RUNEGUARD_README = """# RuneGuard local state

This directory stores local RuneGuard runtime files such as audit logs.

Suggested audit log path:

```bash
.runeguard/audit.jsonl
```
"""


@app.command(
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
    }
)
def run(
    ctx: typer.Context,
    policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
    profile: str | None = typer.Option(None, help="Built-in policy profile to use."),
    audit_log: str | None = typer.Option(None, help="Append decision records to this JSONL file."),
    json_logs: bool = typer.Option(False, help="Print RuneGuard decisions as JSON lines."),
    backend: str | None = typer.Option(None, help="Execution backend: docker, landlock, preload, or host."),
    allow_weak_fallback: bool = typer.Option(
        False,
        help="Allow policy-only fallback if an optional enforcement layer is unavailable.",
    ),
    image: str = typer.Option("python:3.12-slim", help="Docker image for the docker backend."),
    workspace: Path = typer.Option(Path.cwd(), help="Workspace directory to mount into the sandbox."),
    unsafe_writable_workspace: bool = typer.Option(
        False,
        help="Mount the whole workspace writable in Docker backend. Unsafe compatibility mode.",
    ),
    memory: str = typer.Option("512m", help="Docker memory limit."),
    cpus: str = typer.Option("1", help="Docker CPU limit."),
    pids_limit: int = typer.Option(256, help="Docker process count limit."),
    network: str | None = typer.Option(None, help="Docker network mode. Defaults to policy deny_all."),
    preload: bool = typer.Option(False, help="Run the command with the LD_PRELOAD shim."),
    seccomp: bool = typer.Option(False, help="Apply seccomp-BPF filter before running (Linux only)."),
    ask: bool = typer.Option(False, "--ask", help="Ask before allowing selected blocked actions for this session."),
    socket_path: str = typer.Option(DEFAULT_SOCKET_PATH, help="RuneGuard daemon socket for the shim."),
    shim_path: Path = typer.Option(DEFAULT_SHIM_PATH, help="Path to rg_preload.so."),
):
    """
    Run a command through RuneGuard sandbox or host policy checks.
    """
    if not ctx.args:
        typer.echo("Pass a command after '--'", err=True)
        typer.echo("Example: runeguard run -- python examples/fake_agent/agent.py", err=True)
        typer.echo("Fix: put your command after the '--' separator.", err=True)
        raise typer.Exit(2)

    policy_obj = Policy.from_profile(profile) if profile else Policy.from_file(policy)
    approval_manager = ApprovalManager()
    if backend is None:
        backend = policy_obj.sandbox_backend
    command = " ".join(ctx.args)
    env = None

    if ask:
        if _prompt_for_shell_approval(policy_obj, approval_manager, command, ctx.args):
            policy_obj = ApprovalPolicy(policy_obj, approval_manager)

    guard = RuneGuardProxy(policy_obj, audit_log=audit_log, json_logs=json_logs)

    if backend not in {"docker", "landlock", "preload", "host"}:
        typer.echo("Backend must be one of: docker, landlock, preload, host. Fix: use --backend docker, --backend landlock, --backend preload, or --backend host.", err=True)
        raise typer.Exit(2)

    if backend == "docker":
        if preload or seccomp:
            typer.echo("--preload and --seccomp are only supported with --backend host. Fix: add --backend host or remove those flags.", err=True)
            raise typer.Exit(2)

        config = DockerSandboxConfig(
            image=image,
            workspace=workspace,
            unsafe_writable_workspace=unsafe_writable_workspace,
            network="none" if (network or policy_obj.network) in {"deny_all", "none"} else (network or policy_obj.network),
            memory=memory,
            cpus=cpus,
            pids_limit=pids_limit,
            user=current_user_container_id(),
            readonly_rootfs=policy_obj.readonly_rootfs,
        )
        runner = DockerSandboxRunner(
            policy_obj,
            config,
            audit_log=audit_log,
            json_logs=json_logs,
        )
        if policy_obj.fs_enforcement == "landlock" and not landlock_available():
            if not allow_weak_fallback:
                typer.echo("Policy requests sandbox.fs_enforcement=landlock, but Landlock is unavailable. Security mode is fail-closed. Fix: run on Linux with Landlock, remove fs_enforcement, or pass --allow-weak-fallback.", err=True)
                raise typer.Exit(2)
            typer.echo("Warning: Landlock unavailable; continuing because --allow-weak-fallback was set.", err=True)

        try:
            raise typer.Exit(runner.run(ctx.args))
        except FileNotFoundError:
            typer.echo("Docker executable not found. Fix: install Docker, start Docker Desktop, or use --backend host for policy-only execution.", err=True)
            raise typer.Exit(127)
        except PermissionError as exc:
            typer.echo(f"Blocked: {exc}. Fix: adjust policy or use a safer command.", err=True)
            raise typer.Exit(1)
        except ValueError as exc:
            typer.echo(f"Invalid sandbox configuration: {exc}. Fix: run `runeguard doctor` and update runeguard.yaml.", err=True)
            raise typer.Exit(2)

    if backend == "landlock":
        if preload or seccomp:
            typer.echo("--preload and --seccomp are only supported with --backend host. Fix: remove those flags or use --backend host.", err=True)
            raise typer.Exit(2)

        runner = LandlockSandboxRunner(
            policy_obj,
            LandlockConfig(workspace=workspace, allow_weak_fallback=allow_weak_fallback),
        )
        try:
            raise typer.Exit(runner.run(ctx.args))
        except LandlockUnavailable as exc:
            typer.echo(f"{exc} Security mode is fail-closed. Fix: use Docker backend or pass --allow-weak-fallback for policy-only execution.", err=True)
            raise typer.Exit(2)
        except PermissionError as exc:
            typer.echo(f"Blocked: {exc}. Fix: adjust policy or use a safer command.", err=True)
            raise typer.Exit(1)

    if backend == "preload":
        preload = True
        typer.echo(
            "Warning: LD_PRELOAD is practical userspace enforcement, not a hard sandbox boundary. Use Docker or Landlock for stronger isolation.",
            err=True,
        )

    if preload:
        interceptor = RuneGuardInterceptor(
            InterceptorConfig(
                shim_path=shim_path,
                socket_path=socket_path,
                policy_path=policy,
                audit_log=audit_log,
            )
        )
        try:
            env = interceptor.env()
        except RuntimeError as exc:
            typer.echo(f"{exc} Fix: run `runeguard shim build` on Linux or choose --backend docker/host.", err=True)
            raise typer.Exit(2)

    if seccomp:
        if platform.system() != "Linux":
            typer.echo("--seccomp is Linux only. Fix: run on Linux or remove --seccomp.", err=True)
            raise typer.Exit(2)

        decision = policy_obj.decide("shell", command=command, argv=ctx.args)
        if decision.type.value != "ALLOW":
            typer.echo(f"Blocked: {decision.reason}. Fix: adjust policy or use a safer command.", err=True)
            raise typer.Exit(1)

        try:
            exit_code = run_with_seccomp(ctx.args, policy_obj, env=filter_child_env(policy_obj, env))
        except RuntimeError as exc:
            typer.echo(f"{exc}. Fix: run on Linux with seccomp support or remove --seccomp.", err=True)
            raise typer.Exit(2)

        raise typer.Exit(exit_code)

    try:
        result = guard.call(
            "shell",
            lambda command, argv: _run_subprocess(command, argv, policy_obj=policy_obj, env=env),
            command=command,
            argv=ctx.args,
        )
    except PermissionError as exc:
        typer.echo(f"Blocked: {exc}. Fix: adjust policy or use a safer command.", err=True)
        raise typer.Exit(1)

    raise typer.Exit(result)


@app.command()
def init(
    force: bool = typer.Option(False, "--force", help="Overwrite existing runeguard.yaml."),
):
    """
    Create a starter RuneGuard policy and local state directory.
    """
    policy_path = Path("runeguard.yaml")
    state_dir = Path(".runeguard")
    state_readme = state_dir / "README.md"
    audit_path = state_dir / "audit.jsonl"

    if policy_path.exists() and not force:
        typer.echo("runeguard.yaml already exists. Fix: use --force to overwrite it.", err=True)
        raise typer.Exit(1)

    policy_path.write_text(INIT_POLICY, encoding="utf-8")
    state_dir.mkdir(exist_ok=True)
    if not state_readme.exists():
        state_readme.write_text(RUNEGUARD_README, encoding="utf-8")
    if not audit_path.exists():
        audit_path.touch()

    typer.echo("Created runeguard.yaml")
    typer.echo("Created .runeguard/")
    typer.echo("Created .runeguard/audit.jsonl")


@startup_app.command("init")
def startup_init(
    force: bool = typer.Option(False, "--force", help="Overwrite an existing RuneGuard startup policy."),
    allow_common_dev_network: bool = typer.Option(
        False,
        "--allow-common-dev-network",
        help="Allow GitHub, npm, and PyPI domains in the generated policy.",
    ),
):
    """
    Generate a practical default security setup for a startup/dev repo.
    """
    try:
        changes = initialize_startup_repo(
            Path.cwd(),
            force=force,
            allow_common_dev_network=allow_common_dev_network,
        )
    except FileExistsError as exc:
        typer.echo(f"{exc}.", err=True)
        raise typer.Exit(1)

    for change in changes:
        typer.echo(f"Updated {change}")


@app.command("scan")
def scan(
    path: Path = typer.Argument(Path("."), help="Repository or path to scan."),
    json_output: bool = typer.Option(False, "--json", help="Print JSON scan output."),
):
    """
    Inspect a repository for secrets, risky scripts, workflows, and MCP configs.
    """
    try:
        report = scan_path(path)
    except FileNotFoundError:
        typer.echo(f"Path not found: {path}", err=True)
        raise typer.Exit(2)

    typer.echo(report.to_json() if json_output else render_scan_table(report))
    raise typer.Exit(1 if report.high_risk else 0)


@agent_app.command(
    "wrap",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def agent_wrap(
    ctx: typer.Context,
    agent: str = typer.Option("generic", "--agent", help="Agent name: codex, claude, cursor, or generic."),
    policy: Path = typer.Option(Path("runeguard.yaml"), help="Policy file to load."),
    audit_log: Path = typer.Option(Path(".runeguard/audit.jsonl"), help="Audit log path."),
    workspace: Path = typer.Option(Path.cwd(), help="Workspace directory."),
    backend: str | None = typer.Option(None, help="Execution backend: docker or host."),
    image: str = typer.Option("python:3.12-slim", help="Docker image for the docker backend."),
    ask: bool = typer.Option(False, "--ask", help="Ask before allowing selected blocked shell actions."),
):
    """
    Run an AI coding agent command through RuneGuard.
    """
    config = AgentWrapConfig(
        agent=agent,
        command=list(ctx.args),
        workspace=workspace,
        policy_path=policy,
        audit_log=audit_log,
        image=image,
        backend=backend,
    )
    try:
        validate_agent_command(config)
        loaded_policy = Policy.from_file(str(policy))
        if ask:
            approval_manager = ApprovalManager()
            command = " ".join(config.command)
            if _prompt_for_shell_approval(loaded_policy, approval_manager, command, config.command):
                loaded_policy = ApprovalPolicy(loaded_policy, approval_manager)
        exit_code = run_agent(config, policy=loaded_policy)
    except FileNotFoundError as exc:
        typer.echo(f"{exc}. Fix: install the agent binary or pass a different command after '--'.", err=True)
        raise typer.Exit(127)
    except PermissionError as exc:
        typer.echo(f"Blocked: {exc}. Fix: adjust policy or use --ask for reasonable shell/network actions.", err=True)
        raise typer.Exit(1)
    except ValueError as exc:
        typer.echo(f"{exc}.", err=True)
        raise typer.Exit(2)

    typer.echo(summarize_agent_run(audit_log))
    raise typer.Exit(exit_code)


@git_app.command("diff-risk")
def git_diff_risk(
    diff_file: Path | None = typer.Option(None, "--diff-file", help="Analyze a saved unified diff instead of git diff."),
):
    """
    Analyze the current git diff for deterministic AI-change risks.
    """
    try:
        if diff_file:
            report = analyze_diff_text(diff_file.read_text(encoding="utf-8"))
        else:
            report = analyze_git_diff(Path.cwd())
    except (OSError, RuntimeError) as exc:
        typer.echo(f"Unable to analyze diff: {exc}", err=True)
        raise typer.Exit(2)

    typer.echo(render_diff_risk(report))
    raise typer.Exit(1 if report.score == "high" else 0)


@ci_app.command("init")
def ci_init(
    github: bool = typer.Option(False, "--github", help="Create .github/workflows/runeguard.yml."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing workflow."),
):
    """
    Generate CI starter workflow files.
    """
    if not github:
        typer.echo("Choose a CI target. Fix: run `runeguard ci init --github`.", err=True)
        raise typer.Exit(2)
    try:
        workflow = initialize_github_ci(Path.cwd(), force=force)
    except FileExistsError as exc:
        typer.echo(f"{exc}.", err=True)
        raise typer.Exit(1)
    typer.echo(f"Created {workflow}")


@app.command()
def doctor(policy: str = typer.Option("runeguard.yaml", help="Policy file to check.")):
    """
    Check local RuneGuard sandbox prerequisites.
    """
    checks = []
    critical_failures = 0

    docker_path = shutil.which("docker")
    if docker_path:
        checks.append(("ok", f"Docker executable found: {docker_path}"))
    else:
        checks.append(("fail", "Docker executable not found. Fix: install Docker or Docker Desktop."))
        critical_failures += 1

    docker_available = bool(docker_path and _docker_daemon_reachable())
    if docker_available:
        checks.append(("ok", "Docker: available; Docker daemon reachable"))
    else:
        checks.append(("fail", "Docker: unavailable. Fix: install/start Docker or use --backend landlock on Linux."))
        critical_failures += 1

    os_name = platform.system() or "unknown"
    checks.append(("info", f"OS: {os_name}"))

    if os_name == "Linux":
        checks.append(("ok" if _linux_seccomp_likely_available() else "warn", "Seccomp: available" if _linux_seccomp_likely_available() else "Seccomp: unavailable"))
        checks.append(("ok" if landlock_available() else "warn", "Landlock: available" if landlock_available() else "Landlock: unavailable"))
        checks.append(("ok" if _linux_ebpf_likely_available() else "warn", "eBPF: available" if _linux_ebpf_likely_available() else "eBPF: unavailable"))
    else:
        checks.append(("warn", "Seccomp: unavailable on this OS"))
        checks.append(("warn", "Landlock: unavailable on this OS"))
        checks.append(("warn", "eBPF: unavailable on this OS"))

    policy_path = Path(policy)
    if policy_path.exists():
        try:
            loaded_policy = Policy.from_file(str(policy_path))
        except Exception as exc:
            checks.append(("fail", f"Policy file is invalid: {exc}. Fix: compare it with docs/policy-schema.md."))
            critical_failures += 1
        else:
            checks.append(("ok", f"Policy file exists and is valid: {policy}"))
            checks.append(("info", f"Default backend: {loaded_policy.sandbox_backend}"))
            checks.append(("info", "Security mode: fail-closed"))
            for writable_path in loaded_policy.writable_paths:
                candidate = Path(writable_path)
                if not candidate.is_absolute():
                    candidate = Path.cwd() / candidate
                if candidate.exists():
                    checks.append(("ok", f"Writable path exists: {writable_path}"))
                else:
                    checks.append(("warn", f"Writable path does not exist yet: {writable_path}. Fix: create it or remove it from policy."))
    elif policy == "runeguard.yaml" and Path("policies/default.yaml").exists():
        checks.append(("ok", "Default policy file exists: policies/default.yaml"))
        checks.append(("info", "Default backend: docker"))
        checks.append(("info", "Security mode: fail-closed"))
    else:
        checks.append(("fail", f"Policy file not found: {policy}. Fix: run `runeguard init` or pass --policy policies/default.yaml."))
        critical_failures += 1

    for status, message in checks:
        typer.echo(f"[{status.upper()}] {message}")

    if critical_failures:
        raise typer.Exit(1)


@audit_app.command("summary")
def audit_summary(audit_log: Path = typer.Argument(..., help="Path to a RuneGuard JSONL audit log.")):
    """
    Print a summary of a RuneGuard JSONL audit log.
    """
    try:
        summary = summarize_audit_log(audit_log)
    except FileNotFoundError:
        typer.echo(f"Audit log not found: {audit_log}. Fix: pass an existing .runeguard/audit.jsonl path.", err=True)
        raise typer.Exit(1)
    except json.JSONDecodeError as exc:
        typer.echo(f"Invalid JSONL audit log at line {exc.lineno}: {exc.msg}. Fix: remove malformed lines or regenerate the audit log.", err=True)
        raise typer.Exit(2)

    typer.echo(render_summary_text(summary))


@audit_app.command("verify")
def audit_verify(
    audit_log: Path = typer.Argument(..., help="Path to a RuneGuard JSONL audit log."),
    expected_head: str | None = typer.Option(
        None,
        "--expected-head",
        help="Externally anchored head hash used to detect tail truncation.",
    ),
):
    """
    Verify a tamper-evident RuneGuard audit log.
    """
    try:
        result = verify_log(audit_log, key=load_key(), expected_head=expected_head)
    except FileNotFoundError:
        typer.echo(f"Audit log not found: {audit_log}. Fix: pass an existing .runeguard/audit.jsonl path.", err=True)
        raise typer.Exit(1)
    except ValueError as exc:
        typer.echo(f"Invalid audit key: {exc}. Fix: set RUNEGUARD_AUDIT_KEY to hex or RUNEGUARD_AUDIT_KEYFILE to raw key bytes.", err=True)
        raise typer.Exit(2)

    if result.ok:
        typer.echo(f"OK: {result.count} records, head {result.head_hash}")
        return

    where = f" at seq {result.break_seq}" if result.break_seq is not None else ""
    typer.echo(f"TAMPER DETECTED{where}: {result.error}", err=True)
    raise typer.Exit(1)


@app.command()
def report(
    logfile: Path = typer.Argument(..., help="Path to a RuneGuard JSONL audit log."),
    report_format: str = typer.Option(
        "markdown",
        "--format",
        help="Report format: markdown, html, or json.",
    ),
    html: bool = typer.Option(False, "--html", help="Compatibility shortcut for --format html."),
    markdown: bool = typer.Option(False, "--markdown", help="Compatibility shortcut for --format markdown."),
    open_report: bool = typer.Option(False, "--open", help="Open an HTML report in the default browser."),
    pr_summary: bool = typer.Option(False, "--pr-summary", help="Render a concise Markdown PR comment summary."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to a file."),
):
    """
    Generate a RuneGuard audit report.
    """
    if html:
        report_format = "html"
    if markdown:
        report_format = "markdown"
    if pr_summary:
        report_format = "markdown"
    if report_format not in {"markdown", "html", "json"}:
        typer.echo("Format must be one of: markdown, html, json.", err=True)
        raise typer.Exit(2)

    try:
        report_data = build_report(logfile)
    except FileNotFoundError:
        typer.echo(f"Audit log not found: {logfile}. Fix: pass an existing .runeguard/audit.jsonl path.", err=True)
        raise typer.Exit(1)
    except json.JSONDecodeError as exc:
        typer.echo(f"Invalid JSONL audit log at line {exc.lineno}: {exc.msg}. Fix: remove malformed lines or regenerate the audit log.", err=True)
        raise typer.Exit(2)

    if pr_summary:
        rendered = render_pr_summary_markdown(report_data)
    elif report_format == "html":
        rendered = render_report_html(report_data)
    elif report_format == "json":
        rendered = render_report_json(report_data)
    else:
        rendered = render_report_markdown(report_data)

    if open_report and report_format != "html":
        typer.echo("--open requires HTML output. Fix: use --html --open.", err=True)
        raise typer.Exit(2)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        typer.echo(f"Wrote report: {output}")
        if open_report:
            webbrowser.open(output.resolve().as_uri())
        return

    if open_report:
        output = Path(".runeguard") / "report.html"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        webbrowser.open(output.resolve().as_uri())
        typer.echo(f"Wrote report: {output}")
        return

    typer.echo(rendered)


@examples_app.command("poisoned-readme")
def examples_poisoned_readme(
    policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
    audit_log: str | None = typer.Option(None, help="Append decision records to this JSONL file."),
):
    """
    Run the poisoned README prompt-injection example.
    """
    run_demo(policy, audit_log=audit_log)


@app.command()
def demo(
    policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
    audit_log: str | None = typer.Option(None, help="Append decision records to this JSONL file."),
    json_logs: bool = typer.Option(False, help="Print RuneGuard decisions as JSON lines."),
):
    """
    Run the local poisoned-prompt demo.
    """
    run_demo(policy, audit_log=audit_log, json_logs=json_logs)


@app.command()
def quickstart():
    """
    Print the recommended RuneGuard run command for this environment.
    """
    if _docker_available():
        typer.echo("Docker detected. Recommended: runeguard run --profile ci -- your-command")
        return

    if platform.system() == "Linux" and landlock_available():
        typer.echo("Linux detected. Recommended: runeguard run --backend landlock -- your-command")
        return

    typer.echo("Recommended: runeguard run --backend host -- your-command")


@app.command()
def check(
    policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
    json_output: bool = typer.Option(False, "--json", help="Print policy summary as JSON."),
):
    """
    Print a RuneGuard environment health table.
    """
    loaded = Policy.from_file(policy)
    if json_output:
        import json

        typer.echo(json.dumps(loaded.summary(), sort_keys=True))
        return

    typer.echo(f"Policy loaded: {policy}")

    python_ok = sys.version_info >= (3, 10)
    docker_ok = _docker_available()
    is_linux = platform.system() == "Linux"
    landlock_ok = is_linux and landlock_available()
    ebpf_ok = is_linux and os.geteuid() == 0 and _linux_ebpf_likely_available()
    recommended = _recommended_backend(docker_ok=docker_ok, landlock_ok=landlock_ok)

    rows = [
        ("✓" if python_ok else "✗", "Python 3.10+"),
        ("✓" if docker_ok else "✗", "Docker available"),
        ("✓" if landlock_ok else "✗", "Linux required for Landlock"),
        ("✓" if ebpf_ok else "✗", "Linux + root required for eBPF"),
        ("→", f"Recommended backend: {recommended}"),
    ]

    for marker, message in rows:
        typer.echo(f"{marker} {message}")


@app.command("eval")
def evaluate(
    tool_name: str = typer.Argument(..., help="Tool/action name, for example read_file, shell, or http_post."),
    policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
    path: str | None = typer.Option(None, help="Path argument for file tools."),
    command: str | None = typer.Option(None, help="Command string for shell tools."),
    url: str | None = typer.Option(None, help="URL argument for HTTP tools."),
    json_output: bool = typer.Option(False, "--json", help="Print the decision as JSON."),
):
    """
    Evaluate one action against policy without executing it.
    """
    loaded = Policy.from_file(policy)
    kwargs = {}

    if path is not None:
        kwargs["path"] = path

    if command is not None:
        kwargs["command"] = command

    if url is not None:
        kwargs["url"] = url

    decision = loaded.decide(tool_name, **kwargs)

    if json_output:
        import json

        typer.echo(json.dumps(decision_record(tool_name, decision, kwargs), sort_keys=True))
        return

    typer.echo(f"{decision.type.value}: {decision.reason}")


@daemon_app.command("start")
def daemon_start(
    policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
    socket_path: str = typer.Option(DEFAULT_SOCKET_PATH, help="Unix socket path."),
    audit_log: str | None = typer.Option(None, help="Append decisions to this JSONL file."),
    json_logs: bool = typer.Option(False, help="Print decisions as JSON lines."),
):
    """
    Start the RuneGuard policy daemon for shim IPC.
    """
    daemon = RuneGuardDaemon(
        policy_path=policy,
        socket_path=socket_path,
        audit_log=audit_log,
        json_logs=json_logs,
    )
    daemon.start()


@daemon_app.command("status")
def daemon_status(socket_path: str = typer.Option(DEFAULT_SOCKET_PATH, help="Unix socket path.")):
    """
    Check whether the daemon socket exists.
    """
    if Path(socket_path).exists():
        typer.echo(f"RuneGuard daemon socket found: {socket_path}")
        return

    typer.echo(f"RuneGuard daemon socket not found: {socket_path}")
    raise typer.Exit(1)


@shim_app.command("build")
def shim_build():
    """
    Build the Linux LD_PRELOAD shim.
    """
    if platform.system() != "Linux":
        typer.echo("LD_PRELOAD shim builds are supported on Linux only.", err=True)
        raise typer.Exit(2)

    shim_dir = Path(__file__).resolve().parent / "shim"
    result = subprocess.run(["make"], cwd=shim_dir, check=False)
    raise typer.Exit(result.returncode)


@shim_app.command("path")
def shim_path():
    """
    Print the expected shim .so path.
    """
    typer.echo(Path(__file__).resolve().parent / "shim" / "rg_preload.so")


@ebpf_app.command("trace")
def ebpf_trace(
    policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
    loader_path: Path | None = typer.Option(None, help="Path to runeguard-ebpf-loader."),
):
    """
    Trace execve, openat, and connect syscalls with libbpf/CO-RE eBPF.
    """
    raise typer.Exit(EbpfTracer(EbpfConfig(mode="trace", policy=policy, loader_path=loader_path)).start())


@ebpf_app.command("enforce")
def ebpf_enforce(
    policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
    loader_path: Path | None = typer.Option(None, help="Path to runeguard-ebpf-loader."),
):
    """
    Start the libbpf/CO-RE eBPF loader in enforcement mode.
    """
    raise typer.Exit(EbpfTracer(EbpfConfig(mode="enforce", policy=policy, loader_path=loader_path)).start())


@mcp_app.command(
    "proxy",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def mcp_proxy(
    ctx: typer.Context,
    policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
    server_name: str = typer.Option("upstream", "--server-name", help="Policy name for the upstream MCP server."),
    audit_log: str | None = typer.Option(None, help="Append decisions to this JSONL file."),
    json_logs: bool = typer.Option(False, help="Print decisions as JSON lines."),
):
    """
    Run RuneGuard as a transparent MCP proxy in front of an upstream MCP server.
    """
    if not ctx.args:
        typer.echo("Pass the upstream MCP server command after '--'", err=True)
        typer.echo(
            "Example: runeguard mcp proxy -- npx @modelcontextprotocol/server-filesystem /workspace",
            err=True,
        )
        raise typer.Exit(2)

    loaded = Policy.from_file(policy)
    try:
        run_proxy(loaded, ctx.args, audit_log=audit_log, json_logs=json_logs, server_name=server_name)
    except RuntimeError as exc:
        typer.echo(f"{exc}.", err=True)
        raise typer.Exit(2)


@mcp_app.command("serve")
def mcp_serve(
    policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
    audit_log: str | None = typer.Option(None, help="Append decisions to this JSONL file."),
):
    """
    Run RuneGuard as a standalone MCP server with policy-checked tools.
    """
    loaded = Policy.from_file(policy)
    RuneGuardMCPServer(loaded, audit_log=audit_log).serve()


@mcp_app.command("inspect")
def mcp_inspect(
    config_path: Path = typer.Argument(..., help="Path to an MCP JSON config file."),
    json_output: bool = typer.Option(False, "--json", help="Print JSON output."),
):
    """
    Inspect common MCP config JSON for risky server definitions.
    """
    try:
        servers = inspect_mcp_config(config_path)
    except FileNotFoundError:
        typer.echo(f"MCP config not found: {config_path}", err=True)
        raise typer.Exit(2)
    except (json.JSONDecodeError, ValueError) as exc:
        typer.echo(f"Invalid MCP config: {exc}", err=True)
        raise typer.Exit(2)

    typer.echo(render_mcp_inspection(servers, json_output=json_output))


def _run_subprocess(
    command: str,
    argv: list[str],
    *,
    policy_obj: Policy,
    env: dict[str, str] | None = None,
) -> int:
    completed = subprocess.run(argv, check=False, env=filter_child_env(policy_obj, env))
    return completed.returncode


def _docker_daemon_reachable() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return False

    return result.returncode == 0


def _docker_available() -> bool:
    return bool(shutil.which("docker") and _docker_daemon_reachable())


def _recommended_backend(*, docker_ok: bool | None = None, landlock_ok: bool | None = None) -> str:
    docker_ok = _docker_available() if docker_ok is None else docker_ok
    landlock_ok = (platform.system() == "Linux" and landlock_available()) if landlock_ok is None else landlock_ok

    if docker_ok:
        return "docker"
    if landlock_ok:
        return "landlock"
    return "host"


def _linux_seccomp_likely_available() -> bool:
    if platform.system() != "Linux":
        return False

    status_path = Path("/proc/self/status")
    try:
        status = status_path.read_text(encoding="utf-8")
    except OSError:
        return False

    return "Seccomp:" in status


def _linux_landlock_likely_available() -> bool:
    if platform.system() != "Linux":
        return False

    return Path("/proc/self/attr/landlock").exists() or Path("/sys/kernel/security/landlock").exists()


def _linux_ebpf_likely_available() -> bool:
    if platform.system() != "Linux":
        return False

    return Path("/sys/kernel/btf/vmlinux").exists() or Path("/sys/fs/bpf").exists()


def _prompt_for_shell_approval(policy_obj, approval_manager: ApprovalManager, command: str, argv: list[str]) -> bool:
    decision = policy_obj.decide("shell", command=command, argv=argv)
    if decision.type.value == "ALLOW":
        return False

    typer.echo(f"BLOCKED: {decision.reason}")
    choice = typer.prompt(
        "Choose: allow once, allow session, deny, deny policy",
        default="deny",
    ).strip().lower()

    kwargs = {"command": command, "argv": argv}
    if choice in {"allow once", "once", "1"}:
        approval_manager.allow_for_session("shell", kwargs)
        return True
    if choice in {"allow session", "session", "2"}:
        approval_manager.allow_for_session("shell", kwargs)
        return True
    if choice in {"deny policy", "deny and add to policy", "4"}:
        typer.echo("Denied. Policy was not changed because this action is already blocked by the loaded policy.")
    return False


if __name__ == "__main__":
    app()
