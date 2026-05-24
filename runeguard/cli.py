import json
import platform
import shutil
import subprocess
from pathlib import Path

import typer

from .audit import (
    build_report,
    render_report_html,
    render_report_json,
    render_report_markdown,
    render_summary_text,
    summarize_audit_log,
)
from .daemon import DEFAULT_SOCKET_PATH, RuneGuardDaemon
from .demo import run_demo
from .ebpf import EbpfConfig, EbpfTracer
from .logger import decision_record
from .mcp.proxy import run_proxy
from .mcp.server import RuneGuardMCPServer
from .policy import Policy
from .proxy import RuneGuardProxy
from .core.docker import DockerSandboxConfig, DockerSandboxRunner, current_user_container_id
from .core.interceptor import InterceptorConfig, RuneGuardInterceptor
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

app.add_typer(daemon_app, name="daemon")
app.add_typer(shim_app, name="shim")
app.add_typer(ebpf_app, name="ebpf")
app.add_typer(mcp_app, name="mcp")
app.add_typer(audit_app, name="audit")
app.add_typer(examples_app, name="examples")


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
    backend: str | None = typer.Option(None, help="Execution backend: docker, landlock, or host."),
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
    socket_path: str = typer.Option(DEFAULT_SOCKET_PATH, help="RuneGuard daemon socket for the shim."),
    shim_path: Path = typer.Option(Path("runeguard/shim/rg_preload.so"), help="Path to rg_preload.so."),
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
    if backend is None:
        backend = policy_obj.sandbox_backend
    guard = RuneGuardProxy(policy_obj, audit_log=audit_log, json_logs=json_logs)
    command = " ".join(ctx.args)
    env = None

    if backend not in {"docker", "landlock", "host"}:
        typer.echo("Backend must be one of: docker, landlock, host. Fix: use --backend docker, --backend landlock, or --backend host.", err=True)
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

    if preload:
        interceptor = RuneGuardInterceptor(
            InterceptorConfig(
                shim_path=shim_path,
                socket_path=socket_path,
                policy_path=policy,
            )
        )
        env = interceptor.env()

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
        checks.append(("ok", "Docker: available"))
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


@app.command()
def report(
    logfile: Path = typer.Argument(..., help="Path to a RuneGuard JSONL audit log."),
    report_format: str = typer.Option(
        "markdown",
        "--format",
        help="Report format: markdown, html, or json.",
    ),
    html: bool = typer.Option(False, "--html", help="Compatibility shortcut for --format html."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to a file."),
):
    """
    Generate a RuneGuard audit report.
    """
    if html:
        report_format = "html"
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

    if report_format == "html":
        rendered = render_report_html(report_data)
    elif report_format == "json":
        rendered = render_report_json(report_data)
    else:
        rendered = render_report_markdown(report_data)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
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
def check(
    policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
    json_output: bool = typer.Option(False, "--json", help="Print policy summary as JSON."),
):
    """
    Check that a policy file can be loaded.
    """
    loaded = Policy.from_file(policy)
    if json_output:
        import json

        typer.echo(json.dumps(loaded.summary(), sort_keys=True))
        return

    typer.echo(f"Policy loaded: {policy}")
    typer.echo(f"Protected paths: {loaded.protected_paths}")
    typer.echo(f"Allowed domains: {loaded.allowed_domains}")


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
    run_proxy(loaded, ctx.args, audit_log=audit_log, json_logs=json_logs)


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


if __name__ == "__main__":
    app()
