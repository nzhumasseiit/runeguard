import platform
import subprocess
from pathlib import Path

import typer

from .daemon import DEFAULT_SOCKET_PATH, RuneGuardDaemon
from .demo import run_demo
from .ebpf import EbpfTracer
from .logger import decision_record
from .mcp.proxy import run_proxy
from .mcp.server import RuneGuardMCPServer
from .policy import Policy
from .proxy import RuneGuardProxy
from .core.docker import DockerSandboxConfig, DockerSandboxRunner, current_user_container_id
from .core.interceptor import InterceptorConfig, RuneGuardInterceptor
from .seccomp.runner import run_with_seccomp

app = typer.Typer(help="RuneGuard: runtime enforcement for AI agents.")
daemon_app = typer.Typer(help="Manage the RuneGuard policy daemon.")
shim_app = typer.Typer(help="Build and inspect the LD_PRELOAD shim.")
ebpf_app = typer.Typer(help="Run Linux eBPF tracing.")
mcp_app = typer.Typer(help="MCP proxy and server commands.")

app.add_typer(daemon_app, name="daemon")
app.add_typer(shim_app, name="shim")
app.add_typer(ebpf_app, name="ebpf")
app.add_typer(mcp_app, name="mcp")


@app.command(
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
    }
)
def run(
    ctx: typer.Context,
    policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
    audit_log: str | None = typer.Option(None, help="Append decision records to this JSONL file."),
    json_logs: bool = typer.Option(False, help="Print RuneGuard decisions as JSON lines."),
    backend: str = typer.Option("docker", help="Execution backend: docker or host."),
    image: str = typer.Option("python:3.12-slim", help="Docker image for the docker backend."),
    workspace: Path = typer.Option(Path.cwd(), help="Workspace directory to mount into the sandbox."),
    memory: str = typer.Option("512m", help="Docker memory limit."),
    cpus: str = typer.Option("1", help="Docker CPU limit."),
    pids_limit: int = typer.Option(256, help="Docker process count limit."),
    network: str = typer.Option("none", help="Docker network mode. Defaults to none."),
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
        raise typer.Exit(2)

    policy_obj = Policy.from_file(policy)
    guard = RuneGuardProxy(policy_obj, audit_log=audit_log, json_logs=json_logs)
    command = " ".join(ctx.args)
    env = None

    if backend not in {"docker", "host"}:
        typer.echo("Backend must be one of: docker, host", err=True)
        raise typer.Exit(2)

    if backend == "docker":
        if preload or seccomp:
            typer.echo("--preload and --seccomp are only supported with --backend host", err=True)
            raise typer.Exit(2)

        config = DockerSandboxConfig(
            image=image,
            workspace=workspace,
            network=network,
            memory=memory,
            cpus=cpus,
            pids_limit=pids_limit,
            user=current_user_container_id(),
        )
        runner = DockerSandboxRunner(
            policy_obj,
            config,
            audit_log=audit_log,
            json_logs=json_logs,
        )
        try:
            raise typer.Exit(runner.run(ctx.args))
        except FileNotFoundError:
            typer.echo("Docker executable not found. Install Docker or use --backend host.", err=True)
            raise typer.Exit(127)
        except PermissionError as exc:
            typer.echo(f"Blocked: {exc}", err=True)
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
            typer.echo("--seccomp is Linux only", err=True)
            raise typer.Exit(2)

        decision = policy_obj.decide("shell", command=command, argv=ctx.args)
        if decision.type.value != "ALLOW":
            typer.echo(f"Blocked: {decision.reason}", err=True)
            raise typer.Exit(1)

        try:
            exit_code = run_with_seccomp(ctx.args, policy_obj, env=env)
        except RuntimeError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(2)

        raise typer.Exit(exit_code)

    try:
        result = guard.call(
            "shell",
            lambda command, argv: _run_subprocess(command, argv, env=env),
            command=command,
            argv=ctx.args,
        )
    except PermissionError as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(1)

    raise typer.Exit(result)


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
def ebpf_trace():
    """
    Trace execve, openat, and connect syscalls with BCC/eBPF.
    """
    EbpfTracer().start()


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


def _run_subprocess(command: str, argv: list[str], env: dict[str, str] | None = None) -> int:
    completed = subprocess.run(argv, check=False, env=env)
    return completed.returncode


if __name__ == "__main__":
    app()
