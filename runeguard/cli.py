import subprocess

import typer

from .demo import run_demo
from .policy import Policy
from .proxy import RuneGuardProxy

app = typer.Typer(help="RuneGuard: runtime enforcement for AI agents.")


@app.command(
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
    }
)
def run(
    ctx: typer.Context,
    policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
):
    """
    Run a command through RuneGuard policy checks.
    """
    if not ctx.args:
        raise typer.BadParameter("Pass a command after '--', for example: runeguard run -- python app.py")

    policy_obj = Policy.from_file(policy)
    guard = RuneGuardProxy(policy_obj)
    command = " ".join(ctx.args)

    try:
        result = guard.call(
            "shell",
            _run_subprocess,
            command=command,
            argv=ctx.args,
        )
    except PermissionError as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(1)

    raise typer.Exit(result)


@app.command()
def demo(policy: str = "policies/default.yaml"):
    """
    Run the local poisoned-prompt demo.
    """
    run_demo(policy)


@app.command()
def check(policy: str = "policies/default.yaml"):
    """
    Check that a policy file can be loaded.
    """
    loaded = Policy.from_file(policy)
    typer.echo(f"Policy loaded: {policy}")
    typer.echo(f"Protected paths: {loaded.protected_paths}")
    typer.echo(f"Allowed domains: {loaded.allowed_domains}")


def _run_subprocess(command: str, argv: list[str]) -> int:
    completed = subprocess.run(argv, check=False)
    return completed.returncode


if __name__ == "__main__":
    app()
