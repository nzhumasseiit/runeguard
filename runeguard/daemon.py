import json
import os
import socket
from pathlib import Path
from threading import Thread

from .decision import DecisionType
from .logger import log_decision
from .policy import Policy


DEFAULT_SOCKET_PATH = "/tmp/runeguard.sock"


class RuneGuardDaemon:
    def __init__(
        self,
        policy_path: str = "policies/default.yaml",
        socket_path: str = DEFAULT_SOCKET_PATH,
        *,
        audit_log: str | None = None,
        json_logs: bool = False,
    ):
        self.policy_path = policy_path
        self.policy = Policy.from_file(policy_path)
        self.socket_path = socket_path
        self.audit_log = audit_log
        self.json_logs = json_logs
        self.running = False
        self._server: socket.socket | None = None

    def start(self):
        self.running = True
        socket_file = Path(self.socket_path)
        if socket_file.exists():
            socket_file.unlink()

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        os.chmod(self.socket_path, 0o600)
        server.listen(16)
        self._server = server
        print(f"[RuneGuard daemon] listening on {self.socket_path}")

        try:
            while self.running:
                conn, _ = server.accept()
                Thread(target=self._handle_client, args=(conn,), daemon=True).start()
        finally:
            server.close()
            self._server = None
            if socket_file.exists():
                socket_file.unlink()

    def stop(self):
        self.running = False
        if self._server:
            self._server.close()

    def decide_request(self, request: dict) -> dict:
        tool_name = request.get("tool_name") or request.get("tool")
        if not tool_name:
            return {"type": "ERROR", "reason": "missing tool_name", "allow": False}

        kwargs = {
            key: value
            for key, value in request.items()
            if key not in {"tool", "tool_name", "pid", "ppid", "comm"}
        }
        decision = self.policy.decide(tool_name, **kwargs)
        log_decision(
            tool_name,
            decision,
            kwargs,
            audit_log=self.audit_log,
            json_logs=self.json_logs,
        )

        return {
            "type": decision.type.value,
            "reason": decision.reason,
            "allow": decision.type == DecisionType.ALLOW,
        }

    def _handle_client(self, conn: socket.socket):
        response = {"type": "ERROR", "reason": "empty request", "allow": False}
        try:
            data = conn.recv(65536)
            if not data:
                return

            request = json.loads(data.decode("utf-8"))
            response = self.decide_request(request)
        except Exception as exc:
            response = {"type": "ERROR", "reason": str(exc), "allow": False}
        finally:
            conn.sendall(json.dumps(response).encode("utf-8"))
            conn.close()


def ask_daemon(request: dict, socket_path: str = DEFAULT_SOCKET_PATH, timeout: float = 1.0) -> dict:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(socket_path)
        client.sendall(json.dumps(request).encode("utf-8"))
        data = client.recv(65536)
        return json.loads(data.decode("utf-8"))
    finally:
        client.close()


def main():
    import typer

    app = typer.Typer(help="RuneGuard policy daemon.")

    @app.command()
    def start(
        policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
        socket_path: str = typer.Option(DEFAULT_SOCKET_PATH, help="Unix socket path."),
        audit_log: str | None = typer.Option(None, help="Append decisions to this JSONL file."),
        json_logs: bool = typer.Option(False, help="Print decisions as JSON lines."),
    ):
        daemon = RuneGuardDaemon(
            policy_path=policy,
            socket_path=socket_path,
            audit_log=audit_log,
            json_logs=json_logs,
        )
        daemon.start()

    app()


if __name__ == "__main__":
    main()
