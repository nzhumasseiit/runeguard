import json
import sys


TOOLS = [
    {"name": "read_file", "inputSchema": {"type": "object"}},
    {"name": "write_file", "inputSchema": {"type": "object"}},
    {"name": "list_directory", "inputSchema": {"type": "object"}},
    {"name": "run_command", "inputSchema": {"type": "object"}},
]


def respond(message, result=None, error=None):
    payload = {"jsonrpc": "2.0", "id": message.get("id")}
    if error is not None:
        payload["error"] = error
    else:
        payload["result"] = result if result is not None else {}
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    method = message.get("method")
    params = message.get("params", {})

    if method == "tools/list":
        respond(message, {"tools": TOOLS})
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        respond(message, {"content": [{"type": "text", "text": f"{name}:{args}"}]})
    elif method == "resources/list":
        respond(message, {"resources": [{"uri": "file:///README.md", "name": "README.md"}]})
    elif method == "resources/read":
        respond(message, {"contents": [{"uri": params.get("uri"), "text": "ok"}]})
    else:
        respond(message, error={"code": -32601, "message": "method not found"})
