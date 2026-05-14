from pathlib import Path


def read_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def shell(command: str) -> str:
    return f"simulated shell execution: {command}"


def http_post(url: str, data: str) -> str:
    return f"simulated HTTP POST to {url} with {len(data)} bytes"
