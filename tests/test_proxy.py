import pytest

from runeguard.decision import DecisionType
from runeguard.policy import Policy
from runeguard.proxy import RuneGuardProxy


def test_proxy_blocks_disallowed_action():
    policy = Policy({"blocked_commands": ["rm -rf"]})
    proxy = RuneGuardProxy(policy)

    with pytest.raises(PermissionError):
        proxy.call("shell", lambda command: command, command="rm -rf ./project")


def test_proxy_allows_safe_action():
    policy = Policy({"blocked_commands": ["rm -rf"]})
    proxy = RuneGuardProxy(policy)

    result = proxy.call("shell", lambda command: command, command="echo hello")
    assert result == "echo hello"


def test_proxy_logs_and_passes_extra_kwargs():
    policy = Policy({"blocked_commands": []})
    proxy = RuneGuardProxy(policy)

    result = proxy.call(
        "shell",
        lambda command, argv: (command, argv),
        command="echo hello",
        argv=["echo", "hello"],
    )

    assert result == ("echo hello", ["echo", "hello"])
