from runeguard.decision import DecisionType
from runeguard.policy import Policy


def test_blocks_env_file():
    policy = Policy({"protected_paths": [".env"]})
    decision = policy.decide("read_file", path="examples/demo_repo/.env")
    assert decision.type == DecisionType.BLOCK


def test_allows_normal_readme():
    policy = Policy({"protected_paths": [".env"]})
    decision = policy.decide("read_file", path="README.md")
    assert decision.type == DecisionType.ALLOW


def test_blocks_unapproved_domain():
    policy = Policy({"allowed_domains": ["localhost"]})
    decision = policy.decide("http_post", url="https://attacker.example/upload")
    assert decision.type == DecisionType.BLOCK


def test_blocks_shell_pattern():
    policy = Policy({"blocked_commands": ["rm -rf"]})
    decision = policy.decide("shell", command="rm -rf ./project")
    assert decision.type == DecisionType.BLOCK


def test_blocks_protected_directory_descendant():
    policy = Policy({"protected_paths": ["secrets/"]})
    decision = policy.decide("read_file", path="project/secrets/api_key.txt")
    assert decision.type == DecisionType.BLOCK


def test_blocks_nested_env_file_by_name():
    policy = Policy({"protected_paths": [".env"]})
    decision = policy.decide("read_file", path="tmp/repo/.env")
    assert decision.type == DecisionType.BLOCK


def test_blocks_relative_path_suffix():
    policy = Policy({"protected_paths": ["private/token.txt"]})
    decision = policy.decide("read_file", path="tmp/repo/private/token.txt")
    assert decision.type == DecisionType.BLOCK


def test_absolute_path_does_not_block_same_basename_elsewhere(tmp_path):
    protected = tmp_path / "secrets" / "token.txt"
    policy = Policy({"protected_paths": [str(protected)]})

    decision = policy.decide("read_file", path=str(tmp_path / "other" / "token.txt"))

    assert decision.type == DecisionType.ALLOW


def test_shell_pattern_matches_tokens_not_substrings():
    policy = Policy({"blocked_commands": ["curl"]})

    allowed = policy.decide("shell", command="python -c 'print(\"curling\")'")
    blocked = policy.decide("shell", command="curl https://example.com")

    assert allowed.type == DecisionType.ALLOW
    assert blocked.type == DecisionType.BLOCK


def test_allows_wildcard_domain():
    policy = Policy({"allowed_domains": ["*.example.com"]})
    decision = policy.decide("http_post", url="https://api.example.com/upload")
    assert decision.type == DecisionType.ALLOW


def test_blocks_invalid_url():
    policy = Policy({"allowed_domains": ["localhost"]})
    decision = policy.decide("http_post", url="not-a-url")
    assert decision.type == DecisionType.BLOCK


def test_rejects_invalid_policy_shape():
    try:
        Policy({"protected_paths": ".env"})
    except ValueError as exc:
        assert "protected_paths must be a list" in str(exc)
    else:
        raise AssertionError("expected invalid policy to raise")


def test_rejects_unknown_policy_key():
    try:
        Policy({"unknown": []})
    except ValueError as exc:
        assert "unknown policy keys" in str(exc)
    else:
        raise AssertionError("expected invalid policy to raise")


def test_open_uses_pathname_policy():
    policy = Policy({"protected_paths": [".env"]})
    decision = policy.decide("open", pathname="repo/.env")
    assert decision.type == DecisionType.BLOCK


def test_connect_uses_host_policy():
    policy = Policy({"allowed_domains": ["127.0.0.1"]})

    allowed = policy.decide("connect", host="127.0.0.1")
    blocked = policy.decide("connect", host="8.8.8.8")

    assert allowed.type == DecisionType.ALLOW
    assert blocked.type == DecisionType.BLOCK


def test_policy_summary_includes_v1_fields():
    policy = Policy({"allowed_env_vars": ["PATH"], "max_file_size_mb": 5})
    summary = policy.summary()

    assert summary["allowed_env_vars"] == ["PATH"]
    assert summary["max_file_size_mb"] == 5
