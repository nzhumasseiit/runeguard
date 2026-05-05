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
