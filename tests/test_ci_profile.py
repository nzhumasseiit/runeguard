from runeguard.core.sandbox import filter_child_env
from runeguard.policy import Policy


def test_ci_profile_strips_secret_env_vars_from_child_process_env():
    policy = Policy.from_profile("ci")
    env = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "RUNNER_OS": "Linux",
        "AWS_ACCESS_KEY_ID": "akid",
        "GITHUB_TOKEN": "token",
        "NPM_SECRET": "secret",
        "PRIVATE_KEY": "key",
        "PATH": "/usr/bin",
    }

    filtered = filter_child_env(policy, env)

    assert filtered == {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "RUNNER_OS": "Linux",
    }


def test_env_filter_strips_patterns_without_allowlist():
    policy = Policy({"env_var_strip_pattern": ["AWS_*", "*_SECRET", "*_KEY"]})
    env = {
        "AWS_REGION": "us-east-1",
        "API_SECRET": "secret",
        "PUBLIC_KEY": "public",
        "PATH": "/usr/bin",
    }

    filtered = filter_child_env(policy, env)

    assert filtered == {"PATH": "/usr/bin"}
