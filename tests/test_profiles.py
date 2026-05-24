from runeguard.policy import Policy


def test_ci_profile_loads_expected_fields():
    policy = Policy.from_profile("ci")

    assert policy.network == "deny"
    assert policy.blocked_commands == ["curl", "wget", "nc", "ssh", "scp", "git clone"]
    assert policy.protected_paths == [
        ".env",
        "*.key",
        "*.pem",
        ".ssh/",
        "/etc/passwd",
        "/etc/shadow",
    ]
    assert policy.allowed_paths == ["**"]
    assert policy.readonly_rootfs is True
    assert policy.allowed_env_vars == ["CI", "GITHUB_ACTIONS", "RUNNER_OS"]
    assert policy.env_var_strip_pattern == ["AWS_*", "GITHUB_TOKEN", "*_SECRET", "*_KEY"]
