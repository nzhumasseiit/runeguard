import json
from subprocess import CompletedProcess

from runeguard.decision import DecisionType
from runeguard.opa import OpaConfig, OpaPolicyBackend
from runeguard.policy import Policy


def test_opa_backend_allows_boolean_result(monkeypatch, tmp_path):
    policy_path = tmp_path / "policy.rego"
    policy_path.write_text("package runeguard\nallow := true\n", encoding="utf-8")

    def fake_run(argv, input, text, capture_output, check):
        assert "--stdin-input" in argv
        assert json.loads(input)["tool"] == "shell"
        return CompletedProcess(argv, 0, stdout=json.dumps({"result": [{"expressions": [{"value": True}]}]}), stderr="")

    monkeypatch.setattr("runeguard.opa.shutil.which", lambda command: "/usr/bin/opa")
    monkeypatch.setattr("runeguard.opa.subprocess.run", fake_run)

    decision = OpaPolicyBackend(OpaConfig(policy=str(policy_path))).decide("shell", {"command": "echo hi"})

    assert decision.type == DecisionType.ALLOW


def test_policy_opa_backend_blocks_when_opa_missing(monkeypatch, tmp_path):
    policy_path = tmp_path / "policy.rego"
    policy_path.write_text("package runeguard\nallow := true\n", encoding="utf-8")
    monkeypatch.setattr("runeguard.opa.shutil.which", lambda command: None)

    policy = Policy(
        {
            "policy": {"backend": "opa"},
            "opa": {"policy": str(policy_path)},
        }
    )
    decision = policy.decide("shell", command="echo hi")

    assert decision.type == DecisionType.BLOCK
    assert "OPA executable not found" in decision.reason
