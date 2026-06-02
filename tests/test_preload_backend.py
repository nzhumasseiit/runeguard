from pathlib import Path

from runeguard.core.interceptor import InterceptorConfig, RuneGuardInterceptor


def test_preload_environment_sets_policy_audit_and_inherits_existing_preload(tmp_path, monkeypatch):
    shim = tmp_path / "rg_preload.so"
    shim.touch()
    monkeypatch.setattr("runeguard.core.interceptor.platform.system", lambda: "Linux")

    env = RuneGuardInterceptor(
        InterceptorConfig(
            shim_path=shim,
            socket_path="/tmp/runeguard-test.sock",
            policy_path="runeguard.yaml",
            audit_log=".runeguard/audit.jsonl",
        )
    ).env({"LD_PRELOAD": "/lib/existing.so", "KEEP": "1"})

    assert env["LD_PRELOAD"] == f"{shim} /lib/existing.so"
    assert env["RUNEGUARD_POLICY"] == "runeguard.yaml"
    assert env["RUNEGUARD_AUDIT"] == ".runeguard/audit.jsonl"
    assert env["RUNEGUARD_SOCKET"] == "/tmp/runeguard-test.sock"
    assert env["KEEP"] == "1"
