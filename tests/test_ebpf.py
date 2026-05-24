import subprocess
from pathlib import Path

import pytest

from runeguard.ebpf import EbpfConfig, EbpfTracer


def test_ebpf_loader_resolution_uses_explicit_path(tmp_path):
    loader = tmp_path / "runeguard-ebpf-loader"
    loader.write_text("#!/bin/sh\n", encoding="utf-8")

    resolved = EbpfTracer(EbpfConfig(loader_path=loader))._resolve_loader()

    assert resolved == loader


def test_ebpf_loader_resolution_fails_with_helpful_message(monkeypatch):
    monkeypatch.setattr("runeguard.ebpf.loader.shutil.which", lambda name: None)

    with pytest.raises(RuntimeError, match="Build it with `make -C ebpf`"):
        EbpfTracer()._resolve_loader()


def test_ebpf_start_populates_blocked_paths_file_for_loader(monkeypatch, tmp_path):
    loader = tmp_path / "runeguard-ebpf-loader"
    loader.write_text("#!/bin/sh\n", encoding="utf-8")
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
version: 1
files:
  deny:
    - /workspace/.env
    - /workspace/secrets/
""".lstrip(),
        encoding="utf-8",
    )
    captured = {}

    def fake_run(argv, check):
        blocked_paths = Path(argv[2])
        captured["argv"] = argv
        captured["blocked_paths"] = blocked_paths.read_text(encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("runeguard.ebpf.loader.platform.system", lambda: "Linux")
    monkeypatch.setattr("runeguard.ebpf.loader.subprocess.run", fake_run)

    rc = EbpfTracer(
        EbpfConfig(mode="enforce", policy=str(policy), loader_path=loader)
    ).start()

    assert rc == 0
    assert captured["argv"][0] == str(loader)
    assert captured["argv"][1] == "enforce"
    assert captured["argv"][3:] == ["--policy", str(policy)]
    assert captured["blocked_paths"] == "/workspace/.env\n/workspace/secrets/\n"
