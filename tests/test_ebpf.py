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
