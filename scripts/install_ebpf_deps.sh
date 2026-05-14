#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "RuneGuard eBPF dependencies are Linux-only." >&2
  exit 2
fi

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev make gcc
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y clang llvm bpftool libbpf-devel elfutils-libelf-devel zlib-devel make gcc
else
  echo "Install clang, bpftool, libbpf headers, libelf, zlib, make, and gcc with your distro package manager." >&2
  exit 1
fi

make -C ebpf
make -C ebpf install-package
