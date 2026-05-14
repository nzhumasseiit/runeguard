# RuneGuard eBPF

RuneGuard uses a libbpf/CO-RE loader for Linux syscall visibility and a BPF LSM
exec enforcement path for kernels with BPF LSM support. Enforcement mode seeds a
kernel map with blocked executable names such as `rm`, `curl`, `nc`, `scp`, and
`ssh`; Landlock handles filesystem MAC.

Build on Linux:

```bash
scripts/install_ebpf_deps.sh
```

Or directly:

```bash
make -C ebpf
make -C ebpf install-package
```

Run:

```bash
runeguard ebpf trace --policy policies/default.yaml
runeguard ebpf enforce --policy policies/default.yaml
```

Notes:

- BCC is not used at runtime.
- The loader expects `/sys/kernel/btf/vmlinux` for CO-RE builds.
- Loading eBPF programs requires the kernel capabilities and LSM configuration
  normally required by the host distribution.
