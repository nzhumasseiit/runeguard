"""
RuneGuard seccomp-BPF enforcement.

Builds a Linux seccomp filter from RuneGuard policy and applies it to the
current process using prctl(). All child processes inherit the filter.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import platform
import struct

from ..policy import Policy


SECCOMP_MODE_FILTER = 2
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22

BPF_LD  = 0x00
BPF_JMP = 0x05
BPF_RET = 0x06

BPF_W   = 0x00
BPF_ABS = 0x20
BPF_JEQ = 0x10

SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000

ERRNO_EPERM = 1

# Offset of seccomp_data.nr (syscall number)
SECCOMP_DATA_NR_OFFSET = 0
# Offset of seccomp_data.args[0] (first syscall argument, u64 little-endian)
SECCOMP_DATA_ARGS0_OFFSET = 16

# Socket address families we block when network policy is deny.
# AF_UNIX (1) is intentionally NOT blocked — Python stdlib and the
# RuneGuard daemon both use Unix domain sockets internally.
AF_INET    = 2
AF_INET6   = 10
AF_NETLINK = 16

# Syscall numbers keyed by platform.machine() return value.
# Add new architectures here; apply() rejects anything not listed.
_SYSCALL_NR: dict[str, dict[str, int]] = {
    "x86_64": {
        "ptrace":      101,
        "kexec_load":  246,
        "reboot":      169,
        "mount":       165,
        "socket":       41,
    },
    "aarch64": {
        "ptrace":      117,
        "kexec_load":  104,
        "reboot":      142,
        "mount":        40,
        "socket":      198,
    },
}


def _bpf_stmt(code: int, k: int) -> bytes:
    return struct.pack("HBBI", code, 0, 0, k)


def _bpf_jump(code: int, k: int, jt: int, jf: int) -> bytes:
    return struct.pack("HBBI", code, jt, jf, k)


def _ld_nr() -> bytes:
    """Load syscall number into accumulator."""
    return _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET)


def _ld_args0() -> bytes:
    """Load args[0] (lower 32 bits) into accumulator."""
    return _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARGS0_OFFSET)


def _jeq(k: int, jt: int, jf: int = 0) -> bytes:
    return _bpf_jump(BPF_JMP | BPF_JEQ | BPF_W, k, jt, jf)


def _allow() -> bytes:
    return _bpf_stmt(BPF_RET, SECCOMP_RET_ALLOW)


def _block(errno: int = ERRNO_EPERM) -> bytes:
    return _bpf_stmt(BPF_RET, SECCOMP_RET_ERRNO | (errno & 0xFFFF))


class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt",   ctypes.c_ubyte),
        ("jf",   ctypes.c_ubyte),
        ("k",    ctypes.c_uint),
    ]


class SockFprog(ctypes.Structure):
    _fields_ = [
        ("len",    ctypes.c_ushort),
        ("filter", ctypes.POINTER(SockFilter)),
    ]


class SeccompFilter:
    """
    Builds and applies a seccomp-BPF filter.

    Dangerous-syscall blocklist (both arches):
      ptrace, kexec_load, reboot, mount

    Network deny (socket family check):
      socket(AF_INET)    → BLOCK
      socket(AF_INET6)   → BLOCK
      socket(AF_NETLINK) → BLOCK
      socket(AF_UNIX)    → ALLOW  (Python IPC + RuneGuard daemon)
      socket(other)      → ALLOW
    """

    def __init__(self, policy: Policy):
        self.policy = policy

    def build(self, arch: str | None = None) -> bytes:
        """
        Build the BPF program for the given arch (defaults to current machine).
        Raises RuntimeError for unsupported architectures.
        """
        machine = arch or platform.machine()
        nrs = _SYSCALL_NR.get(machine)
        if nrs is None:
            raise RuntimeError(
                f"seccomp-BPF is not supported on architecture '{machine}'. "
                f"Supported: {', '.join(_SYSCALL_NR)}"
            )

        dangerous = [nrs["ptrace"], nrs["kexec_load"], nrs["reboot"], nrs["mount"]]
        instructions = self._linear_block_filter(dangerous)

        if self.policy.network in {"deny", "deny_all", "none"}:
            instructions += self._socket_family_block_filter(nrs["socket"])

        return b"".join(instructions)

    def apply(self) -> None:
        if platform.system() != "Linux":
            raise RuntimeError("seccomp-BPF is Linux-only")

        program_bytes = self.build()
        filters = self._program_to_filters(program_bytes)
        program = SockFprog(len=len(filters), filter=filters)

        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            raise RuntimeError("cannot find libc")

        libc = ctypes.CDLL(libc_name, use_errno=True)

        ret = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        if ret != 0:
            raise RuntimeError(f"prctl(PR_SET_NO_NEW_PRIVS) failed: errno {ctypes.get_errno()}")

        ret = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0)
        if ret != 0:
            raise RuntimeError(f"prctl(PR_SET_SECCOMP) failed: errno {ctypes.get_errno()}")

    def _linear_block_filter(self, syscall_nrs: list[int]) -> list[bytes]:
        """
        Block a list of syscalls by number.

        Program layout:
          [0]     ld  nr
          [1..N]  jeq nr_i → block
          [N+1]   ret ALLOW
          [N+2]   ret BLOCK
        """
        instructions = [_ld_nr()]
        for index, nr in enumerate(syscall_nrs):
            remaining = len(syscall_nrs) - index - 1
            instructions.append(_jeq(nr, jt=remaining + 1, jf=0))
        instructions.append(_allow())
        instructions.append(_block())
        return instructions

    def _socket_family_block_filter(self, sys_socket_nr: int) -> list[bytes]:
        """
        Block socket() calls for internet families; allow AF_UNIX.

        Program layout:
          [0]  ld  nr
          [1]  jeq SYS_SOCKET → [3], else → [2]
          [2]  ret ALLOW             (not socket, this sub-filter allows)
          [3]  ld  args[0]           (socket family)
          [4]  jeq AF_INET    → [8]
          [5]  jeq AF_INET6   → [8]
          [6]  jeq AF_NETLINK → [8]
          [7]  ret ALLOW             (AF_UNIX or other allowed family)
          [8]  ret BLOCK
        """
        return [
            _ld_nr(),
            _jeq(sys_socket_nr, jt=1, jf=0),   # [1] → [3] if socket, else [2]
            _allow(),                            # [2] not socket → allow
            _ld_args0(),                         # [3] load family
            _jeq(AF_INET,    jt=3, jf=0),        # [4] → [8] if AF_INET
            _jeq(AF_INET6,   jt=2, jf=0),        # [5] → [8] if AF_INET6
            _jeq(AF_NETLINK, jt=1, jf=0),        # [6] → [8] if AF_NETLINK
            _allow(),                            # [7] allowed family (AF_UNIX etc.)
            _block(),                            # [8] blocked family
        ]

    def _program_to_filters(self, program_bytes: bytes) -> ctypes.Array:
        if len(program_bytes) % ctypes.sizeof(SockFilter) != 0:
            raise ValueError("invalid BPF program length")
        count = len(program_bytes) // ctypes.sizeof(SockFilter)
        return (SockFilter * count).from_buffer_copy(program_bytes)


def apply_seccomp_from_policy(policy: Policy) -> None:
    SeccompFilter(policy).apply()
