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

BPF_LD = 0x00
BPF_JMP = 0x05
BPF_RET = 0x06

BPF_W = 0x00
BPF_ABS = 0x20
BPF_JEQ = 0x10

SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000

ERRNO_EPERM = 1
SECCOMP_DATA_NR_OFFSET = 0

SYS_PTRACE = 101
SYS_KEXEC_LOAD = 246
SYS_REBOOT = 169
SYS_MOUNT = 165
SYS_SOCKET = 41
SYS_CONNECT = 42
SYS_ACCEPT = 43
SYS_ACCEPT4 = 288
SYS_BIND = 49
SYS_LISTEN = 50


def _bpf_stmt(code: int, k: int) -> bytes:
    return struct.pack("HBBI", code, 0, 0, k)


def _bpf_jump(code: int, k: int, jt: int, jf: int) -> bytes:
    return struct.pack("HBBI", code, jt, jf, k)


def _ld_syscall_nr() -> bytes:
    return _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET)


def _allow() -> bytes:
    return _bpf_stmt(BPF_RET, SECCOMP_RET_ALLOW)


def _block(errno: int = ERRNO_EPERM) -> bytes:
    return _bpf_stmt(BPF_RET, SECCOMP_RET_ERRNO | (errno & 0xFFFF))


class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    ]


class SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(SockFilter)),
    ]


class SeccompFilter:
    """
    Builds and applies a seccomp-BPF filter.

    v1 blocks a small syscall-class set that coding agents should not need:
    ptrace, kexec_load, reboot, and mount. When policy network is denied, it
    also blocks basic network syscalls. Classic seccomp cannot inspect pathname
    strings; path policy belongs in Docker, Landlock, preload, or future
    seccomp user notification / eBPF LSM integrations.
    """

    def __init__(self, policy: Policy):
        self.policy = policy

    def build(self) -> bytes:
        dangerous_syscalls = [SYS_PTRACE, SYS_KEXEC_LOAD, SYS_REBOOT, SYS_MOUNT]
        if self.policy.network in {"deny", "deny_all", "none"}:
            dangerous_syscalls.extend([
                SYS_SOCKET,
                SYS_CONNECT,
                SYS_ACCEPT,
                SYS_ACCEPT4,
                SYS_BIND,
                SYS_LISTEN,
            ])
        return b"".join(self._linear_block_filter(dangerous_syscalls))

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
            errno = ctypes.get_errno()
            raise RuntimeError(f"prctl(PR_SET_NO_NEW_PRIVS) failed: errno {errno}")

        ret = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0)
        if ret != 0:
            errno = ctypes.get_errno()
            raise RuntimeError(f"prctl(PR_SET_SECCOMP) failed: errno {errno}")

    def _linear_block_filter(self, syscall_nrs: list[int]) -> list[bytes]:
        instructions = [_ld_syscall_nr()]

        for index, syscall_nr in enumerate(syscall_nrs):
            remaining_checks = len(syscall_nrs) - index - 1
            jump_to_block = remaining_checks + 1
            instructions.append(
                _bpf_jump(BPF_JMP | BPF_JEQ | BPF_W, syscall_nr, jump_to_block, 0)
            )

        instructions.append(_allow())
        instructions.append(_block())
        return instructions

    def _program_to_filters(self, program_bytes: bytes):
        if len(program_bytes) % ctypes.sizeof(SockFilter) != 0:
            raise ValueError("invalid BPF program length")

        count = len(program_bytes) // ctypes.sizeof(SockFilter)
        filters_type = SockFilter * count
        return filters_type.from_buffer_copy(program_bytes)


def apply_seccomp_from_policy(policy: Policy) -> None:
    SeccompFilter(policy).apply()
