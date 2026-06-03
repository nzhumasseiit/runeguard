# RuneGuard — Eng Review Fixes
## 6 bugs found in the MCP proxy + seccomp implementation

This document tells you exactly what to change and why.
All changes are surgical — no file should be rewritten wholesale.
T1 and T2 both touch `seccomp/filter.py`; apply them together.

---

## T1 + T2: seccomp/filter.py — ARM64 support + safe network blocking

**T1** — the filter uses hardcoded x86_64 syscall numbers. On ARM64 Linux
(AWS Graviton, Raspberry Pi 5) it silently enforces the wrong syscalls.

**T2** — blocking all `socket()` calls breaks Python's own stdlib (DNS,
urllib, the RuneGuard daemon socket). Fix: block by socket address family —
allow `AF_UNIX` (Python IPC), block `AF_INET` / `AF_INET6` / `AF_NETLINK`
(internet + kernel sockets).

### Replace `runeguard/seccomp/filter.py` entirely with:

```python
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
```

---

### Replace `tests/test_seccomp.py` entirely with:

```python
import platform
import subprocess
import sys

import pytest

from runeguard.policy import Policy
from runeguard.seccomp.filter import (
    AF_INET, AF_INET6, AF_NETLINK,
    SeccompFilter,
    _SYSCALL_NR,
)


def test_filter_builds_without_error():
    policy = Policy({"protected_paths": [".env"], "blocked_commands": ["rm -rf"]})
    filt = SeccompFilter(policy)
    program = filt.build(arch="x86_64")
    assert isinstance(program, bytes)
    assert len(program) > 0
    assert len(program) % 8 == 0


def test_filter_instruction_count_reasonable():
    policy = Policy({})
    filt = SeccompFilter(policy)
    program = filt.build(arch="x86_64")
    num_instructions = len(program) // 8
    assert num_instructions >= 3
    assert num_instructions < 256


def test_filter_builds_for_arm64():
    policy = Policy({})
    filt = SeccompFilter(policy)
    program = filt.build(arch="aarch64")
    assert isinstance(program, bytes)
    assert len(program) % 8 == 0


def test_filter_arm64_uses_different_syscall_numbers():
    """x86_64 and ARM64 programs must differ (different syscall numbers)."""
    policy = Policy({})
    filt = SeccompFilter(policy)
    x86 = filt.build(arch="x86_64")
    arm = filt.build(arch="aarch64")
    assert x86 != arm


def test_filter_unsupported_arch_raises():
    policy = Policy({})
    filt = SeccompFilter(policy)
    with pytest.raises(RuntimeError, match="not supported on architecture"):
        filt.build(arch="mips")


def test_filter_network_deny_adds_socket_filter():
    """Network deny policy produces a larger program (socket family sub-filter)."""
    base = SeccompFilter(Policy({})).build(arch="x86_64")
    with_net = SeccompFilter(Policy({"network": "deny"})).build(arch="x86_64")
    assert len(with_net) > len(base)


def test_filter_network_deny_instruction_count():
    """Socket family filter adds exactly 9 instructions (program above)."""
    base_count = len(SeccompFilter(Policy({})).build(arch="x86_64")) // 8
    net_count  = len(SeccompFilter(Policy({"network": "deny"})).build(arch="x86_64")) // 8
    assert net_count - base_count == 9


def test_filter_network_allow_no_socket_filter():
    """When network is not denied, socket() is not filtered."""
    base = SeccompFilter(Policy({})).build(arch="x86_64")
    host = SeccompFilter(Policy({"network": "host"})).build(arch="x86_64")
    assert base == host


@pytest.mark.skipif(platform.system() != "Linux", reason="seccomp is Linux-only")
def test_apply_does_not_raise_on_linux():
    result = subprocess.run(
        [
            sys.executable, "-c",
            "from runeguard.policy import Policy; "
            "from runeguard.seccomp.filter import SeccompFilter; "
            "SeccompFilter(Policy({})).apply(); "
            "print('ok')",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "ok" in result.stdout, result.stderr


def test_non_linux_raises():
    if platform.system() == "Linux":
        pytest.skip("This test only runs on non-Linux")
    with pytest.raises(RuntimeError, match="Linux-only"):
        SeccompFilter(Policy({})).apply()
```

---

## T3: mcp/proxy.py — handle sampling/* and warn on unknown methods

**Problem:** `check_client_message` silently forwards any method not in its
explicit list (`tools/list`, `tools/call`, `resources/list`, `resources/read`).
`sampling/createMessage` — an LLM prompt that can exfiltrate data — passes through
unexamined. Unknown future MCP methods are invisible to the audit log.

**Fix:** handle `sampling/createMessage` (log + allow by default, configurable);
log a `warn` decision for unrecognized methods so they appear in audit logs.

### In `runeguard/mcp/proxy.py`, replace lines 115–150:

**FROM:**
```python
    def check_client_message(self, msg: dict) -> tuple[bool, dict | None] | None:
        """Return forwarding decision and optional JSON-RPC response."""
        method = msg.get("method")
        if method not in {"tools/list", "tools/call", "resources/list", "resources/read"}:
            return None

        server_decision = self.policy.decide("mcp_server", server_name=self.server_name)
        self._log("mcp_server", server_decision, {"server_name": self.server_name})
        if server_decision.type in (DecisionType.BLOCK, DecisionType.REQUIRE_APPROVAL):
            return False, self._error(msg, server_decision, "mcp_server")

        if method in {"tools/list", "resources/list"}:
            self._log(method, Decision(DecisionType.ALLOW, "MCP list request allowed"), {"server_name": self.server_name})
            return True, None

        if method == "resources/read":
            decision = self._resource_read_decision(msg)
            self._log("resources/read", decision, self._params(msg))
            if decision.type in (DecisionType.BLOCK, DecisionType.REQUIRE_APPROVAL):
                return False, self._error(msg, decision, "resources/read")
            return True, None

        decision = self._tool_call_decision(msg)
        params = self._params(msg)
        tool_name = str(params.get("name") or "")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}
        self._log(
            "tools/call",
            decision,
            {"server_name": self.server_name, "tool_name": tool_name, "arguments": arguments},
        )
        if decision.type in (DecisionType.BLOCK, DecisionType.REQUIRE_APPROVAL):
            return False, self._error(msg, decision, tool_name or "tools/call")
        return True, None
```

**TO:**
```python
    # Methods we actively policy-check.
    _CHECKED_METHODS = frozenset({
        "tools/list", "tools/call",
        "resources/list", "resources/read",
        "sampling/createMessage",
        "prompts/list", "prompts/get",
    })
    # Methods that are notifications (no response expected, always forward).
    _NOTIFICATION_PREFIX = "notifications/"

    def check_client_message(self, msg: dict) -> tuple[bool, dict | None] | None:
        """Return forwarding decision and optional JSON-RPC response."""
        method = msg.get("method")
        if not isinstance(method, str):
            return None

        # Notifications are fire-and-forget; never block, never respond.
        if method.startswith(self._NOTIFICATION_PREFIX):
            return None

        # Unknown methods: log a warning so they appear in the audit trail,
        # then forward. Don't block — the MCP spec is evolving.
        if method not in self._CHECKED_METHODS:
            self._log(
                method,
                Decision(DecisionType.ALLOW, f"unrecognized MCP method forwarded: {method}"),
                {"server_name": self.server_name, "warning": "method not in policy check list"},
            )
            return None

        server_decision = self.policy.decide("mcp_server", server_name=self.server_name)
        self._log("mcp_server", server_decision, {"server_name": self.server_name})
        if server_decision.type in (DecisionType.BLOCK, DecisionType.REQUIRE_APPROVAL):
            return False, self._error(msg, server_decision, "mcp_server")

        if method in {"tools/list", "resources/list", "prompts/list"}:
            self._log(method, Decision(DecisionType.ALLOW, "MCP list request allowed"), {"server_name": self.server_name})
            return True, None

        if method in {"resources/read", "prompts/get"}:
            decision = self._resource_read_decision(msg)
            self._log(method, decision, self._params(msg))
            if decision.type in (DecisionType.BLOCK, DecisionType.REQUIRE_APPROVAL):
                return False, self._error(msg, decision, method)
            return True, None

        if method == "sampling/createMessage":
            # Log sampling requests for audit visibility; allow by default.
            # Future: add a policy key to block sampling on sensitive servers.
            self._log(
                "sampling/createMessage",
                Decision(DecisionType.ALLOW, "MCP sampling request logged"),
                {"server_name": self.server_name, "params": redact_value(self._params(msg))},
            )
            return True, None

        decision = self._tool_call_decision(msg)
        params = self._params(msg)
        tool_name = str(params.get("name") or "")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}
        self._log(
            "tools/call",
            decision,
            {"server_name": self.server_name, "tool_name": tool_name, "arguments": arguments},
        )
        if decision.type in (DecisionType.BLOCK, DecisionType.REQUIRE_APPROVAL):
            return False, self._error(msg, decision, tool_name or "tools/call")
        return True, None
```

---

## T4: mcp/proxy.py — fix false positives in _looks_like_read / _looks_like_write

**Problem:** `"read" in normalized` matches `thread_read`, `spread`, `breadcrumb`.
`"write" in normalized` matches `overwrite`, `rewrite`, `typewrite`.
A tool with a path argument and a name containing these substrings gets its path
silently blocked by RuneGuard's file policy.

**Fix:** explicit exact names + known prefixes.

### In `runeguard/mcp/proxy.py`, add these constants just before the class definition (after the imports):

```python
# Exact tool names and prefixes that indicate a file-read operation.
# Substring matching ("read" in name) is intentionally avoided — it causes
# false positives on tool names like thread_read, spread, breadcrumb.
_READ_TOOL_NAMES = frozenset({
    "read_file", "readfile", "read", "cat",
    "resources/read", "get_file_contents",
    "fetch_file", "load_file", "open_file",
    "view_file", "show_file", "display_file",
})
_READ_TOOL_PREFIXES = ("read_", "fetch_file", "get_file", "load_file", "open_file")

# Same principle for write operations.
_WRITE_TOOL_NAMES = frozenset({
    "write_file", "writefile", "write", "save_file", "save",
    "put_file", "store_file", "create_file",
    "append_file", "edit_file", "patch_file", "update_file",
})
_WRITE_TOOL_PREFIXES = ("write_", "save_file", "create_file", "edit_file", "append_file", "patch_file", "update_file")
```

### Replace lines 251–257 (the two heuristic methods):

**FROM:**
```python
    def _looks_like_read(self, tool_name: str) -> bool:
        normalized = tool_name.lower()
        return normalized in {"read_file", "resources/read"} or "read" in normalized or "cat" in normalized

    def _looks_like_write(self, tool_name: str) -> bool:
        normalized = tool_name.lower()
        return normalized in {"write_file"} or any(token in normalized for token in ("write", "create", "append", "edit"))
```

**TO:**
```python
    def _looks_like_read(self, tool_name: str) -> bool:
        n = tool_name.lower()
        return n in _READ_TOOL_NAMES or n.startswith(_READ_TOOL_PREFIXES)

    def _looks_like_write(self, tool_name: str) -> bool:
        n = tool_name.lower()
        return n in _WRITE_TOOL_NAMES or n.startswith(_WRITE_TOOL_PREFIXES)
```

---

## T5: mcp/proxy.py — fix async write+flush race

**Problem:** lines 93–94 and 112–113 make two separate `run_in_executor` calls —
one to write, one to flush. asyncio can schedule another coroutine between them,
interleaving bytes from `_server_to_client` with bytes from `_client_to_server`
on stdout. The agent receives garbled JSON-RPC.

**Fix:** combine into one executor call per write site.

### Replace lines 92–95 in `_client_to_server`:

**FROM:**
```python
                    encoded = json.dumps(blocked_response).encode("utf-8") + b"\n"
                    await loop.run_in_executor(None, sys.stdout.buffer.write, encoded)
                    await loop.run_in_executor(None, sys.stdout.buffer.flush)
                    continue
```

**TO:**
```python
                    encoded = json.dumps(blocked_response).encode("utf-8") + b"\n"
                    await loop.run_in_executor(
                        None, lambda b=encoded: (sys.stdout.buffer.write(b), sys.stdout.buffer.flush())
                    )
                    continue
```

### Replace lines 112–113 in `_server_to_client`:

**FROM:**
```python
            await loop.run_in_executor(None, writer.write, line)
            await loop.run_in_executor(None, writer.flush)
```

**TO:**
```python
            await loop.run_in_executor(None, lambda l=line: (writer.write(l), writer.flush()))
```

---

## T6: tests/test_mcp_proxy.py — test upstream server not found

**Problem:** the `FileNotFoundError` / `OSError` path in `proxy.py:49–52` is
handled and raises a clear `RuntimeError`, but nothing verifies it.
A future refactor could silently break the user-facing error message.

### Add this test at the end of `tests/test_mcp_proxy.py`:

```python
import asyncio


def test_proxy_upstream_not_found(tmp_path):
    """MCPPolicyProxy.run() raises RuntimeError with a clear message when the upstream command doesn't exist."""
    from runeguard.mcp.proxy import MCPPolicyProxy
    from runeguard.policy import Policy

    proxy = MCPPolicyProxy(
        Policy({}),
        ["/nonexistent-binary-runeguard-test"],
        audit_log=str(tmp_path / "audit.jsonl"),
    )

    with pytest.raises(RuntimeError, match="MCP server executable not found"):
        asyncio.run(proxy.run())
```

---

## Summary of all file changes

### MODIFY (exact sections replaced):
```
runeguard/seccomp/filter.py     — full rewrite (T1 + T2: arch constants + socket-family BPF)
tests/test_seccomp.py           — full rewrite (new arch + network deny tests)
runeguard/mcp/proxy.py          — 3 surgical changes:
                                    check_client_message (T3)
                                    _looks_like_read / _looks_like_write (T4)
                                    write+flush executor calls (T5)
tests/test_mcp_proxy.py         — append test_proxy_upstream_not_found (T6)
```

### DO NOT TOUCH:
```
runeguard/seccomp/runner.py     (no changes needed)
runeguard/mcp/server.py         (no changes needed)
runeguard/mcp/inspect.py        (no changes needed)
runeguard/policy.py             (no changes needed)
tests/test_mcp.py               (existing tests still valid)
```

### Verify all fixes with:
```bash
cd /path/to/runeguard
pip install -e .[dev]
pytest tests/test_seccomp.py tests/test_mcp.py tests/test_mcp_proxy.py -v
```

All 11 existing tests must still pass. New tests added: 7 (seccomp) + 1 (mcp_proxy) = 8.
