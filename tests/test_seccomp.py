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
    """Network deny policy produces a larger program (socket family sub-filter).

    Note: RuneGuard's default network policy is ``deny``, so an explicitly
    network-allowed policy (``host``) is used as the no-socket-filter baseline.
    """
    base = SeccompFilter(Policy({"network": "host"})).build(arch="x86_64")
    with_net = SeccompFilter(Policy({"network": "deny"})).build(arch="x86_64")
    assert len(with_net) > len(base)


def test_filter_network_deny_instruction_count():
    """Socket family filter adds exactly 9 instructions (program above)."""
    base_count = len(SeccompFilter(Policy({"network": "host"})).build(arch="x86_64")) // 8
    net_count  = len(SeccompFilter(Policy({"network": "deny"})).build(arch="x86_64")) // 8
    assert net_count - base_count == 9


def test_filter_network_allow_no_socket_filter():
    """When network is not denied, socket() is not filtered."""
    host = SeccompFilter(Policy({"network": "host"})).build(arch="x86_64")
    bridge = SeccompFilter(Policy({"network": "bridge"})).build(arch="x86_64")
    assert host == bridge


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
