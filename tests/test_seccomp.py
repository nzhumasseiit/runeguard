import platform
import subprocess
import sys

import pytest

from runeguard.policy import Policy
from runeguard.seccomp.filter import SeccompFilter


def test_filter_builds_without_error():
    policy = Policy({"protected_paths": [".env"], "blocked_commands": ["rm -rf"]})
    filt = SeccompFilter(policy)
    program = filt.build()
    assert isinstance(program, bytes)
    assert len(program) > 0
    assert len(program) % 8 == 0


def test_filter_instruction_count_reasonable():
    policy = Policy({})
    filt = SeccompFilter(policy)
    program = filt.build()
    num_instructions = len(program) // 8
    assert num_instructions >= 3
    assert num_instructions < 256


@pytest.mark.skipif(platform.system() != "Linux", reason="seccomp is Linux-only")
def test_apply_does_not_raise_on_linux():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
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

    policy = Policy({})
    filt = SeccompFilter(policy)
    with pytest.raises(RuntimeError, match="Linux-only"):
        filt.apply()
