import ctypes
import ctypes.util
import os
import platform
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from runeguard.decision import DecisionType
from runeguard.policy import Policy


SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446

PR_SET_NO_NEW_PRIVS = 38
LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_CREATE_RULESET_VERSION = 1

LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14

READ_ACCESS = (
    LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
)
WRITE_ACCESS = (
    LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE
)
HANDLED_ACCESS = READ_ACCESS | WRITE_ACCESS


class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int),
    ]


@dataclass(frozen=True)
class LandlockConfig:
    workspace: Path = Path.cwd()
    allow_weak_fallback: bool = False


class LandlockUnavailable(RuntimeError):
    pass


class LandlockSandboxRunner:
    """Runs commands under Linux Landlock filesystem restrictions."""

    def __init__(self, policy: Policy, config: LandlockConfig | None = None):
        self.policy = policy
        self.config = config or LandlockConfig()

    def run(self, argv: list[str]) -> int:
        decision = self.policy.decide("shell", command=" ".join(argv), argv=argv)
        if decision.type != DecisionType.ALLOW:
            raise PermissionError(decision.reason)

        if not landlock_available():
            if self.config.allow_weak_fallback:
                return subprocess.run(argv, cwd=self.workspace, check=False).returncode
            raise LandlockUnavailable(
                "Landlock is unavailable. Fix: run on Linux kernel >= 5.13 with Landlock enabled, or pass --allow-weak-fallback for policy-only execution."
            )

        with tempfile.TemporaryDirectory(prefix="runeguard-landlock-") as tmpdir:
            filtered = Path(tmpdir) / "workspace"
            filtered.mkdir()
            self._copy_filtered_workspace(filtered)
            return _fork_exec_with_landlock(argv, self.policy, self.workspace, filtered)

    @property
    def workspace(self) -> Path:
        return Path(self.config.workspace).expanduser().resolve(strict=True)

    def _copy_filtered_workspace(self, destination: Path):
        workspace = self.workspace
        for source in workspace.rglob("*"):
            relative = source.relative_to(workspace)
            relative_text = str(relative).replace(os.sep, "/")
            if self.policy.is_denied_workspace_path(relative_text):
                continue
            if not self.policy.is_allowed_workspace_path(relative_text):
                continue

            target = destination / relative
            if source.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def landlock_available() -> bool:
    if platform.system() != "Linux":
        return False

    libc = _libc()
    if libc is None:
        return False

    version = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, 0, 0, LANDLOCK_CREATE_RULESET_VERSION)
    return version >= 1


def _fork_exec_with_landlock(argv: list[str], policy: Policy, workspace: Path, filtered: Path) -> int:
    child_pid = os.fork()
    if child_pid == 0:
        try:
            apply_landlock(policy, workspace, filtered)
            os.chdir(filtered)
            os.execvp(argv[0], argv)
        except Exception as exc:
            print(f"[RuneGuard] Landlock setup failed: {exc}", file=os.sys.stderr)
            os._exit(1)

    _, status = os.waitpid(child_pid, 0)
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 1


def apply_landlock(policy: Policy, workspace: Path, filtered: Path):
    libc = _libc()
    if libc is None:
        raise LandlockUnavailable("libc unavailable")

    ruleset_attr = LandlockRulesetAttr(HANDLED_ACCESS)
    ruleset_fd = libc.syscall(
        SYS_LANDLOCK_CREATE_RULESET,
        ctypes.byref(ruleset_attr),
        ctypes.sizeof(ruleset_attr),
        0,
    )
    if ruleset_fd < 0:
        raise LandlockUnavailable("landlock_create_ruleset failed")

    try:
        _add_path_rule(libc, ruleset_fd, filtered, READ_ACCESS)
        for writable_path in policy.writable_paths:
            source = Path(os.path.expanduser(writable_path))
            if not source.is_absolute():
                source = workspace / source
            if source.exists():
                _add_path_rule(libc, ruleset_fd, source.resolve(strict=True), READ_ACCESS | WRITE_ACCESS)

        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise LandlockUnavailable("prctl(PR_SET_NO_NEW_PRIVS) failed")

        if libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0:
            raise LandlockUnavailable("landlock_restrict_self failed")
    finally:
        os.close(ruleset_fd)


def _add_path_rule(libc, ruleset_fd: int, path: Path, access: int):
    fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    try:
        rule = LandlockPathBeneathAttr(access, fd)
        result = libc.syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            ctypes.byref(rule),
            0,
        )
        if result != 0:
            raise LandlockUnavailable(f"landlock_add_rule failed for {path}")
    finally:
        os.close(fd)


def _libc():
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        return None
    return ctypes.CDLL(libc_name, use_errno=True)
