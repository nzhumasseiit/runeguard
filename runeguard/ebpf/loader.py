import ctypes as ct
import json
import platform
from dataclasses import asdict, dataclass
from pathlib import Path


TASK_COMM_LEN = 16
ARG_LEN = 256


@dataclass
class EbpfEvent:
    pid: int
    uid: int
    event_type: int
    comm: str
    target: str


class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("event_type", ct.c_uint),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("target", ct.c_char * ARG_LEN),
    ]


class EbpfTracer:
    """BCC-based syscall visibility for RuneGuard v1."""

    def __init__(self, probe_path: Path | None = None):
        self.probe_path = probe_path or Path(__file__).with_name("probes") / "syscalls.bpf.c"
        self.bpf = None

    def start(self):
        if platform.system() != "Linux":
            raise RuntimeError("RuneGuard eBPF tracing requires Linux")

        try:
            from bcc import BPF
        except ImportError as exc:
            raise RuntimeError(
                "Python BCC bindings are not installed. Run scripts/install_ebpf_deps.sh on Linux."
            ) from exc

        self.bpf = BPF(src_file=str(self.probe_path))
        self.bpf.attach_kprobe(event=self.bpf.get_syscall_fnname("execve"), fn_name="trace_execve")
        self.bpf.attach_kprobe(event=self.bpf.get_syscall_fnname("openat"), fn_name="trace_openat")
        self.bpf.attach_kprobe(event=self.bpf.get_syscall_fnname("connect"), fn_name="trace_connect")
        self.bpf["events"].open_perf_buffer(self._handle_event)
        print("[RuneGuard eBPF] tracing execve, openat, connect")

        while True:
            self.bpf.perf_buffer_poll()

    def _handle_event(self, cpu, data, size):
        event = self._decode(data)
        print(json.dumps(asdict(event), sort_keys=True))

    def _decode(self, data) -> EbpfEvent:
        raw = ct.cast(data, ct.POINTER(Event)).contents
        return EbpfEvent(
            pid=raw.pid,
            uid=raw.uid,
            event_type=raw.event_type,
            comm=raw.comm.split(b"\0", 1)[0].decode("utf-8", "replace"),
            target=raw.target.split(b"\0", 1)[0].decode("utf-8", "replace"),
        )


def main():
    EbpfTracer().start()


if __name__ == "__main__":
    main()
