from pathlib import Path
from bcc import BPF


def hello_world_ebpf():
    script_dir = Path(__file__).parent
    c_file_path = script_dir / "hello_world.ebpf.c"
    bpf = BPF(src_file=str(c_file_path), debug=0)

    syscall = bpf.get_syscall_fnname("execve")
    bpf.attach_kprobe(event=syscall, fn_name="hello")

    bpf.trace_print()
