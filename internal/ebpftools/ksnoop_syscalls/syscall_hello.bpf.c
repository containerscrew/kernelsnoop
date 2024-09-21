//go:build ignore

#include "../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";
struct connection_info {
    u64 pid; // Change to u64
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct connection_info);
} kprobe_map SEC(".maps");

SEC("kprobe/sys_connect")
int kprobe_sys_connect() {
    u32 key = 0;
    struct connection_info info;

    // Get the current PID and program name
    info.pid = bpf_get_current_pid_tgid() >> 32; // Extract PID
    bpf_get_current_comm(info.comm, sizeof(info.comm)); // Get program name

    // Update the map with the connection info
    bpf_map_update_elem(&kprobe_map, &key, &info, BPF_ANY);

    return 0;
}
