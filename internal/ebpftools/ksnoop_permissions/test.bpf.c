//go:build ignore

#include "../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct process_info {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64); // Use u64 as the key type to match Go code
    __type(value, struct process_info);
} kprobe_map SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_process(void *ctx) {
    u64 key = bpf_get_current_pid_tgid() >> 32; // Use PID as the key

    // Declare the struct
    struct process_info info;

    // Populate struct fields using BPF helper functions
    info.pid = key; // We already have the PID as the key
    info.uid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(info.comm, sizeof(info.comm)); // Get the process name

    // Update the map with the process information
    int ret = bpf_map_update_elem(&kprobe_map, &key, &info, BPF_ANY);
    if (ret < 0) {
        bpf_printk("Failed to update kprobe_map for PID %d\n", info.pid);
    } else {
        bpf_printk("Updated kprobe_map with PID %d, UID %d, COMM %s\n", info.pid, info.uid, info.comm);
    }

    return 0;
}
