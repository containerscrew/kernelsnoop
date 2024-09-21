//go:build ignore

#include "../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct connection_info {
    u64 pid;  // Store as uint64
    char comm[TASK_COMM_LEN]; // Process name
};

// Function prototype
static int handle_syscall(void);

// Define the map using modern syntax
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);  // Adjust based on your needs
    __type(key, u32);  // Use PID as the key
    __type(value, struct connection_info);
} kprobe_map SEC(".maps");

SEC("kprobe/sys_connect")
int kprobe_sys_connect() {
    return handle_syscall();
}

SEC("kprobe/sys_execve")
int kprobe_sys_execve() {
    return handle_syscall();
}

// Common handler for syscalls
static int handle_syscall() {
    u32 key = bpf_get_current_pid_tgid() >> 32;  // Use PID as key
    struct connection_info info;

    // Get the current PID and program name
    info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(info.comm, sizeof(info.comm));

    // Update the map with the syscall info
    bpf_map_update_elem(&kprobe_map, &key, &info, BPF_ANY);

    return 0;
}
