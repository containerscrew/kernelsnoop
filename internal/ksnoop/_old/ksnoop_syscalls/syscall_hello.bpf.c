//go:build ignore

#include "../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct process_info {
    u32 pid;                       // Process ID
    u32 uid;                       // User ID
    u32 gid;                       // Group ID
    char comm[TASK_COMM_LEN];      // Command name
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);      // Hash map for storing process info
    __uint(max_entries, 1024);            // Max number of entries
    __type(key, u64);                     // Key type (PID)
    __type(value, struct process_info);   // Value type (process info struct)
} kprobe_map SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_process_execve(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;             // Extract PID
    u32 uid = bpf_get_current_uid_gid() >> 32; // Extract UID
    u32 gid = bpf_get_current_uid_gid();  // Extract GID

    struct process_info info = {};        // Initialize the process info struct
    info.pid = pid;
    info.uid = uid;
    info.gid = gid;

    // Get the process command name
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    // Insert or update the map with the process information using PID as the key
    bpf_map_update_elem(&kprobe_map, &pid_tgid, &info, BPF_ANY);

    return 0;
}

SEC("kprobe/clone")
int kprobe_process_clone(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;             // Extract PID
    u32 uid = bpf_get_current_uid_gid() >> 32; // Extract UID
    u32 gid = bpf_get_current_uid_gid();  // Extract GID

    struct process_info info = {};        // Initialize the process info struct
    info.pid = pid;
    info.uid = uid;
    info.gid = gid;

    // Get the process command name
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    // Insert or update the map with the process information using PID as the key
    bpf_map_update_elem(&kprobe_map, &pid_tgid, &info, BPF_ANY);

    return 0;
}
