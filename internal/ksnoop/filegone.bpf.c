//go:build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct filegone_info {
    u32 pid;                       // Process ID
    char comm[TASK_COMM_LEN];      // Command name
};

//cat /sys/kernel/debug/tracing/events/ext4/ext4_free_inode/format
struct trace_event_raw_ext4_free_inode {
    u32 common_type;
    u8 common_flags;
    u8 common_preempt_count;
    int common_pid;
    u32 dev;
    u64 ino;
};

struct {
    __uint(type,BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

SEC("tracepoint/ext4/ext4_free_inode")
int trace_inode_free(struct trace_event_raw_ext4_free_inode *ctx) {
    struct filegone_info *data = bpf_ringbuf_reserve(&events, sizeof(struct filegone_info), 0);

    if (!data) {
        return 0; // Skip event if ring buffer reservation fails
    }

    data->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    // Populate data with other relevant information to the event

    bpf_ringbuf_submit(data, 0); // Submit the event to the ring buffer
    return 0;
}
