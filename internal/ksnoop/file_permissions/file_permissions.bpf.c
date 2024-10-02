//go:build ignore

#include "../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <linux/version.h>

#define AF_INET 2
#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";
__u32 __version SEC("version") = LINUX_VERSION_CODE;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct event {
    u32 pid;
    u32 uid;
    u8 comm[16];
    // u32 mode;
    char filename[256];
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_chmod")
int file_permissions(struct trace_event_raw_sys_enter *ctx){
    struct event *data;

    // Allocate ring buffer space for event data
    data = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!data) {
        return 0;
    }

    // Fill event data
    data->pid = bpf_get_current_pid_tgid();
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    // Retrieve the first argument (permission mode)
    // data->mode = (u32)ctx->args[0];

    // Retrieve the second argument (file path)
    const char *file_path = (const char *)ctx->args[1];
    bpf_probe_read_kernel_str(&data->filename, sizeof(data->filename), file_path);

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(data, 0);

    return 0;
}
