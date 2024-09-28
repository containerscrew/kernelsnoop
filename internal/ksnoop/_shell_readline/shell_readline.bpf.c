//go:build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/version.h>

char __license[] SEC("license") = "Dual MIT/GPL";
__u32 __version SEC("version") = LINUX_VERSION_CODE;

#define MAX_LINE_SIZE 80

struct event {
    u32 pid;
    u32 uid;
    u8 line[MAX_LINE_SIZE];
    u8 shell[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

// Function to handle the common logic for reading shell commands
static inline int handle_readline_event(struct pt_regs *ctx) {
    struct event event;

    // Get the UID and PID of the current process
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.pid = bpf_get_current_pid_tgid();

    // Get the shell name dynamically
    bpf_get_current_comm(&event.shell, sizeof(event.shell));

    // Read the command line from the return value of the function
    bpf_probe_read(&event.line, sizeof(event.line), (void *)PT_REGS_RC(ctx));

    // Calculate the length of the string
    int len = 0;
    while (len < MAX_LINE_SIZE && event.line[len] != '\0') {
        len++;  // Count characters until the null terminator or the max size
    }

    // Check if the command is empty (i.e., only contains a newline)
    if (len == 0 || (len == 1 && event.line[0] == '\n')) {
        return 0;  // Skip logging for empty commands
    }

    // If the last character is a newline, replace it with a null terminator
    if (len > 0 && event.line[len - 1] == '\n') {
        event.line[len - 1] = '\0';  // Replace the last character with a null terminator
    }

    // Output the event to the perf event array
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

SEC("uretprobe/bash_readline")
int uretprobe_sh_readline(struct pt_regs *ctx) {
    return handle_readline_event(ctx);
}

SEC("uretprobe/zsh_readline")
int uretprobe_zsh_readline(struct pt_regs *ctx) {
    return handle_readline_event(ctx);
}
