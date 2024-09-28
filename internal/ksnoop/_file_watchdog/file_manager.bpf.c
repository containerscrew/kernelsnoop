//go:build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/version.h>

char __license[] SEC("license") = "Dual MIT/GPL";
__u32 __version SEC("version") = LINUX_VERSION_CODE;

struct event {
    u32 pid;
    u32 uid;
    u8 filename[80];
};

// Generate a map to store the events
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("kprobe/do_unlinkat")
int kprobe__do_unlinkat(struct pt_regs *ctx) {
    struct event event;

    event.uid = bpf_get_current_uid_gid() >> 32;
    event.pid = bpf_get_current_pid_tgid();

    bpf_probe_read(&event.filename, sizeof(event.filename), (void *)PT_REGS_RC(ctx));

    // Enviar el evento al espacio de usuario
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// Add kretpobe to trace the return of the syscall
// SEC("kretprobe/do_unlinkat")
// int kretprobe__do_unlinkat(struct pt_regs *ctx) {
//     struct event event;

//     event.uid = bpf_get_current_uid_gid() >> 32;
//     event.pid = bpf_get_current_pid_tgid();

//     bpf_probe_read(&event.filename, sizeof(event.filename), (void *)PT_REGS_RC(ctx));

//     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

//     return 0;
// }
