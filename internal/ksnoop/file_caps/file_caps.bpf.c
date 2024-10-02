//go:build ignore

#include "../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
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
    u32 tgid;
    u32 pid;
    u32 uid;
    int cap;
    int audit;
    int insetid;
    u8 comm[16];
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("kprobe/cap_capable")
int kprobe_file_capabilities(struct pt_regs *ctx)
{
    struct event *data;
    u32 uid = (u32)bpf_get_current_uid_gid();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;  // Los primeros 32 bits son el TGID
    u32 pid = pid_tgid & 0xFFFFFFFF;  // Los últimos 32 bits son el PID
    int cap, audit;

    // Manually fetch arguments from the pt_regs struct (x86_64)
    cap = ctx->dx;    // Segundo argumento (cap) en %rdx
    audit = ctx->cx;  // Tercer argumento (audit) en %rcx

    // Reserva espacio en el ring buffer para el evento
    data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) {
        return 0;
    }

    data->tgid = tgid;
    data->pid = pid;
    data->uid = uid;
    data->cap = cap;
    data->audit = audit;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    // Envía los datos al ring buffer
    bpf_ringbuf_submit(data, 0);

    return 0;
}
