//go:build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <linux/version.h>

typedef unsigned int u32;
typedef int pid_t;

struct data_t {
    int pid;
    int uid;
    char command[256];
    char message[256]; // adjust size as needed
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

char __license[] SEC("license") = "Dual MIT/GPL";
__u32 __version SEC("version") = LINUX_VERSION_CODE;

SEC("tracepoint/syscalls/sys_enter_chmod")
int handle_sys_chmod(void *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;

    bpf_get_current_comm(&data.command, sizeof(data.command));

    // Asignar directamente el mensaje a la estructura
    __builtin_memcpy(data.message, "Hello, World", sizeof(data.message));

    // Enviar los datos a la aplicación de usuario
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}
