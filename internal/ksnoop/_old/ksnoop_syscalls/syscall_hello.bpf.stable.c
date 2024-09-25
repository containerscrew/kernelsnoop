//go:build ignore

#include "../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

typedef unsigned int mode_t; // Definir mode_t

struct permission_change_info {
    u64 pid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct permission_change_info);
} chmod_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_chmod(struct pt_regs *ctx, const char *filename, mode_t mode) {
    u32 key = 0;
    struct permission_change_info info;

    // Obtener PID y nombre del proceso
    info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(info.comm, sizeof(info.comm));

    // Leer el nombre del archivo desde el espacio del usuario
    if (bpf_copy_from_user(info.filename, filename, sizeof(info.filename)) == 0) {
        // Actualizar el mapa con la información del cambio de permisos
        bpf_map_update_elem(&chmod_map, &key, &info, BPF_ANY);
    }

    return 0;
}
