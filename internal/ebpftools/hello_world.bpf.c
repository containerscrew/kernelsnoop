// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/sys_execve")
int hello(void *ctx)
{
    bpf_printk("I'm alive!");
    return 0;
}

// char LICENSE[] SEC("license") = "GPL-3.0";
char LICENSE[] SEC("license") = "Dual BSD/GPL";
