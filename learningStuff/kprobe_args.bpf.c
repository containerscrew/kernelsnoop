//go:build ignore

#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <linux/fs.h> // For struct file

char __license[] SEC("license") = "GPL";

SEC("kprobe/sys_open")
int bpf_prog1(struct pt_regs *ctx) {
    // Declare a buffer to hold the file path
    char filename[256];

    // Retrieve the first argument (file path)
    // PT_REGS_PARM1(ctx) returns the pointer to the file path
    const char *file_path = (const char *)PT_REGS_PARM1(ctx);

    // Use bpf_probe_read_kernel to read the file path safely
    bpf_probe_read_kernel(&filename, sizeof(filename), file_path);

    // Log the file path (you would typically send this to a ring buffer or similar)
    bpf_printk("Opening file: %s\n", filename);

    return 0;
}
