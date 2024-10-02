<!-- START OF TOC !DO NOT EDIT THIS CONTENT MANUALLY-->
**Table of Contents**  *generated with [mtoc](https://github.com/containerscrew/mtoc)*
- [Retrieve data from kprobe](#retrieve-data-from-kprobe)
<!-- END OF TOC -->
# Retrieve data from kprobe

```c
int my_probe(struct pt_regs *ctx) {
    long arg1 = ctx->di; // First argument
    long arg2 = ctx->si; // Second argument
    long arg3 = ctx->dx; // Third argument

    // Your code to use these arguments
    return 0;
}
```

```c
SEC("uprobe/pam_get_authtok")
int get_addr_pam_get_authtok(struct pt_regs *ctx)
{
  if (!PT_REGS_PARM1(ctx))
    return 0;

  pam_handle_t* phandle = (pam_handle_t*)PT_REGS_PARM1(ctx);

  // Get current PID to track
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  // Store pam_handle_t pointer in map for later use
  bpf_map_update_elem(&pam_handle_t_map, &pid, &phandle, BPF_ANY);

  return 0;
};
```
