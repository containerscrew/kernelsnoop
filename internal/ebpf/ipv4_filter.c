//go:build ignore

#include <linux/ptrace.h>
#include <linux/socket.h>
#include <net/sock.h>


BPF_HASH(currsock, u32, struct sock *);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid();

    // Store the sock ptr for lookup on return
    currsock.update(&pid, &sk);

    return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0;    // Missed entry
    }

    if (ret != 0) {
        // Failed to send SYN packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&pid);
        return 0;
    }

    // Pull in details
    struct sock *skp = *skpp;
    u32 saddr = skp->__sk_common.skc_rcv_saddr;
    u32 daddr = skp->__sk_common.skc_daddr;
    u16 dport = skp->__sk_common.skc_dport;

    // Output
    bpf_trace_printk("trace_tcp4connect %x %x %d\\n", saddr, daddr, ntohs(dport));

    currsock.delete(&pid);

    return 0;
}
