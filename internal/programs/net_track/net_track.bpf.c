//go:build ignore

#include "../../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <linux/version.h>

#define AF_INET 2
#define AF_INET6 10
#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";
__u32 __version SEC("version") = LINUX_VERSION_CODE;

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct event_ipv4
{
	u8 comm[16];
	__u16 sport;
	__be16 dport;
	__be32 saddr;
	__be32 daddr;
};

struct event_ipv6
{
	u8 comm[16];
	__u16 sport;
	__be16 dport;
	__u8 saddr[16];
	__u8 daddr[16];
};

// Union to support both IPv4 and IPv6 events
union event
{
	struct event_ipv4 v4;
	struct event_ipv6 v6;
};

union event *unused __attribute__((unused));

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk)
{
	__u16 family = sk->__sk_common.skc_family;

	if (family != AF_INET && family != AF_INET6)
	{
		return 0;
	}

	union event *tcp_info;
	tcp_info = bpf_ringbuf_reserve(&events, sizeof(union event), 0);
	if (!tcp_info)
	{
		return 0;
	}

	if (family == AF_INET)
	{
		// IPv4 handling
		tcp_info->v4.saddr = sk->__sk_common.skc_rcv_saddr;
		tcp_info->v4.daddr = sk->__sk_common.skc_daddr;
		tcp_info->v4.dport = sk->__sk_common.skc_dport;
		tcp_info->v4.sport = bpf_htons(sk->__sk_common.skc_num);

		bpf_get_current_comm(&tcp_info->v4.comm, TASK_COMM_LEN);
	}
	else if (family == AF_INET6)
	{
		// IPv6 handling
		bpf_probe_read_kernel(&tcp_info->v6.saddr, sizeof(tcp_info->v6.saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read_kernel(&tcp_info->v6.daddr, sizeof(tcp_info->v6.daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		tcp_info->v6.dport = sk->__sk_common.skc_dport;
		tcp_info->v6.sport = bpf_htons(sk->__sk_common.skc_num);

		bpf_get_current_comm(&tcp_info->v6.comm, TASK_COMM_LEN);
	}

	bpf_ringbuf_submit(tcp_info, 0);

	return 0;
}
