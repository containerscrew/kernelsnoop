//go:build ignore

#include "../../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <linux/version.h>

#define AF_INET 2
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
	u8 comm[16];     // Process name
	__u16 sport;     // Source port
	__be16 dport;    // Destination port
	__be32 saddr;    // Source IP address
	__be32 daddr;    // Destination IP address
	__u8 protocol;   // Protocol: 6 for TCP, 17 for UDP
};

// Union to support IPv4 events (both TCP and UDP)
union event
{
	struct event_ipv4 v4;
};

union event *unused __attribute__((unused));

// Hook for TCP connections
SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk)
{
	__u16 family = sk->__sk_common.skc_family;

	if (family != AF_INET)
	{
		return 0;
	}

	union event *tcp_info;
	tcp_info = bpf_ringbuf_reserve(&events, sizeof(union event), 0);
	if (!tcp_info)
	{
		return 0;
	}

	// Handling IPv4 for TCP
	tcp_info->v4.saddr = sk->__sk_common.skc_rcv_saddr;
	tcp_info->v4.daddr = sk->__sk_common.skc_daddr;
	tcp_info->v4.dport = sk->__sk_common.skc_dport;
	tcp_info->v4.sport = bpf_htons(sk->__sk_common.skc_num);
	tcp_info->v4.protocol = 6;  // TCP protocol

	bpf_get_current_comm(&tcp_info->v4.comm, TASK_COMM_LEN);  // Get process name
	bpf_ringbuf_submit(tcp_info, 0);

	return 0;
}

// Hook for UDP sendmsg
SEC("fentry/udp_sendmsg")
int BPF_PROG(udp_sendmsg, struct sock *sk)
{
	__u16 family = sk->__sk_common.skc_family;

	if (family != AF_INET)
	{
		return 0;
	}

	// Filter out events with destination IP "0.0.0.0" or destination port "0"
	if (sk->__sk_common.skc_daddr == 0 || sk->__sk_common.skc_dport == 0)
	{
		return 0;  // Skip this event
	}

	union event *udp_info;
	udp_info = bpf_ringbuf_reserve(&events, sizeof(union event), 0);
	if (!udp_info)
	{
		return 0;
	}

	// Handling IPv4 for UDP
	udp_info->v4.saddr = sk->__sk_common.skc_rcv_saddr;
	udp_info->v4.daddr = sk->__sk_common.skc_daddr;
	udp_info->v4.dport = sk->__sk_common.skc_dport;
	udp_info->v4.sport = bpf_htons(sk->__sk_common.skc_num);
	udp_info->v4.protocol = 17;  // UDP protocol

	bpf_get_current_comm(&udp_info->v4.comm, TASK_COMM_LEN);  // Get process name
	bpf_ringbuf_submit(udp_info, 0);

	return 0;
}
