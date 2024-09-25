//go:build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "headers/tcpstates.h"
#include <linux/version.h>

#define MAX_ENTRIES 10240
#define AF_INET     2
#define AF_INET6    10

// Enable/disable filtering by source/destination ports
const volatile bool filter_by_sport = false;
const volatile bool filter_by_dport = false;

// Target address family (0 for all)
const volatile short target_family = 0;

// Map to store filtered source ports
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u16);
    __type(value, __u16);
} sports SEC(".maps");

// Map to store filtered destination ports
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u16);
    __type(value, __u16);
} dports SEC(".maps");

// Map to store timestamps per socket
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct sock *);
    __type(value, __u64);
} timestamps SEC(".maps");

// Perf event array to send events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Handle the "sock/inet_sock_set_state" tracepoint
SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {

    // Get socket pointer, address family, and ports
    struct sock *sk = (struct sock *)ctx->skaddr;
    __u16 family = ctx->family;
    __u16 sport = ctx->sport;
    __u16 dport = ctx->dport;

    // Variables for timestamp and delta
    __u64 *tsp, delta_us, ts;

    // Event structure to store information
    struct event {
        __u64 skaddr;        // Socket address
        __u64 ts_us;         // Timestamp in microseconds
        __u64 delta_us;      // Time delta in microseconds
        __u32 pid;           // Process ID
        __u8 oldstate;       // Old TCP state
        __u8 newstate;       // New TCP state
        __u16 family;        // Address family
        __u16 sport;         // Source port
        __u16 dport;         // Destination port
        char task[TASK_COMM_LEN]; // Task name
        __u32 saddr;         // Source IP
        __u32 daddr;         // Destination IP
    } event;

    // Filter for TCP protocol only
    if (ctx->protocol != IPPROTO_TCP)
        return 0;  // Skip non-TCP packets

    // Filter by address family (if enabled)
    if (target_family && target_family != family)
        return 0;  // Skip if family doesn't match

    // Filter by source port (if enabled)
    if (filter_by_sport && !bpf_map_lookup_elem(&sports, &sport))
        return 0;  // Skip if source port doesn't match

    // Filter by destination port (if enabled)
    if (filter_by_dport && !bpf_map_lookup_elem(&dports, &dport))
        return 0;  // Skip if destination port doesn't match

    // Get timestamp from map or set initial timestamp
    tsp = bpf_map_lookup_elem(&timestamps, &sk);
    ts = bpf_ktime_get_ns();
    if (!tsp)
        delta_us = 0;  // First time seeing this socket
    else
        delta_us = (ts - *tsp) / 1000;  // Calculate time delta in microseconds

    // Populate the event structure
    event.skaddr = (__u64)sk;
    event.ts_us = ts / 1000;
    event.delta_us = delta_us;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.oldstate = ctx->oldstate;
    event.newstate = ctx->newstate;
    event.family = family;
    event.sport = sport;
    event.dport = dport;
    bpf_get_current_comm(&event.task, sizeof(event.task));

    // Read source and destination IP addresses
    if (family == AF_INET) {
        bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    } else { /* family == AF_INET6 */
        bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    // Send the event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    // Update or delete timestamp in the map
    if (ctx->newstate == TCP_CLOSE)
        bpf_map_delete_elem(&timestamps, &sk);
    else
        bpf_map_update_elem(&timestamps, &sk, &ts, BPF_ANY);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
__u32 __version SEC("version") = LINUX_VERSION_CODE;
