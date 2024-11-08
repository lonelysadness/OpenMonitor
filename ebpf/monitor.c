#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h> // Include this header for bpf_ntohs

#define AF_INET 2
#define AF_INET6 10
#define TCP 6
#define UDP 17
#define UDPLite 136
#define OUTBOUND 0
#define INBOUND 1

char __license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} pm_connection_events SEC(".maps");

struct Event {
	u32 saddr[4];
	u32 daddr[4];
	u16 sport;
	u16 dport;
	u32 pid;
	u8 ipVersion;
	u8 protocol;
	u8 direction;
};
struct Event *unused __attribute__((unused));

// Add filtering for invalid addresses
static __always_inline int is_valid_ipv4(u32 addr) {
    return addr != 0;
}

// Add connection validation
static __always_inline int is_valid_connection(struct Event *event) {
    if (event->sport == 0 || event->dport == 0) {
        return 0;
    }

    if (event->ipVersion == 4) {
        return is_valid_ipv4(event->saddr[0]) && is_valid_ipv4(event->daddr[0]);
    }
    
    return 1; // IPv6 validation if needed
}

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk) {
	struct Event *tcp_info;
	tcp_info = bpf_ringbuf_reserve(&pm_connection_events, sizeof(struct Event), 0);
	if (!tcp_info) {
		return 0;
	}

	tcp_info->pid = bpf_get_current_pid_tgid() >> 32;
	tcp_info->protocol = TCP;
	tcp_info->direction = OUTBOUND;
	tcp_info->sport = bpf_ntohs(sk->__sk_common.skc_num);
	tcp_info->dport = bpf_ntohs(sk->__sk_common.skc_dport);

	if (sk->__sk_common.skc_family == AF_INET) {
		tcp_info->saddr[0] = sk->__sk_common.skc_rcv_saddr;
		tcp_info->daddr[0] = sk->__sk_common.skc_daddr;
		tcp_info->ipVersion = 4;
	} else if (sk->__sk_common.skc_family == AF_INET6) {
		bpf_probe_read_kernel(&tcp_info->saddr, sizeof(tcp_info->saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read_kernel(&tcp_info->daddr, sizeof(tcp_info->daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		tcp_info->ipVersion = 6;
	}

	// Add validation before submitting
	if (!is_valid_connection(tcp_info)) {
		bpf_ringbuf_discard(tcp_info, 0);
		return 0;
	}

	bpf_ringbuf_submit(tcp_info, 0);
	return 0;
}

SEC("fexit/ip4_datagram_connect")
int BPF_PROG(udp_v4_connect, struct sock *sk) {
	if (sk->__sk_common.skc_family != AF_INET || sk->__sk_common.skc_dport == 0) {
		return 0;
	}

	struct Event *udp_info;
	udp_info = bpf_ringbuf_reserve(&pm_connection_events, sizeof(struct Event), 0);
	if (!udp_info) {
		return 0;
	}

	udp_info->pid = bpf_get_current_pid_tgid() >> 32;
	udp_info->sport = bpf_ntohs(sk->__sk_common.skc_num);
	udp_info->dport = bpf_ntohs(sk->__sk_common.skc_dport);
	udp_info->saddr[0] = sk->__sk_common.skc_rcv_saddr;
	udp_info->daddr[0] = sk->__sk_common.skc_daddr;
	udp_info->ipVersion = 4;
	udp_info->protocol = sk->sk_protocol == IPPROTO_UDPLITE ? UDPLite : UDP;

	// Add validation before submitting
	if (!is_valid_connection(udp_info)) {
		bpf_ringbuf_discard(udp_info, 0);
		return 0;
	}

	bpf_ringbuf_submit(udp_info, 0);
	return 0;
}

SEC("fexit/ip6_datagram_connect")
int BPF_PROG(udp_v6_connect, struct sock *sk) {
	if (sk->__sk_common.skc_family != AF_INET6 || sk->__sk_common.skc_dport == 0) {
		return 0;
	}

	struct udp6_sock *us = bpf_skc_to_udp6_sock(sk);
	if (!us) {
		return 0;
	}

	struct Event *udp_info;
	udp_info = bpf_ringbuf_reserve(&pm_connection_events, sizeof(struct Event), 0);
	if (!udp_info) {
		return 0;
	}

	udp_info->pid = bpf_get_current_pid_tgid() >> 32;
	udp_info->sport = bpf_ntohs(sk->__sk_common.skc_num);
	udp_info->dport = bpf_ntohs(sk->__sk_common.skc_dport);
	bpf_probe_read_kernel(&udp_info->saddr, sizeof(udp_info->saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	bpf_probe_read_kernel(&udp_info->daddr, sizeof(udp_info->daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	udp_info->ipVersion = 6;
	udp_info->protocol = sk->sk_protocol == IPPROTO_UDPLITE ? UDPLite : UDP;

	// Add validation before submitting
	if (!is_valid_connection(udp_info)) {
		bpf_ringbuf_discard(udp_info, 0);
		return 0;
	}

	bpf_ringbuf_submit(udp_info, 0);
	return 0;
}

SEC("sockops")
int socket_operations(struct bpf_sock_ops *skops) {
    struct Event *tcp_info;
    
    if (skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
        return 0;

    tcp_info = bpf_ringbuf_reserve(&pm_connection_events, sizeof(struct Event), 0);
    if (!tcp_info) 
        return 0;

    // For sockops, we don't have access to current PID
    tcp_info->pid = 0;
    tcp_info->protocol = TCP;
    tcp_info->direction = INBOUND;
    
    if (skops->family == AF_INET) {
        tcp_info->sport = bpf_ntohs(skops->remote_port >> 16);
        tcp_info->dport = bpf_ntohs(skops->local_port >> 16);
        tcp_info->saddr[0] = skops->remote_ip4;
        tcp_info->daddr[0] = skops->local_ip4;
        tcp_info->ipVersion = 4;
    } else if (skops->family == AF_INET6) {
        tcp_info->sport = bpf_ntohs(skops->remote_port >> 16);
        tcp_info->dport = bpf_ntohs(skops->local_port >> 16);
        tcp_info->ipVersion = 6;
        
        // Safe copy of IPv6 addresses
        bpf_probe_read_kernel(&tcp_info->saddr, sizeof(tcp_info->saddr), &skops->remote_ip6);
        bpf_probe_read_kernel(&tcp_info->daddr, sizeof(tcp_info->daddr), &skops->local_ip6);
    }

    // Add validation before submitting
    if (!is_valid_connection(tcp_info)) {
        bpf_ringbuf_discard(tcp_info, 0);
        return 0;
    }

    bpf_ringbuf_submit(tcp_info, 0);
    
    // Set callback flags
    bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_ALL_CB_FLAGS);
    return 0;
}

// Modify UDP receive handling
SEC("fexit/udp_recvmsg")
int BPF_PROG(udp_rcv, struct sock *sk) {
    if (!sk) return 0;

    struct Event *udp_info;
    udp_info = bpf_ringbuf_reserve(&pm_connection_events, sizeof(struct Event), 0);
    if (!udp_info) return 0;

    udp_info->pid = bpf_get_current_pid_tgid() >> 32;
    udp_info->protocol = UDP;
    udp_info->direction = INBOUND;

    struct sock_common *skc = &sk->__sk_common;
    udp_info->sport = bpf_ntohs(skc->skc_dport);
    udp_info->dport = bpf_ntohs(skc->skc_num);

    if (skc->skc_family == AF_INET) {
        udp_info->saddr[0] = skc->skc_daddr;
        udp_info->daddr[0] = skc->skc_rcv_saddr;
        udp_info->ipVersion = 4;
    } else if (skc->skc_family == AF_INET6) {
        bpf_probe_read_kernel(&udp_info->saddr, sizeof(udp_info->saddr), skc->skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&udp_info->daddr, sizeof(udp_info->daddr), skc->skc_v6_rcv_saddr.in6_u.u6_addr32);
        udp_info->ipVersion = 6;
    }

    // Add validation before submitting
    if (!is_valid_connection(udp_info)) {
        bpf_ringbuf_discard(udp_info, 0);
        return 0;
    }

    bpf_ringbuf_submit(udp_info, 0);
    return 0;
}
