package ksnoop_syscalls

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf syscall_hello.bpf.c -- -I/usr/include -I ../headers
