package ksnoop

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go process_monitor_bpf process_monitor.bpf.c -- -I/usr/include -I ./headers
