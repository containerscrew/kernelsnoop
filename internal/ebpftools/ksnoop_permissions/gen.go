package ksnoop_permissions

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go test_bpf test.bpf.c -- -I/usr/include -I ../headers
