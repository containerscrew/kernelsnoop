package generates

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native Process_monitor_bpf ../process_monitor.bpf.c -- -I/usr/include -I ../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native Filegone_monitor_bpf ../filegone.bpf.c -- -I/usr/include -I ../headers
