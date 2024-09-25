package ksnoop

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	logger "github.com/containerscrew/devstdout/pkg"
	"github.com/containerscrew/kernelsnoop/internal/ksnoop/generates"
)

type Data struct {
	PID     uint32
	UID     uint32
	Command [16]byte
	Message [256]byte
}

func PermissionMonitor(ctx context.Context) {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Retrieve the logger from the context
	log, _ := ctx.Value("log").(*logger.CustomLogger)

	log.Info("Starting permission monitor")

	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error(fmt.Sprintf("failed to remove memlock rlimit: %v. Consider using sudo or give necessary capabilities to the program", err))
	}

	// Load pre-compiled BPF programs and maps into the kernel
	objs := generates.Permission_monitor_bpfObjects{}
	if err := generates.LoadPermission_monitor_bpfObjects(&objs, nil); err != nil {
		log.Error(fmt.Sprintf("failed to load BPF objects: %v", err))
	}
	defer objs.Close()

	// Attach to tracepoints
	tpEnterLink, err := link.Tracepoint("syscalls", "sys_enter_chmod", objs.HandleSysChmod, nil)
	if err != nil {
		log.Error(fmt.Sprintf("failed to open tracepoint: %v", err))
	}
	defer tpEnterLink.Close()

	fmt.Println("eBPF program attached. Waiting for events...")

	// Listen for termination signals (Ctrl+C)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// Set up to read the BPF logs from /sys/kernel/debug/tracing/trace_pipe
	// Initialize ring buffer
	events := objs.Events
	rd, err := perf.NewReader(events, 4096)
	if err != nil {
		log.Error(fmt.Sprintf("failed to create ringbuf reader: %v", err))
	}
	defer rd.Close()

	// Read trace_pipe output in a separate goroutine
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Error(fmt.Sprintf("Failed to read from ringbuf: %v", err))
				continue
			}
			// Print the trace output (eBPF logs)
			var data Data
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &data); err != nil {
				log.Error(fmt.Sprintf("Error decoding event: %s", err))
				continue
			}
			comm := string(bytes.Trim(data.Command[:], "\x00"))

			log.Info(fmt.Sprintf("PID: %d, UID: %d, Command: %s, Message: %s", data.PID, data.UID, comm, data.Message))
		}
	}()

	// Wait for the termination signal
	<-sig
	fmt.Println("Exiting...")
}
