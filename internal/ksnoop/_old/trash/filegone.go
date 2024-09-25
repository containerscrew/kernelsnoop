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
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	logger "github.com/containerscrew/devstdout/pkg"
	"github.com/containerscrew/kernelsnoop/internal/ksnoop/generates"
)

type FileGoneInfo struct {
	Pid  uint32
	Comm [16]byte
}

func FileGoneMonitor(ctx context.Context) {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Retrieve the logger from the context
	log, _ := ctx.Value("log").(*logger.CustomLogger)

	log.Info("Starting filegone monitor")

	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error(fmt.Sprintf("failed to remove memlock rlimit: %v. Consider using sudo or give necessary capabilities to the program", err))
	}

	// Load pre-compiled BPF programs and maps into the kernel
	objs := generates.Filegone_monitor_bpfObjects{}
	if err := generates.LoadFilegone_monitor_bpfObjects(&objs, nil); err != nil {
		log.Error(fmt.Sprintf("failed to load BPF objects: %v", err))
	}
	defer objs.Close()

	// Attach to tracepoints
	tpEnterLink, err := link.Tracepoint("ext4", "ext4_free_inode", objs.TraceInodeFree, nil)
	if err != nil {
		log.Error(fmt.Sprintf("failed to open tracepoint: %v", err))
	}
	defer tpEnterLink.Close()

	// Initialize ring buffer
	events := objs.Events
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		log.Error(fmt.Sprintf("failed to create ringbuf reader: %v", err))
	}
	defer rd.Close()

	// Handle incoming events
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

			var data FileGoneInfo
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &data); err != nil {
				log.Error(fmt.Sprintf("Error decoding event: %s", err))
				continue
			}

			comm := string(bytes.Trim(data.Comm[:], "\x00"))
			//log.Printf("Event received: PID: %d, Comm: %s\n", data.Pid, comm)
			log.Info("Filegone event",
				logger.PrintMessage("pid", fmt.Sprintf("%v", data.Pid)),
				logger.PrintMessage("process", comm),
			)
		}
	}()

	// Wait for interrupt
	<-stopper
}
