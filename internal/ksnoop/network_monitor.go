package ksnoop

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	logger "github.com/containerscrew/devstdout/pkg"
	"github.com/containerscrew/kernelsnoop/internal/ksnoop/generates"
)

// Define the event structure according to your BPF code
type event struct {
	SkAddr   uint64
	TsUs     uint64
	DeltaUs  uint64
	Pid      uint32
	OldState uint32
	NewState uint32
	Family   uint16
	Sport    uint16
	Dport    uint16
	Task     [16]byte
	SAddr    uint32
	DAddr    uint32
}

func NetworkMonitor(ctx context.Context) {
	// Retrieve the logger from the context
	log, _ := ctx.Value("log").(*logger.CustomLogger)
	log.Info("Starting network monitor")

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error(fmt.Sprintf("failed to remove memlock rlimit: %v. Consider using sudo or give necessary capabilities to the program", err))
		return
	}

	objs := generates.Network_monitor_bpfObjects{}
	if err := generates.LoadNetwork_monitor_bpfObjects(&objs, nil); err != nil {
		log.Error(fmt.Sprintf("failed to load BPF objects: %v", err))
		return
	}
	defer objs.Close()

	// Set up a ring buffer reader for the perf events
	// Attach to tracepoints
	tpEnterLink, err := link.Tracepoint("sock", "inet_sock_set_state", objs.HandleSetState, nil)
	if err != nil {
		log.Error(fmt.Sprintf("failed to open tracepoint: %v", err))
	}
	defer tpEnterLink.Close()

	// Initialize ring buffer
	events := objs.Events
	rd, err := perf.NewReader(events, 4096)

	if err != nil {
		log.Error(fmt.Sprintf("failed to create ringbuf reader: %v", err))
	}
	defer rd.Close()

	// Create a channel to handle graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	// Start reading from the perf event reader in a separate goroutine
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

			var data event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &data); err != nil {
				log.Error(fmt.Sprintf("Error decoding event: %s", err))
				continue
			}

			// Log the event values
			log.Info("new connection",
				logger.PrintMessage("skaddr", data.SAddr),
				logger.PrintMessage("daddr", data.DAddr),
				logger.PrintMessage("sport", fmt.Sprintf("%d", data.Sport)),
				logger.PrintMessage("dport", fmt.Sprintf("%d", data.Dport)),
				logger.PrintMessage("pid", data.Pid),
				logger.PrintMessage("task", string(data.Task[:])),
				logger.PrintMessage("oldstate", data.OldState),
				logger.PrintMessage("newstate", data.NewState),
				logger.PrintMessage("family", fmt.Sprintf("%d", data.Family)),
				logger.PrintMessage("tsus", data.TsUs),
				logger.PrintMessage("deltaus", data.DeltaUs),
			)
		}
	}()
	// Wait for interrupt signal
	<-stop
	log.Info("Stopping network monitor")
}
