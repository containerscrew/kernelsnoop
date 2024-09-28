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
	"github.com/cilium/ebpf/rlimit"
	devstdout "github.com/containerscrew/devstdout/pkg"
	"github.com/containerscrew/kernelsnoop/internal/ksnoop/generates"
	"github.com/containerscrew/kernelsnoop/internal/ksnoop/utils"
	"golang.org/x/sys/unix"
)

func DeleteFile(ctx context.Context) {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Retrieve the devstdout from the context
	log, _ := ctx.Value("log").(*devstdout.CustomLogger)

	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error(fmt.Sprintf("failed to remove memlock rlimit: %v. Consider using sudo or give necessary capabilities to the program", err))
	}

	// Load pre-compiled BPF programs and maps into the kernel
	objs := generates.FileManagerObjects{}
	if err := generates.LoadFileManagerObjects(&objs, nil); err != nil {
		log.Error(fmt.Sprintf("failed to load BPF objects: %v", err))
	}
	defer objs.Close()

	kp, err := link.Kprobe("do_unlinkat", objs.KprobeDoUnlinkat, nil)
	if err != nil {
		log.Error(fmt.Sprintf("creating kprobe: %s", err))
	}
	defer kp.Close()

	// Open a perf ring buffer reader to retrieve the events from the kernel
	events := objs.Events
	rd, err := perf.NewReader(events, 4096)
	if err != nil {
		log.Error(fmt.Sprintf("failed to create ringbuf reader: %v", err))
	}
	defer rd.Close()

	// Close the perf reader when the program exits.
	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Warning("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Error("closing perf event reader: %s", err)
		}
	}()

	// Log that the program is listening for events, and the event type is shell_readline
	log.Info("listening for events",
		devstdout.Argument("event", "file_manager"),
	)

	var event generates.FileManagerEvent

	for {
		// Read the next event from the ring buffer.
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Error(fmt.Sprintf("Failed to read from ringbuf: %v", err))
			continue
		}

		// If the ring buffer is full, some events were lost.
		if record.LostSamples != 0 {
			log.Warning(fmt.Sprintf("perf event ring buffer full, dropped %d samples", record.LostSamples))
			continue
		}

		// Decode the raw sample into a ShellReadlineEvent struct.
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Error(fmt.Sprintf("Error decoding event: %s", err))
			continue
		}

		// Log the event with the following fields
		log.Info("new file deletion",
			devstdout.Argument("pid", fmt.Sprintf("%d", event.Pid)),
			devstdout.Argument("uid", fmt.Sprintf("%d", event.Uid)),
			devstdout.Argument("user", utils.GetUsername(event.Uid)),
			devstdout.Argument("filename", unix.ByteSliceToString(event.Filename[:])),
		)
	}
}
