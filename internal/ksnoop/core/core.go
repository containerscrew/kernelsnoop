// Some helper functions for the core of ksnoop.

// This was an intention to separate the code to avoid code duplication, but it was not used in the initial version.

// package core

// import (
// 	"fmt"
// 	"os"
// 	"os/signal"
// 	"syscall"

// 	"github.com/cilium/ebpf"
// 	"github.com/cilium/ebpf/link"
// 	"github.com/cilium/ebpf/ringbuf"
// 	"github.com/cilium/ebpf/rlimit"
// 	devstdout "github.com/containerscrew/devstdout/pkg"
// )

// type EbpfHandler struct {
// 	rd  *ringbuf.Reader
// 	log *devstdout.CustomLogger
// }

// // NewFileHandler es el constructor para FileHandler
// func NewEbpfHandler(log *devstdout.CustomLogger) *EbpfHandler {
// 	// Allow the current process to lock memory for eBPF resources
// 	if err := rlimit.RemoveMemlock(); err != nil {
// 		log.Error(fmt.Sprintf("failed to remove memlock rlimit: %v. Consider using sudo or give necessary capabilities to the program", err))
// 	}

// 	return &EbpfHandler{
// 		log: log,
// 	}
// }

// func (e *EbpfHandler) AttachTracingLink(program *ebpf.Program) {
// 	link, err := link.AttachTracing(link.TracingOptions{
// 		Program: program,
// 	})
// 	if err != nil {
// 		e.log.Error(fmt.Sprintf("failed to attach kprobe link: %v", err))
// 	}
// 	defer link.Close()
// }

// func (e *EbpfHandler) NewRingBufferReader(events *ebpf.Map) {
// 	rd, err := ringbuf.NewReader(events)
// 	if err != nil {
// 		e.log.Error(fmt.Sprintf("failed to create ring buffer reader: %v", err))
// 	}
// 	defer rd.Close()
// 	e.rd = rd
// }

// func (e *EbpfHandler) ReadEvents(events interface{}) {
// 	var event events
// }

// func (e *EbpfHandler) HandleSignals() {
// 	// Subscribe to signals for terminating the program.
// 	stopper := make(chan os.Signal, 1)
// 	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

// 	// Close resources when the program exits.
// 	go func() {
// 		<-stopper
// 		if err := e.rd.Close(); err != nil {
// 			e.log.Error("closing perf event reader: %s", err)
// 		}
// 		e.log.Warning("Received signal, exiting program...")
// 	}()
// }
