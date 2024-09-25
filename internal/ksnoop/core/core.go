// // Some helper functions for the core of ksnoop.
// package core

// import (
// 	"context"
// 	"fmt"
// 	"os"
// 	"os/signal"
// 	"syscall"

// 	"github.com/cilium/ebpf/perf"
// 	"github.com/cilium/ebpf/rlimit"
// 	logger "github.com/containerscrew/devstdout/pkg"
// 	"github.com/containerscrew/kernelsnoop/internal/ksnoop/generates"
// )

// // EbpfProgram represents an eBPF program with its associated functionality
// type EbpfProgram struct {
// 	log     *logger.CustomLogger
// 	objs    generates.ShellReadlineObjects
// 	rd      *perf.Reader
// 	stopper chan os.Signal
// }

// // NewEbpfProgram creates a new eBPF program, sets up rlimit, loads objects, and returns the program
// func NewEbpfProgram(ctx context.Context, objs struct{}) (*EbpfProgram, error) {
// 	log, _ := ctx.Value("log").(*logger.CustomLogger)

// 	// Remove memory lock limit for eBPF resources
// 	if err := rlimit.RemoveMemlock(); err != nil {
// 		log.Error(fmt.Sprintf("failed to remove memlock rlimit: %v. Check permissions", err))
// 		return nil, err
// 	}

// 	// Load pre-compiled BPF programs and maps into the kernel
// 	//objs := generates.ShellReadlineObjects{}
// 	if err := generates.LoadShellReadlineObjects(&objs, nil); err != nil {
// 		log.Error(fmt.Sprintf("failed to load BPF objects: %v", err))
// 		return nil, err
// 	}

// 	return &EbpfProgram{
// 		log:     log,
// 		stopper: make(chan os.Signal, 1),
// 	}, nil
// }

// func (p *EbpfProgram) WaitForSignal() {
// 	signal.Notify(p.stopper, os.Interrupt, syscall.SIGTERM)

// 	go func() {
// 		<-p.stopper
// 		p.log.Warning("Received signal, exiting program..")

// 		if err := p.rd.Close(); err != nil {
// 			p.log.Error(fmt.Sprintf("closing perf event reader: %s", err))
// 		}
// 		p.objs.Close()
// 	}()
// }
