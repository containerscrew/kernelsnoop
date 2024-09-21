package ksnoop_syscalls

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	logger "github.com/containerscrew/devstdout/pkg"
)

const mapKey uint32 = 0

type ConnectionInfo struct {
	Pid  uint64 // Change to uint64
	Comm [16]byte
}

func SyscallHello(ctx context.Context) {
	// First step: retrieve the log from the context
	log, _ := ctx.Value("log").(*logger.CustomLogger)

	log.Info("Starting syscall hello tracer")
	fn := "sys_connect"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error(fmt.Sprintf("failed to remove memlock rlimit: %v. Consider using sudo or give necessary capabilities to the program", err))
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Error(fmt.Sprintf("failed to load BPF objects: %v", err))
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function
	kp, err := link.Kprobe(fn, objs.KprobeSysConnect, nil)
	if err != nil {
		log.Error(fmt.Sprintf("failed to open kprobe: %v", err))
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel function was entered
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Info("Waiting for events")

	for range ticker.C {
		var info ConnectionInfo
		if err := objs.KprobeMap.Lookup(mapKey, &info); err != nil {
			log.Error("failed to lookup kprobe map value")
			continue
		}

		log.Info("syscall called",
			logger.PrintMessage("process", string(bytes.Trim(info.Comm[:], "\x00"))), // Trim null characters
			logger.PrintMessage("pid", info.Pid),
		)
	}
}
