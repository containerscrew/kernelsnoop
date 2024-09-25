package ksnoop

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	logger "github.com/containerscrew/devstdout/pkg"
	"github.com/containerscrew/kernelsnoop/internal/ksnoop/generates"
	"github.com/containerscrew/kernelsnoop/internal/ksnoop/utils"
)

type ProcessInfo struct {
	Pid  uint32
	Uid  uint32
	Gid  uint32
	Comm [16]byte
}

func ProcessMonitor(ctx context.Context) {
	// Retrieve the logger from the context
	log, _ := ctx.Value("log").(*logger.CustomLogger)

	log.Info("Starting process monitor")
	fn := "sys_execve"

	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error(fmt.Sprintf("failed to remove memlock rlimit: %v. Consider using sudo or give necessary capabilities to the program", err))
	}

	// Load pre-compiled BPF programs and maps into the kernel
	objs := generates.Process_monitor_bpfObjects{}
	if err := generates.LoadProcess_monitor_bpfObjects(&objs, nil); err != nil {
		log.Error(fmt.Sprintf("failed to load BPF objects: %v", err))
	}
	defer objs.Close()

	// Attach a Kprobe to the kernel function
	kp, err := link.Kprobe(fn, objs.KprobeProcess, nil)
	if err != nil {
		log.Error(fmt.Sprintf("failed to open kprobe: %v", err))
	}
	defer kp.Close()

	// Loop to read from the map and report the number of times the syscall was called
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var key uint64
		var processInfo ProcessInfo

		// Create an iterator for the map
		iter := objs.KprobeMap.Iterate()
		for iter.Next(&key, &processInfo) {
			// Translate UID to username
			if err != nil {
				log.Error(fmt.Sprintf("failed to lookup username for UID %d: %v", processInfo.Uid, err))
				continue
			}

			// Log the process information
			log.Info("Syscall event",
				logger.PrintMessage("pid", fmt.Sprintf("%v", processInfo.Pid)),
				logger.PrintMessage("uid", fmt.Sprintf("%v", processInfo.Uid)),
				logger.PrintMessage("gid", fmt.Sprintf("%v", processInfo.Gid)),
				logger.PrintMessage("username", utils.GetUsername(processInfo.Uid)),
				logger.PrintMessage("process", string(bytes.Trim(processInfo.Comm[:], "\x00"))), // Trim null characters
			)
		}

		// Check for errors during map iteration
		if err := iter.Err(); err != nil {
			log.Error(fmt.Sprintf("error while iterating over BPF map: %v", err))
		}
	}
}
