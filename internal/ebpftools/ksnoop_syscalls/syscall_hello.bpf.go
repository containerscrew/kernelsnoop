package ksnoop_syscalls

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	logger "github.com/containerscrew/devstdout/pkg"
	"golang.org/x/sys/unix"
)

const mapKey uint32 = 0

type ConnectionInfo struct {
    Pid  uint64 // PID
    Comm [16]byte // Process name (TASK_COMM_LEN)
}

func SyscallHello(ctx context.Context, syscalls []string) {
    // Retrieve the logger from the context
    log, _ := ctx.Value("log").(*logger.CustomLogger)

    log.Info("Starting syscall tracer")

    // Allow the current process to lock memory for eBPF resources.
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Error(fmt.Sprintf("failed to remove memlock rlimit: %v. Consider using sudo or give necessary capabilities to the program", err))
        return
    }

    // Load pre-compiled programs and maps into the kernel.
    objs := bpfObjects{}
    if err := loadBpfObjects(&objs, nil); err != nil {
        log.Error(fmt.Sprintf("failed to load BPF objects: %v", err))
        return
    }
    defer objs.Close()

    // Open kprobes for each syscall
    var kprobes []link.Link
    for _, fn := range syscalls {
        kp, err := link.Kprobe(fn, objs.KprobeSysConnect, nil) // Ensure this matches the compiled BPF program's name
        if err != nil {
            log.Error(fmt.Sprintf("failed to open kprobe for %s: %v", fn, err))
            continue
        }
        kprobes = append(kprobes, kp)
    }

    // Read loop reporting syscall information
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()

    log.Info("Waiting for events")

    for range ticker.C {
        key := getCurrentPID() // Function to get the current PID
        var info ConnectionInfo
        if err := objs.KprobeMap.Lookup(key, &info); err != nil {
            log.Error(fmt.Sprintf("failed to lookup kprobe map value for PID %d: %v", key, err))
            continue
        }

        log.Info(fmt.Sprintf("systemcall executed by program %s and PID %d", string(bytes.Trim(info.Comm[:], "\x00")), info.Pid))
    }
}

// Implement getCurrentPID to return the current process PID
func getCurrentPID() uint32 {
    pid := uint32(unix.Getpid()) // Retrieve the current process PID
    return pid
}
