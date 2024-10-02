package ksnoop_file_caps

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	devstdout "github.com/containerscrew/devstdout/pkg"
)

var capabilities = map[int]string{
    0:  "CAP_CHOWN",
    1:  "CAP_DAC_OVERRIDE",
    2:  "CAP_DAC_READ_SEARCH",
    3:  "CAP_FOWNER",
    4:  "CAP_FSETID",
    5:  "CAP_KILL",
    6:  "CAP_SETGID",
    7:  "CAP_SETUID",
    8:  "CAP_SETPCAP",
    9:  "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf ./file_caps.bpf.c -- -I../headers

func FileCaps(ctx context.Context) {
	// Retrieve the devstdout from the context
	log, _ := ctx.Value("log").(*devstdout.CustomLogger)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error(fmt.Sprintf("failed to remove memlock rlimit: %v. Consider using sudo or give necessary capabilities to the program", err))
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Error(fmt.Sprintf("loading objects: %v", err))
	}
	defer objs.Close()

	fn := "cap_capable"

	kp, err := link.Kprobe(fn, objs.KprobeFileCapabilities, nil)
	if err != nil {
		log.Error(fmt.Sprintf("failed to attach kprobe link: %v", err))
	}
	defer kp.Close()


	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Error(fmt.Sprintf("failed to create ring buffer reader: %v", err))
	}
	defer rd.Close()

		var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Warning("received signal, closing ringbuf reader..")
				return
			}
			log.Info("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event); err != nil {
			log.Warning("parsing ringbuf event: %s", err)
			continue
		}

		log.Info("file changed",
			devstdout.Argument("file", event.Cap),
			devstdout.Argument("pid", event.Pid),
			devstdout.Argument("uid", event.Uid),
			devstdout.Argument("comm", string(event.Comm[:bytes.IndexByte(event.Comm[:], 0)])),
			devstdout.Argument("audit", event.Audit),
			devstdout.Argument("cap", capabilities[int(event.Insetid)]),
		)
	}
}
