package ksnoop_tcp_connect

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	devstdout "github.com/containerscrew/devstdout/pkg"
	"github.com/containerscrew/kernelsnoop/internal/ksnoop/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event  bpf ./tcp_connect.bpf.c -- -I../headers

func TcpConnect(ctx context.Context) {
	// Handle signals to gracefully shutdown the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

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

	link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.TcpConnect,
	})
	if err != nil {
		log.Error(fmt.Sprintf("failed to attach kprobe link: %v", err))
	}
	defer link.Close()

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Error(fmt.Sprintf("failed to create ring buffer reader: %v", err))
	}
	defer rd.Close()

	go func() {
		<-stopper
		if err := rd.Close(); err != nil {
			log.Error(fmt.Sprintf("closing ringbuf reader: %v", err))
		}
	}()

	// bpfEvent is generated by bpf2go.
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

		hostInfo, err := utils.GetIPInfo(intToIP(event.Daddr).String())
		if err != nil {
			log.Debug("error getting IP info from ip.guide: %s", err)
			hostInfo.Network.AutonomousSystem.Organization = "unknown"
		}

		virustotalInfo, err := utils.GetVirusTotalInfo(intToIP(event.Daddr).String())
		if err != nil {
			log.Debug("error getting VirusTotal info: %s", err)
		}

		log.Info("new connection",
			devstdout.Argument("comm", string(event.Comm[:bytes.IndexByte(event.Comm[:], 0)])),
			devstdout.Argument("src_addr", intToIP(event.Saddr)),
			devstdout.Argument("src_port", event.Sport),
			devstdout.Argument("dst_addr", intToIP(event.Daddr)),
			devstdout.Argument("dst_port", event.Dport),
			devstdout.Argument("host", hostInfo.Network.AutonomousSystem.Organization),
			devstdout.Argument("country", hostInfo.Location.Country),
			devstdout.Argument("latitude", hostInfo.Location.Latitude),
			devstdout.Argument("longitude", hostInfo.Location.Longitude),
			devstdout.Argument("virustotal", virustotalInfo),
		)
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}
