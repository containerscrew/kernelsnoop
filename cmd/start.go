package cmd

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	logger "github.com/containerscrew/devstdout/pkg"
)

func Start() {
	// Initialite the logger
	log := logger.NewLogger(
		logger.OptionsLogger{Level: "info", AddSource: true, LoggerType: "pretty"},
	)

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	// var objs counterObjects
	// if err := loadCounterObjects(&objs, nil); err != nil {
	//     log.Error("Loading eBPF objects:", err)
	// }
	// defer objs.Close()

	// ifname := "enp0s20f0u1u3" // Change this to an interface on your machine.

	// iface, err := net.InterfaceByName(ifname)
	// if err != nil {
	//     log.Error("Getting interface %s: %s", ifname, err)
	// }

	// // Attach count_packets to the network interface.
	// link, err := link.AttachXDP(link.XDPOptions{
	//     Program:   objs.CountPackets,
	//     Interface: iface.Index,
	// })
	// if err != nil {
	//     log.Error("Attaching XDP:", err)
	// }
	// defer link.Close()

	// log.Info("Counting incoming packets on", logger.PrintMessage("interface", ifname))

	// // Periodically fetch the packet counter from PktCount,
	// // exit the program when interrupted.
	// tick := time.Tick(time.Second)
	// stop := make(chan os.Signal, 5)
	// signal.Notify(stop, os.Interrupt)
	// for {
	//     select {
	//     case <-tick:
	//         var count uint64
	//         err := objs.PktCount.Lookup(uint32(0), &count)
	//         if err != nil {
	//             log.Error("Map lookup:", err)
	//         }
	//         log.Info(fmt.Sprintf("Received %d packets", count))
	//     case <-stop:
	//         log.Info("Received signal, exiting..")
	//         return
	//     }
	// }
}
