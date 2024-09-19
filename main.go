package main

import (
	"github.com/containerscrew/kernelsnoop/internal/ebpftools"
)


func main() {
	ebpftools.StartNetworkSniffer()
}
