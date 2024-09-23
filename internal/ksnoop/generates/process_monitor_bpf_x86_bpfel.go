// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package generates

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type Process_monitor_bpfProcessInfo struct {
	Pid  uint32
	Uid  uint32
	Gid  uint32
	Comm [16]int8
}

// LoadProcess_monitor_bpf returns the embedded CollectionSpec for Process_monitor_bpf.
func LoadProcess_monitor_bpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Process_monitor_bpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Process_monitor_bpf: %w", err)
	}

	return spec, err
}

// LoadProcess_monitor_bpfObjects loads Process_monitor_bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*Process_monitor_bpfObjects
//	*Process_monitor_bpfPrograms
//	*Process_monitor_bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadProcess_monitor_bpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadProcess_monitor_bpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// Process_monitor_bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type Process_monitor_bpfSpecs struct {
	Process_monitor_bpfProgramSpecs
	Process_monitor_bpfMapSpecs
}

// Process_monitor_bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type Process_monitor_bpfProgramSpecs struct {
	KprobeProcess *ebpf.ProgramSpec `ebpf:"kprobe_process"`
}

// Process_monitor_bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type Process_monitor_bpfMapSpecs struct {
	KprobeMap *ebpf.MapSpec `ebpf:"kprobe_map"`
}

// Process_monitor_bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadProcess_monitor_bpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type Process_monitor_bpfObjects struct {
	Process_monitor_bpfPrograms
	Process_monitor_bpfMaps
}

func (o *Process_monitor_bpfObjects) Close() error {
	return _Process_monitor_bpfClose(
		&o.Process_monitor_bpfPrograms,
		&o.Process_monitor_bpfMaps,
	)
}

// Process_monitor_bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadProcess_monitor_bpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type Process_monitor_bpfMaps struct {
	KprobeMap *ebpf.Map `ebpf:"kprobe_map"`
}

func (m *Process_monitor_bpfMaps) Close() error {
	return _Process_monitor_bpfClose(
		m.KprobeMap,
	)
}

// Process_monitor_bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadProcess_monitor_bpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type Process_monitor_bpfPrograms struct {
	KprobeProcess *ebpf.Program `ebpf:"kprobe_process"`
}

func (p *Process_monitor_bpfPrograms) Close() error {
	return _Process_monitor_bpfClose(
		p.KprobeProcess,
	)
}

func _Process_monitor_bpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed process_monitor_bpf_x86_bpfel.o
var _Process_monitor_bpfBytes []byte
