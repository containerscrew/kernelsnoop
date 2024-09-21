package ebpftools

import (
    "log"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
)

// main is the entry point of the Go program
func NewHelloWorld() {
    // Load the compiled BPF program into an eBPF collection
    // "hello_world_bpf" is the prefix of the generated BPF object
    spec, err := loadHello_world_bpf()
    if err != nil {
        log.Fatalf("Error loading BPF program: %v", err)
    }

    // Create a new BPF collection, which holds programs and maps from the loaded BPF object
    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        log.Fatalf("Error creating BPF collection: %v", err)
    }
    // Ensure the collection is closed after usage
    defer coll.Close()

    // Attach the kprobe to the syscall "sys_execve"
    // This links our BPF program to the kernel function that handles execve
    kprobe, err := link.Kprobe("sys_execve", coll.Programs["hello"], nil)
    if err != nil {
        log.Fatalf("Error attaching kprobe: %v", err)
    }
    // Ensure the kprobe is detached when we're done
    defer kprobe.Close()

    log.Println("Successfully attached kprobe to sys_execve")

    // Use the perf reader to capture messages from bpf_printk (like "I'm alive!")
    rd, err := perf.NewReader(coll.Maps["events"], 4096)
    if err != nil {
        log.Fatalf("Error creating perf reader: %v", err)
    }
    // Ensure the reader is closed after use
    defer rd.Close()

    // Infinite loop to read messages sent by the BPF program through bpf_printk
    for {
        // Read one record (message) at a time
        record, err := rd.Read()
        if err != nil {
            log.Fatalf("Error reading from perf event: %v", err)
        }

        // Print the message from bpf_printk to the console
        log.Printf("BPF message: %s", string(record.RawSample))
    }
}
