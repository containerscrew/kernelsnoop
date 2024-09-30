# kernelsnoop

What's going on down there? Kernel sniffing using eBPF.

I want to learn how to create my own applications to simply monitor my computer. I don't know how far this will go.

I am practicing everything I learned in [this book](https://isovalent.com/books/learning-ebpf).


<!-- START OF TOC !DO NOT EDIT THIS CONTENT MANUALLY-->
**Table of Contents**  *generated with [mtoc](https://github.com/containerscrew/mtoc)*
- [kernelsnoop](#kernelsnoop)
- [About](#about)
- [Available tools](#available-tools)
- [Local development](#local-development)
  - [Requirements](#requirements)
  - [pre-commit](#pre-commit)
  - [Stuff](#stuff)
- [Ideas](#ideas)
- [Useful links](#useful-links)
<!-- END OF TOC -->

# About

...pending to add

# Available tools

* Shell readline: read every user command for bash, zsh and sh.
* In progress: file access. Read file, access to a file, write a file.

# Local development

## Requirements

System package dependencies are **MANDATORY**.

Since I'm using the framework `ebpf-go` from Cilium, see the [required dependencies](https://ebpf-go.dev/guides/getting-started/#ebpf-c-program) in their official documentation.


## pre-commit

Please, **install pre-commit before push your changes**

```bash
pre-commit install
# or run once
pre-commit run -a
```

## Stuff

* Generate `vmlinux.h`:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/headers/vmlinux.h
```

* Look for available tracepoints:

```bash
sudo bpftrace -l 'tracepoint:*'
```

* Other:

```bash
sudo cat /sys/kernel/debug/tracing/events/ext4/ext4_free_inode/format
```

* Stuff

```
curl -sL ip.guide/bulk/asns.csv
```

# Ideas

1. User Activity Monitor
2. Network connection tracker
3. Real-Time File Access Watchdog


# Useful links

* https://nvd.codes/post/monitor-any-command-typed-at-a-shell-with-ebpf/
* https://eunomia.dev/
* https://github.com/cilium/ebpf
* https://docs.fluentbit.io/manual/pipeline/outputs/influxdb
* https://docs.influxdata.com/influxdb/v2/install/use-docker-compose/
* https://github.com/ruanbekker/docker-promtail-loki/tree/main
