# kernelsnoop

<!-- START OF TOC !DO NOT EDIT THIS CONTENT MANUALLY-->
**Table of Contents**  *generated with [mtoc](https://github.com/containerscrew/mtoc)*
- [kernelsnoop](#kernelsnoop)
- [Local development](#local-development)
  - [Requirements](#requirements)
  - [pre-commit](#pre-commit)
  - [Stuff](#stuff)
- [Ideas](#ideas)
<!-- END OF TOC -->

# Local development

## Requirements

**pending to add**


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
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

* Look for available tracepoints:

```bash
sudo bpftrace -l 'tracepoint:*'
```

# Ideas

1. User Activity Monitor
2. Network connection tracker
3. Real-Time File Access Watchdog
