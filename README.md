# kernelsnoop

<!-- START OF TOC !DO NOT EDIT THIS CONTENT MANUALLY-->
**Table of Contents**  *generated with [mtoc](https://github.com/containerscrew/mtoc)*
- [kernelsnoop](#kernelsnoop)
- [Local development](#local-development)
  - [Requirements](#requirements)
  - [Running kernelsnoop](#running-kernelsnoop)
  - [Setup vscode interpreter for poetry](#setup-vscode-interpreter-for-poetry)
  - [pre-commit](#pre-commit)
  - [Stuff](#stuff)
<!-- END OF TOC -->

# Local development

## Requirements

* **Install poetry cli in your local machine!**

## Running kernelsnoop

```bash
git clone https://github.com/containerscrew/kernelsnoop.git
cd kernelsnoop
# make your changes
python3 -m venv --system-site-packages .venv # Allow use system libraries, like python-bcc
poetry install
poetry update
# run the code
poetry run python3 src/kernelsnoop/__main__.py
# check version
poetry run python3 src/kernelsnoop/__main__.py --version
# kill the process running in the foreground
killall python3
```

> Also take a look to the [Makefile](./Makefile). You will see some useful commands.


## Setup vscode interpreter for poetry

```shell
poetry env info --path | pbcopy
# now press CONTRL+SHIFT+P and setup the interpreter of the project to this path yoy copied in the previous command
```

## pre-commit

Please, **install pre-commit before push your changes**

```bash
pre-commit install
# or run once
pre-commit run -a
```

## Stuff


Generate `vmlinux.h`:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```
