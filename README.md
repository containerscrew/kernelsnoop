# kernelsnoop

<!-- START OF TOC !DO NOT EDIT THIS CONTENT MANUALLY-->
**Table of Contents**  *generated with [mtoc](https://github.com/containerscrew/mtoc)*
- [kernelsnoop](#kernelsnoop)
- [Setup vscode interpreter for poetr](#setup-vscode-interpreter-for-poetr)
- [Steps](#steps)
- [Local development](#local-development)
  - [Requirements](#requirements)
<!-- END OF TOC -->
# Setup vscode interpreter for poetr

```shell
poetry env info --path | pbcopy
```

# Steps

```bash
make install
```

# Local development

## Requirements

* **Install poetry cli in your local machine!**

```bash
git clone https://github.com/containerscrew/kernelsnoop.git
cd kernelsnoop
# make your changes
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
