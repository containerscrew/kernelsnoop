import argparse
from importlib.metadata import version


app_version = version("kernelsnoop")


def parse_args():
    """
    Parse command line arguments.
    All the application behavior is defined in config.toml
    However, the user can use the flag --version to check the version of the application.
    """
    parser = argparse.ArgumentParser(
        description="""Sniffing the kernel for fun and profit usin eBPF.""",
        add_help=True,
        prog="kernelsnoop",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {app_version}"
    )

    return parser.parse_args()
