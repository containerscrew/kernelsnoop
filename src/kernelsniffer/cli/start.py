# from typing import Optional
import typer

# from cloudsnake.cli.dto import OutputMode
# from cloudsnake.sdk.ec2 import EC2InstanceWrapper

start = typer.Typer(
    no_args_is_help=True,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=False,
)


@start.command(
    "start",
    help="Start daemonized project",
)
def describe_instances(
    ctx: typer.Context,
):
    print("Starting daemonized project")
