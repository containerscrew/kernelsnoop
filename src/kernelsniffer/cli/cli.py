from dataclasses import dataclass
from typing import Optional
import typer
from importlib.metadata import version

from kernelsniffer.app.config import Config, load_config

# App version reading the package version from the pyproject.toml
app_version = version("kernelsniffer")

# Main app Typer
app = typer.Typer(
    no_args_is_help=True,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=False,
)


@app.command(
    "start",
    help="Start daemonized project",
)
def start(
    ctx: typer.Context,
):
    config = ctx.obj.config
    print(config.daemon.enabled)
    print("Starting daemonized project")


# Add subcommands to the main typer
# app.add_typer(test, name="test", help="test")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(
            typer.style(
                f"Using kernelsniffer version: v{app_version}",
                fg=typer.colors.GREEN,
                bold=True,
            )
        )
        raise typer.Exit()


@dataclass
class Common:
    config: Config


@app.callback()
def entrypoint(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the application's version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
):
    """
    kernelsniffer: Sniff what happens in the kernel.
    """
    # Write something you need to do before the program starts
    config = load_config()
    ctx.obj = Common(config=config)
    print("Starting kernelsniffer")
