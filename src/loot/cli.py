"""The loot command line.

`loot` (or `loot scan`) looks where infostealers look and prints what they would get,
graded, with a fix per line. Read-only. Nothing leaves your machine. Secrets are masked.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.text import Text

from . import __version__
from .machine import Machine
from .output import print_paths, print_result, to_json
from .scanners import SCANNERS, scan

CONTEXT = {"help_option_names": ["-h", "--help"], "max_content_width": 100}
_DEBUG = False


def _machine(home: str | None, system: str | None) -> Machine:
    if home:
        return Machine.fake(Path(home), system=system or "linux")
    m = Machine.current()
    if system:
        m.system = system
    return m


@click.group(context_settings=CONTEXT, invoke_without_command=True)
@click.version_option(__version__, prog_name="loot")
@click.option("--debug", is_flag=True, help="Show full tracebacks.")
@click.pass_context
def cli(ctx: click.Context, debug: bool) -> None:
    """See what an infostealer would take from this machine, then empty the list.

    Read-only. Nothing leaves your machine. Secrets are never printed in full.
    Run with no arguments to scan.
    """
    global _DEBUG
    _DEBUG = debug
    if ctx.invoked_subcommand is None:
        ctx.invoke(scan_cmd)


@cli.command("scan")
@click.option("--all", "show_all", is_flag=True, help="Also show positive notes (things you are doing right).")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@click.option("--only", multiple=True, type=click.Choice([n for n, _ in SCANNERS]), help="Run only these scanners. Repeatable.")
@click.option("--fail-on", type=click.Choice(["critical", "high", "none"]), default="none", show_default=True, help="Exit 1 if findings of this severity or worse exist. For CI and dotfile checks.")
@click.option("--home", type=click.Path(file_okay=False, exists=True), help="Scan another folder as if it were a home directory. Try it on the demo: `python demo/plant.py /tmp/demo && loot scan --home /tmp/demo`.")
@click.option("--system", type=click.Choice(["linux", "darwin", "windows"]), help="Use this OS's path layout (default: the one you are on).")
def scan_cmd(show_all: bool, as_json: bool, only: tuple[str, ...], fail_on: str, home: str | None, system: str | None) -> None:
    """Look where infostealers look. Default command."""
    m = _machine(home, system)
    result = scan(m, only=only or None)
    if as_json:
        click.echo(json.dumps(to_json(result), indent=2, ensure_ascii=False))
    else:
        print_result(Console(), result, show_all=show_all)
    if fail_on != "none":
        bad = {"critical": ("critical",), "high": ("critical", "high")}[fail_on]
        if any(f.severity in bad for f in result.findings):
            sys.exit(1)


@cli.command("paths")
def paths_cmd() -> None:
    """List the places loot checks, and what a stealer gets from each."""
    print_paths(Console())


def main(argv: list[str] | None = None) -> int:
    try:
        cli.main(args=argv, prog_name="loot", standalone_mode=True)
    except KeyboardInterrupt:
        Console(stderr=True).print(Text("loot: interrupted.", style="yellow"))
        sys.exit(130)
    except SystemExit:
        raise
    except OSError as exc:
        if exc.errno in (22, 32):  # broken pipe, e.g. `loot | head`
            sys.exit(0)
        raise
    except Exception as exc:  # noqa: BLE001 - never show a stack trace by default
        if _DEBUG:
            raise
        Console(stderr=True, highlight=False).print(Text(f"loot: unexpected error: {exc!r}. Re-run with --debug for the traceback.", style="bold red"))
        sys.exit(3)
    return 0


if __name__ == "__main__":  # pragma: no cover
    main()
