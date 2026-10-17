"""Terminal output with rich. No scanning in here."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .findings import CATEGORIES, SEVERITIES, Finding, counts, score, sort_key
from .scanners import TARGETS, ScanResult

SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "green"}
GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}


def _sev(s: str) -> Text:
    return Text(s, style=SEV_STYLE.get(s, ""))


def print_result(console: Console, result: ScanResult, *, show_all: bool = False, max_fix_first: int = 8) -> None:
    findings = sorted(result.findings, key=sort_key)
    points, grade = score(findings)
    c = counts(findings)

    head = Text()
    head.append("Grade ")
    head.append(grade, style=GRADE_STYLE[grade])
    head.append(f"  ({points}/100)\n")
    head.append("If an infostealer ran on this machine right now, it would leave with:\n")
    for s in SEVERITIES:
        if s == "info":
            continue
        head.append(f"  {c[s]:>3} {s}", style=SEV_STYLE[s])
        head.append("\n")
    head.append(f"Scanned: {', '.join(result.ran)}. Nothing left this machine. Values are masked.", style="dim")
    console.print(Panel(head, title="loot", border_style=GRADE_STYLE[grade].replace("bold ", "")))

    worst = [f for f in findings if f.severity in ("critical", "high")][:max_fix_first]
    if worst:
        t = Table(title="Fix these first", box=box.SIMPLE_HEAVY, show_lines=True, expand=True)
        t.add_column("#", justify="right", no_wrap=True)
        t.add_column("Sev", no_wrap=True)
        t.add_column("What", ratio=3, min_width=22)
        t.add_column("Where", ratio=2, min_width=16, overflow="fold")
        t.add_column("Fix", ratio=5, min_width=30)
        for i, f in enumerate(worst, 1):
            t.add_row(str(i), _sev(f.severity), f.title, f.where, f.fix)
        console.print(t)

    shown = [f for f in findings if show_all or f.severity != "info"]
    for cat in CATEGORIES:
        group = [f for f in shown if f.category == cat]
        if not group:
            continue
        t = Table(title=cat, title_justify="left", box=box.SIMPLE_HEAVY, expand=True)
        t.add_column("Sev", no_wrap=True)
        t.add_column("Finding", ratio=3, min_width=22)
        t.add_column("Where", ratio=2, min_width=16, overflow="fold")
        t.add_column("Evidence", ratio=2, min_width=12, overflow="fold")
        t.add_column("What it unlocks", ratio=4, min_width=24)
        for f in group:
            notes = ("  [yellow](" + "; ".join(f.notes) + ")[/yellow]") if f.notes else ""
            t.add_row(_sev(f.severity), Text.from_markup(f"{f.title}{notes}"), f.where, f.evidence or "", f.unlocks)
        console.print(t)

    if not findings:
        console.print("[green]Nothing found in the places stealers look. Either you are careful, or you are not a developer.[/green]")
    if result.errors:
        console.print("[yellow]Some checks could not run:[/yellow]")
        for name, err in result.errors.items():
            console.print(f"  - {name}: {err}")
    infos = [f for f in findings if f.severity == "info"]
    if infos and not show_all:
        console.print(f"[dim]{len(infos)} positive note{'s' if len(infos) != 1 else ''} hidden; run with --all to see them.[/dim]")
    console.print()
    console.print("[bold]Next:[/bold] work down the list, then run [bold]loot[/bold] again. The grade is the point: make it go up.")


def print_paths(console: Console) -> None:
    t = Table(title="Where infostealers look, and what they get", box=box.SIMPLE_HEAVY)
    t.add_column("Category", no_wrap=True)
    t.add_column("Paths")
    t.add_column("What a stealer walks away with")
    for cat, paths, what in TARGETS:
        t.add_row(cat, paths, what)
    console.print(t)
    console.print("[dim]loot reads these (and only these). Browser and wallet files are noticed, never opened.[/dim]")


def to_json(result: ScanResult) -> dict:
    findings = sorted(result.findings, key=sort_key)
    points, grade = score(findings)
    return {
        "grade": grade,
        "score": points,
        "counts": counts(findings),
        "scanned": list(result.ran),
        "errors": dict(result.errors),
        "findings": [f.to_dict() for f in findings],
    }
