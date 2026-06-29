#!/usr/bin/env python3
"""
Code Vulnerability Analyzer -- Multi-language static analysis tool.
Usage: python main.py [target] [options]
"""
from __future__ import annotations
import sys
import os
import argparse
from pathlib import Path
from typing import List, Optional

# Force UTF-8 output on Windows so Unicode chars render correctly
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    # Also set the console code page to UTF-8 when running interactively
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        pass

# Ensure the project root is on the path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.progress import Progress
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich import box as rbox
from rich.prompt import Prompt

from analyzer import __version__
from analyzer.models import Severity, Language, ScanResult
from analyzer.engine import ScanEngine
from analyzer.reporter import (
    console, print_banner, make_progress, print_report,
    export_json, export_html, print_error,
)
from analyzer.rules import rule_count

console = Console(highlight=False)


# ── Argument parsing ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnscan",
        description="Code Vulnerability Analyzer — Multi-language static analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py myapp/                     Scan directory recursively
  python main.py src/auth.py                Scan a single file
  python main.py . --severity HIGH          Report only HIGH and CRITICAL
  python main.py . --lang python java       Limit to Python and Java
  python main.py . --json report.json       Export JSON report
  python main.py . --html report.html       Export HTML report
  python main.py . --no-snippet             Skip code snippets
  python main.py . --flat                   Flat list sorted by severity
        """,
    )

    p.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Arquivo ou diretório a analisar (padrão: modo interativo)",
    )
    p.add_argument(
        "--severity", "-s",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="INFO",
        help="Minimum severity to report (default: INFO)",
    )
    p.add_argument(
        "--lang", "-l",
        nargs="+",
        metavar="LANGUAGE",
        help="Filter by language(s): python java javascript typescript csharp php go ruby c cpp sql cobol shell",
    )
    p.add_argument(
        "--json",
        metavar="FILE",
        help="Export findings as JSON to FILE",
    )
    p.add_argument(
        "--html",
        metavar="FILE",
        help="Export findings as HTML report to FILE",
    )
    p.add_argument(
        "--no-snippet",
        action="store_true",
        help="Do not display code snippets in output",
    )
    p.add_argument(
        "--no-comments",
        action="store_true",
        help="Skip findings detected inside comments",
    )
    p.add_argument(
        "--flat",
        action="store_true",
        help="Flat list sorted by severity (default: grouped by file)",
    )
    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Only print summary, suppress individual findings",
    )
    p.add_argument(
        "--rules",
        action="store_true",
        help="Listar todas as regras disponíveis e sair",
    )
    p.add_argument(
        "--list-langs", "--langs",
        action="store_true",
        dest="list_langs",
        help="Listar todas as 100 linguagens suportadas e sair",
    )
    p.add_argument(
        "--interactive", "-i",
        action="store_true",
        dest="interactive",
        help="Abre a interface TUI interativa (padrão quando nenhum alvo é passado)",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return p


# ── List languages ────────────────────────────────────────────────────────────

def cmd_list_langs() -> None:
    from analyzer.models import Language
    from analyzer.rules import LANGUAGE_RULES

    categories = Language.by_category()

    console.print()
    console.print(Panel(
        Text("  Linguagens Suportadas  ", style="bold bright_white", justify="center"),
        border_style="#444466",
        box=rbox.DOUBLE_EDGE,
    ))
    console.print()

    for cat_name, langs in categories.items():
        t = Table(
            title=f"[bold bright_cyan]{cat_name}[/]",
            box=rbox.SIMPLE,
            show_header=True,
            header_style="bold bright_white",
            padding=(0, 2),
            border_style="#333355",
        )
        t.add_column("Linguagem", min_width=20)
        t.add_column("ID Interno", style="dim", min_width=16)
        t.add_column("Regras Específicas", justify="right", min_width=8)

        for lang in langs:
            specific = len(LANGUAGE_RULES.get(lang, []))
            badge = f"[bold {lang.color()}]{lang.value}[/]"
            t.add_row(badge, lang.name, str(specific) if specific else "[dim]—[/dim]")

        console.print(t)
        console.print()


# ── List rules ────────────────────────────────────────────────────────────────

def cmd_list_rules() -> None:
    from rich.table import Table
    from rich import box as rbox
    from analyzer.rules import get_all_rules

    rules = get_all_rules()

    table = Table(
        title=f"[bold bright_white]Available Rules ({len(rules)} total)[/]",
        box=rbox.SIMPLE_HEAVY,
        border_style="#444466",
        show_lines=False,
        header_style="bold bright_cyan",
        padding=(0, 1),
    )
    table.add_column("ID", min_width=10, style="bright_black")
    table.add_column("Severity", min_width=10)
    table.add_column("Language", min_width=12)
    table.add_column("Category", min_width=24)
    table.add_column("Name")
    table.add_column("CWE", min_width=10, style="dim")

    from analyzer.reporter import SEVERITY_COLORS
    for rule in sorted(rules, key=lambda r: (-r.severity.value, r.id)):
        color = SEVERITY_COLORS[rule.severity]
        table.add_row(
            rule.id,
            Text(rule.severity.name, style=f"bold {color}"),
            Text(rule.language.value, style=rule.language.color()),
            rule.category.value,
            rule.name,
            rule.cwe or "",
        )

    console.print()
    console.print(table)
    console.print()


# ── Language filter ───────────────────────────────────────────────────────────

_LANG_NAME_MAP: dict[str, Language] = {
    "python": Language.PYTHON,
    "py": Language.PYTHON,
    "javascript": Language.JAVASCRIPT,
    "js": Language.JAVASCRIPT,
    "typescript": Language.TYPESCRIPT,
    "ts": Language.TYPESCRIPT,
    "java": Language.JAVA,
    "csharp": Language.CSHARP,
    "cs": Language.CSHARP,
    "php": Language.PHP,
    "go": Language.GO,
    "golang": Language.GO,
    "ruby": Language.RUBY,
    "rb": Language.RUBY,
    "c": Language.C,
    "cpp": Language.CPP,
    "c++": Language.CPP,
    "sql": Language.SQL,
    "cobol": Language.COBOL,
    "shell": Language.SHELL,
    "sh": Language.SHELL,
    "bash": Language.SHELL,
    "kotlin": Language.KOTLIN,
    "swift": Language.SWIFT,
    "rust": Language.RUST,
    "rs": Language.RUST,
    "scala": Language.SCALA,
    "perl": Language.PERL,
}


def parse_languages(names: List[str]) -> List[Language]:
    result: List[Language] = []
    for name in names:
        lang = _LANG_NAME_MAP.get(name.lower())
        if lang:
            result.append(lang)
        else:
            console.print(f"[yellow]Warning:[/yellow] Unknown language '{name}' — ignored.")
    return result or []


# ── Progress tracking ─────────────────────────────────────────────────────────

class ScanTracker:
    def __init__(self, progress: Progress, task_id: int) -> None:
        self.progress = progress
        self.task_id = task_id
        self.current_file = ""

    def on_file_start(self, path: str) -> None:
        self.current_file = Path(path).name
        self.progress.update(self.task_id, description=f"[cyan]{self.current_file[:50]}[/cyan]")

    def on_file_done(self, result: ScanResult) -> None:
        self.progress.advance(self.task_id)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    num_rules = rule_count()
    print_banner(num_rules)

    if args.rules:
        cmd_list_rules()
        return 0

    if args.list_langs:
        cmd_list_langs()
        return 0

    target = args.target

    # ── TUI interativo ────────────────────────────────────────────────────────
    if target is None or args.interactive:
        from analyzer.tui import run_tui
        start = Path(target) if target else None
        run_tui(start)
        return 0

    target_path = Path(target)

    if not target_path.exists():
        print_error(f"Alvo não encontrado: {target}")
        return 2

    min_severity = Severity[args.severity]
    languages = parse_languages(args.lang) if args.lang else None

    # Collect files to estimate total for progress bar
    if target_path.is_dir():
        from analyzer.engine import ScanEngine as _E
        from analyzer.detector import is_scannable, SKIP_DIRS
        files: List[Path] = []
        for item in target_path.rglob("*"):
            if item.is_file() and is_scannable(str(item)):
                skip = False
                try:
                    rel = item.relative_to(target_path)
                    for part in rel.parts[:-1]:
                        if part in SKIP_DIRS:
                            skip = True
                            break
                except ValueError:
                    pass
                if not skip:
                    files.append(item)
        total_files = len(files)
    else:
        total_files = 1

    console.print(
        f"  [dim]Scanning[/dim] [bold bright_cyan]{target}[/bold bright_cyan]  "
        f"[dim]({total_files} file{'s' if total_files != 1 else ''})[/dim]"
    )
    console.print()

    with make_progress() as progress:
        task_id = progress.add_task("Scanning...", total=total_files)
        tracker = ScanTracker(progress, task_id)

        engine = ScanEngine(
            min_severity=min_severity,
            languages=languages,
            include_comments=not args.no_comments,
            on_file_start=tracker.on_file_start,
            on_file_done=tracker.on_file_done,
        )

        if target_path.is_dir():
            report = engine.scan_directory(target)
        else:
            report = engine.scan_files([target])

        progress.update(task_id, description="[bold bright_green]Done![/bold bright_green]", completed=total_files)

    console.print()

    if not args.quiet:
        print_report(
            report,
            show_snippets=not args.no_snippet,
            group_by_file=not args.flat,
        )
    else:
        from analyzer.reporter import print_summary
        print_summary(report)

    if args.json:
        export_json(report, args.json)

    if args.html:
        export_html(report, args.html)

    # Exit code: 0 = clean, 1 = issues found, 2 = error
    if report.critical_count > 0 or report.high_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)
