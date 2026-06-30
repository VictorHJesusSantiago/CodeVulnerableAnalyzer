from __future__ import annotations
import json
import re
import time
from pathlib import Path
from typing import Optional, List
from collections import defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule as RichRule
from rich.padding import Padding
from rich.align import Align
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeElapsedColumn, MofNCompleteColumn,
)
from rich.syntax import Syntax
from rich.style import Style
from rich import box

from analyzer.models import (
    Severity, Language, VulnCategory,
    Vulnerability, ScanResult, ScanReport,
)
from analyzer.rules import rule_count

import sys as _sys
if _sys.platform == "win32":
    try:
        _sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass
console = Console(highlight=False)

# ── Palette ──────────────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    Severity.CRITICAL: "#ff2244",
    Severity.HIGH:     "#ff6600",
    Severity.MEDIUM:   "#ffcc00",
    Severity.LOW:      "#33aaff",
    Severity.INFO:     "#888888",
}

SEVERITY_BG = {
    Severity.CRITICAL: "on #7a0010",
    Severity.HIGH:     "on #7a2e00",
    Severity.MEDIUM:   "on #5a4a00",
    Severity.LOW:      "on #003366",
    Severity.INFO:     "on #2a2a2a",
}

LANG_SYNTAX_MAP: dict[Language, str] = {
    Language.PYTHON:      "python",
    Language.JAVASCRIPT:  "javascript",
    Language.TYPESCRIPT:  "typescript",
    Language.JAVA:        "java",
    Language.CSHARP:      "csharp",
    Language.PHP:         "php",
    Language.GO:          "go",
    Language.RUBY:        "ruby",
    Language.C:           "c",
    Language.CPP:         "cpp",
    Language.SQL:         "sql",
    Language.PLSQL:       "sql",
    Language.TSQL:        "sql",
    Language.COBOL:       "text",
    Language.SHELL:       "bash",
    Language.BASH:        "bash",
    Language.POWERSHELL:  "powershell",
    Language.BATCH:       "batch",
    Language.AWK:         "awk",
    Language.KOTLIN:      "kotlin",
    Language.SWIFT:       "swift",
    Language.RUST:        "rust",
    Language.SCALA:       "scala",
    Language.PERL:        "perl",
    Language.DART:        "dart",
    Language.OBJECTIVEC:  "objective-c",
    Language.GROOVY:      "groovy",
    Language.VBNET:       "vbnet",
    Language.COLDFUSION:  "html",
    Language.RUBY:        "ruby",
    Language.HASKELL:     "haskell",
    Language.ERLANG:      "erlang",
    Language.ELIXIR:      "elixir",
    Language.CLOJURE:     "clojure",
    Language.FSHARP:      "fsharp",
    Language.OCAML:       "ocaml",
    Language.SCHEME:      "scheme",
    Language.LISP:        "common-lisp",
    Language.PROLOG:      "prolog",
    Language.JULIA:       "julia",
    Language.ELM:         "elm",
    Language.COFFEESCRIPT: "coffeescript",
    Language.LUA:         "lua",
    Language.TCL:         "tcl",
    Language.HTML:        "html",
    Language.CSS:         "css",
    Language.SCSS:        "scss",
    Language.SASS:        "sass",
    Language.LESS:        "less",
    Language.SVG:         "xml",
    Language.XML:         "xml",
    Language.JSON:        "json",
    Language.YAML:        "yaml",
    Language.TOML:        "toml",
    Language.INI:         "ini",
    Language.PROTOBUF:    "protobuf",
    Language.MARKDOWN:    "markdown",
    Language.GRAPHQL:     "graphql",
    Language.TERRAFORM:   "hcl",
    Language.DOCKERFILE:  "docker",
    Language.SOLIDITY:    "solidity",
    Language.MATLAB:      "matlab",
    Language.R:           "r",
    Language.FORTRAN:     "fortran",
    Language.ADA:         "ada",
    Language.PASCAL:      "pascal",
    Language.ASSEMBLY:    "nasm",
    Language.NIM:         "nim",
    Language.CRYSTAL:     "crystal",
    Language.PUG:         "pug",
    Language.HANDLEBARS:  "html",
    Language.EJS:         "html",
    Language.LIQUID:      "html",
    Language.ACTIONSCRIPT: "actionscript",
    Language.APEX:        "java",
    Language.SMALLTALK:   "smalltalk",
}


# ── Banner ────────────────────────────────────────────────────────────────────

BANNER_LINES = [
    ("  ██████╗ ██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗  ██╗  ", "#ff2244"),
    (" ██╔════╝ ██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗ ██║  ", "#ff5500"),
    (" ██║      ██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗██║  ", "#ffaa00"),
    (" ██║      ██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚████║  ", "#33dd66"),
    (" ╚██████╗ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚███║  ", "#33aaff"),
    ("  ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝  ", "#aa44ff"),
]


def print_banner(num_rules: int) -> None:
    from rich.table import Table as RichTable

    logo = Text(justify="center")
    for text, color in BANNER_LINES:
        logo.append(text + "\n", style=f"bold {color}")

    subtitle = Text(justify="center")
    subtitle.append("  VULNERABILITY ANALYZER  ", style="bold bright_white on #1a1a2e")
    subtitle.append("  Multi-Language · Static Analysis  ", style="dim white")
    subtitle.append(f"  {num_rules} Regras  ", style="bold cyan")
    subtitle.append("  100+ Linguagens  ", style="bold bright_magenta")
    subtitle.append("  v1.0.0  ", style="dim white")

    inner = RichTable.grid(padding=(0, 0))
    inner.add_column(justify="center")
    inner.add_row(logo)
    inner.add_row(subtitle)

    console.print()
    console.print(
        Panel(
            Padding(inner, (0, 2)),
            border_style="#444466",
            box=box.DOUBLE_EDGE,
            padding=(0, 1),
        )
    )
    console.print()


# ── Progress ──────────────────────────────────────────────────────────────────

def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn("[bold bright_white]{task.description}"),
        BarColumn(bar_width=40, style="cyan", complete_style="bright_cyan", finished_style="bright_green"),
        MofNCompleteColumn(),
        TextColumn("[dim]•[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


# ── Severity helpers ──────────────────────────────────────────────────────────

def _sev_badge(sev: Severity) -> Text:
    label = f" {sev.name:8} "
    color = SEVERITY_COLORS[sev]
    bg = SEVERITY_BG[sev]
    return Text(label, style=f"bold {color} {bg}")


def _sev_dot(sev: Severity) -> Text:
    return Text("●  ", style=f"bold {SEVERITY_COLORS[sev]}")


# ── Finding panel ─────────────────────────────────────────────────────────────

def _format_snippet(vuln: Vulnerability) -> Optional[Syntax]:
    if not vuln.snippet:
        return None
    syntax_lang = LANG_SYNTAX_MAP.get(vuln.language, "text")
    code = "\n".join(vuln.snippet)
    try:
        return Syntax(
            code,
            syntax_lang,
            theme="monokai",
            line_numbers=True,
            start_line=vuln.snippet_start_line,
            highlight_lines={vuln.line_number},
            word_wrap=True,
        )
    except Exception:
        return None


def print_finding(vuln: Vulnerability, show_snippet: bool = True) -> None:
    sev = vuln.severity
    color = SEVERITY_COLORS[sev]

    header = Text()
    header.append(_sev_dot(sev))
    header.append(_sev_badge(sev))
    header.append("  ")
    header.append(vuln.name, style=f"bold {color}")
    if vuln.in_comment:
        header.append("  [dim](in comment)[/dim]")

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="dim")
    meta.add_column()

    rel_path = vuln.file_path
    try:
        rel_path = str(Path(vuln.file_path).resolve())
    except Exception:
        pass

    meta.add_row("File",     f"[bold white]{rel_path}[/bold white]  :[bold yellow]{vuln.line_number}[/bold yellow]")
    meta.add_row("Rule",     f"[bright_black]{vuln.rule_id}[/bright_black]")

    refs: List[str] = []
    if vuln.cwe:
        refs.append(f"[cyan]{vuln.cwe}[/cyan]")
    if vuln.owasp:
        refs.append(f"[bright_magenta]{vuln.owasp}[/bright_magenta]")
    if refs:
        meta.add_row("Refs", "  ".join(refs))

    meta.add_row("Category",  f"[bright_blue]{vuln.category.value}[/bright_blue]")
    meta.add_row("Confidence", vuln.confidence.label())
    meta.add_row("Language",   f"[{vuln.language.color()}]{vuln.language.value}[/]")

    desc_text = Text(vuln.description, style="white")
    remed_text = Text(vuln.remediation, style="bright_green")

    body_table = Table.grid(padding=(0, 1))
    body_table.add_column()
    body_table.add_row(meta)
    body_table.add_row(Text(""))
    body_table.add_row(Text("Description", style="bold bright_white"))
    body_table.add_row(desc_text)
    body_table.add_row(Text(""))
    body_table.add_row(Text("Remediation", style="bold bright_green"))
    body_table.add_row(remed_text)

    if show_snippet:
        syntax = _format_snippet(vuln)
        if syntax:
            body_table.add_row(Text(""))
            body_table.add_row(Text("Code Snippet", style="bold bright_yellow"))
            body_table.add_row(syntax)

    console.print(
        Panel(
            body_table,
            title=header,
            title_align="left",
            border_style=color,
            padding=(0, 1),
        )
    )


# ── File section header ───────────────────────────────────────────────────────

def print_file_header(result: ScanResult) -> None:
    n = len(result.vulnerabilities)
    lang_color = result.language.color()

    row = Text()
    row.append("  📄  ", style="dim")
    row.append(result.file_path, style="bold white")
    row.append("  ", style="dim")
    row.append(f"[{result.language.value}]", style=f"bold {lang_color}")
    row.append(f"  {n} issue{'s' if n != 1 else ''}  ", style="bold red" if n > 0 else "dim")

    console.print(RichRule(row, style="#333355", align="left"))


# ── Summary ───────────────────────────────────────────────────────────────────

def _make_bar(count: int, max_count: int, width: int = 28, color: str = "cyan") -> Text:
    if max_count == 0:
        return Text("")
    filled = int(width * count / max_count) if max_count > 0 else 0
    bar = Text()
    bar.append("█" * filled, style=f"bold {color}")
    bar.append("░" * (width - filled), style="bright_black")
    return bar


def print_summary(report: ScanReport) -> None:
    console.print()
    console.print(RichRule("[bold bright_white] SCAN COMPLETE [/bold bright_white]", style="#444466"))
    console.print()

    # ── Meta info table ───────────────────────────────────────────────────────
    meta = Table(box=box.SIMPLE_HEAVY, border_style="#444466", show_header=False, padding=(0, 2))
    meta.add_column(style="dim", min_width=22)
    meta.add_column(style="bold white")

    meta.add_row("Target",          f"[bright_cyan]{report.target}[/bright_cyan]")
    meta.add_row("Files Scanned",   str(report.files_scanned))
    meta.add_row("Files With Issues", f"[bold {'red' if report.files_with_issues else 'green'}]{report.files_with_issues}[/]")
    meta.add_row("Total Issues",    f"[bold {'red' if report.total_vulnerabilities else 'green'}]{report.total_vulnerabilities}[/]")
    meta.add_row("Scan Time",       f"{report.total_time:.2f}s")
    if report.languages_found:
        langs = "  ".join(f"[{Language(l).color()}]{l}[/]" for l in report.languages_found)
        meta.add_row("Languages",   langs)

    # ── Severity breakdown ────────────────────────────────────────────────────
    counts = {
        Severity.CRITICAL: report.critical_count,
        Severity.HIGH:     report.high_count,
        Severity.MEDIUM:   report.medium_count,
        Severity.LOW:      report.low_count,
        Severity.INFO:     report.info_count,
    }
    max_count = max(counts.values()) if counts.values() else 1

    sev_table = Table(box=None, show_header=False, padding=(0, 1))
    sev_table.add_column(min_width=10)
    sev_table.add_column(min_width=28)
    sev_table.add_column(min_width=6, justify="right")

    for sev, cnt in counts.items():
        bar = _make_bar(cnt, max_count, color=SEVERITY_COLORS[sev])
        label = Text(f" {sev.name:8}", style=f"bold {SEVERITY_COLORS[sev]}")
        count_text = Text(str(cnt), style=f"bold {SEVERITY_COLORS[sev]}" if cnt > 0 else "dim")
        sev_table.add_row(label, bar, count_text)

    # ── Category breakdown ────────────────────────────────────────────────────
    from analyzer.models import Vulnerability  # avoid circular at top
    all_vulns: List[Vulnerability] = [v for r in report.results for v in r.vulnerabilities]

    cat_counts: dict[str, int] = defaultdict(int)
    for v in all_vulns:
        cat_counts[v.category.value] += 1

    top_cats = sorted(cat_counts.items(), key=lambda x: -x[1])[:8]

    cat_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), border_style="bright_black")
    cat_table.add_column(min_width=32, style="bright_cyan")
    cat_table.add_column(min_width=6, justify="right", style="bold white")

    for cat, cnt in top_cats:
        cat_table.add_row(f"  {cat}", f"[bold white]{cnt}[/bold white]")

    # ── Layout (stacked for terminal compatibility) ───────────────────────────
    summary_content = Table.grid(padding=(0, 0))
    summary_content.add_column()
    summary_content.add_row(Panel(meta, title="[bold bright_white] Scan Info [/]", border_style="#335588", padding=(0, 2)))
    summary_content.add_row(Panel(sev_table, title="[bold bright_white] Severity Distribution [/]", border_style="#553388", padding=(0, 2)))

    if top_cats:
        summary_content.add_row(
            Panel(cat_table, title="[bold bright_white] Top Vulnerability Categories [/]", border_style="#225533", padding=(0, 2))
        )

    console.print(Panel(
        summary_content,
        box=box.DOUBLE_EDGE,
        border_style="#222244",
        title="[bold bright_white on #222244]  VULNERABILITY SCAN REPORT  [/]",
        padding=(1, 1),
    ))
    console.print()

    if report.total_vulnerabilities == 0:
        console.print(
            Align(
                Panel(
                    Text("✅  No vulnerabilities detected!", style="bold bright_green", justify="center"),
                    border_style="bright_green",
                    padding=(1, 4),
                ),
                align="center",
            )
        )
    else:
        sev_summary = Text(justify="center")
        sev_summary.append("  Summary:  ", style="bold white")
        for sev, cnt in counts.items():
            if cnt > 0:
                sev_summary.append(f"  {sev.name} {cnt}  ", style=f"bold {SEVERITY_COLORS[sev]} {SEVERITY_BG[sev]}")
        console.print(Align(sev_summary, align="center"))

    console.print()


# ── Report renderers ──────────────────────────────────────────────────────────

def print_report(report: ScanReport, show_snippets: bool = True, group_by_file: bool = True) -> None:
    files_with_vulns = [r for r in report.results if r.vulnerabilities]

    if not files_with_vulns:
        print_summary(report)
        return

    console.print()
    console.print(RichRule("[bold bright_white] FINDINGS [/bold bright_white]", style="#444466"))
    console.print()

    if group_by_file:
        for result in files_with_vulns:
            print_file_header(result)
            console.print()
            for vuln in result.vulnerabilities:
                print_finding(vuln, show_snippet=show_snippets)
                console.print()
    else:
        all_vulns = sorted(
            (v for r in files_with_vulns for v in r.vulnerabilities),
            key=lambda v: -v.severity.value,
        )
        for vuln in all_vulns:
            print_finding(vuln, show_snippet=show_snippets)
            console.print()

    print_summary(report)


# ── JSON export ───────────────────────────────────────────────────────────────

def export_json(report: ScanReport, output_path: str) -> None:
    data: dict = {
        "scan_info": {
            "target":             report.target,
            "files_scanned":      report.files_scanned,
            "files_with_issues":  report.files_with_issues,
            "total_vulnerabilities": report.total_vulnerabilities,
            "scan_time_seconds":  round(report.total_time, 3),
            "languages_found":    report.languages_found,
            "severity_summary": {
                "CRITICAL": report.critical_count,
                "HIGH":     report.high_count,
                "MEDIUM":   report.medium_count,
                "LOW":      report.low_count,
                "INFO":     report.info_count,
            },
        },
        "findings": [],
    }

    for result in report.results:
        for v in result.vulnerabilities:
            data["findings"].append({
                "rule_id":     v.rule_id,
                "name":        v.name,
                "severity":    v.severity.name,
                "category":    v.category.value,
                "language":    v.language.value,
                "file":        v.file_path,
                "line":        v.line_number,
                "code":        v.line_content,
                "description": v.description,
                "remediation": v.remediation,
                "cwe":         v.cwe,
                "owasp":       v.owasp,
                "confidence":  v.confidence.name,
                "in_comment":  v.in_comment,
            })

    Path(output_path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[bold bright_green]✔[/] JSON report saved → [cyan]{output_path}[/cyan]")


# ── HTML export ───────────────────────────────────────────────────────────────

_SEV_HTML_COLORS = {
    "CRITICAL": "#ff2244",
    "HIGH":     "#ff6600",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#33aaff",
    "INFO":     "#888888",
}

def export_html(report: ScanReport, output_path: str) -> None:
    from html import escape

    rows: List[str] = []
    for r in report.results:
        for v in r.vulnerabilities:
            color = _SEV_HTML_COLORS.get(v.severity.name, "#888")
            rows.append(f"""
            <tr>
                <td><span class="badge" style="background:{color}">{escape(v.severity.name)}</span></td>
                <td>{escape(v.rule_id)}</td>
                <td>{escape(v.name)}</td>
                <td>{escape(v.language.value)}</td>
                <td style="font-size:0.85em">{escape(v.file_path)}</td>
                <td style="text-align:center">{v.line_number}</td>
                <td>{escape(v.category.value)}</td>
                <td style="font-size:0.85em">{escape(v.cwe or '')}</td>
                <td style="font-size:0.8em">{escape(v.description[:100])}…</td>
            </tr>""")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Report — {escape(report.target)}</title>
<style>
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 2rem; }}
  h1 {{ color: #ff6600; }} h2 {{ color: #58a6ff; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }}
  th {{ background: #161b22; color: #8b949e; padding: 0.6rem 1rem; text-align: left; border-bottom: 2px solid #30363d; }}
  td {{ padding: 0.5rem 1rem; border-bottom: 1px solid #21262d; vertical-align: top; }}
  tr:hover td {{ background: #161b22; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; color: #000; font-weight: bold; font-size: 0.8rem; }}
  .stat {{ display: inline-block; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem 2rem; margin: 0.5rem; text-align: center; }}
  .stat-num {{ font-size: 2rem; font-weight: bold; }}
</style>
</head>
<body>
<h1>🔍 Vulnerability Scan Report</h1>
<p><strong>Target:</strong> {escape(report.target)}&nbsp;&nbsp;
   <strong>Files:</strong> {report.files_scanned}&nbsp;&nbsp;
   <strong>Issues:</strong> {report.total_vulnerabilities}&nbsp;&nbsp;
   <strong>Time:</strong> {report.total_time:.2f}s</p>

<div>
  <div class="stat"><div class="stat-num" style="color:#ff2244">{report.critical_count}</div>CRITICAL</div>
  <div class="stat"><div class="stat-num" style="color:#ff6600">{report.high_count}</div>HIGH</div>
  <div class="stat"><div class="stat-num" style="color:#ffcc00">{report.medium_count}</div>MEDIUM</div>
  <div class="stat"><div class="stat-num" style="color:#33aaff">{report.low_count}</div>LOW</div>
  <div class="stat"><div class="stat-num" style="color:#888">{report.info_count}</div>INFO</div>
</div>

<h2>Findings</h2>
<table>
<thead>
  <tr><th>Severity</th><th>Rule</th><th>Name</th><th>Language</th><th>File</th><th>Line</th><th>Category</th><th>CWE</th><th>Description</th></tr>
</thead>
<tbody>{"".join(rows)}</tbody>
</table>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    console.print(f"[bold bright_green]✔[/] HTML report saved → [cyan]{output_path}[/cyan]")


# ── SARIF 2.1 export ─────────────────────────────────────────────────────────

def export_sarif(report: ScanReport, output_path: str) -> None:
    """Exporta resultados no formato SARIF 2.1.0 (GitHub Security, SonarQube, VS Code)."""
    import datetime

    rules_seen: dict[str, dict] = {}
    results: List[dict] = []

    for r in report.results:
        for v in r.vulnerabilities:
            if v.rule_id not in rules_seen:
                rules_seen[v.rule_id] = {
                    "id": v.rule_id,
                    "name": re.sub(r"[^A-Za-z0-9]", "", v.name),
                    "shortDescription": {"text": v.name},
                    "fullDescription":  {"text": v.description},
                    "help": {"text": v.remediation, "markdown": f"**Remediação:** {v.remediation}"},
                    "properties": {
                        "tags": [v.category.value],
                        "precision": "medium",
                        "problem.severity": v.severity.name.lower(),
                    },
                    "defaultConfiguration": {
                        "level": {
                            "CRITICAL": "error",
                            "HIGH":     "error",
                            "MEDIUM":   "warning",
                            "LOW":      "note",
                            "INFO":     "none",
                        }.get(v.severity.name, "warning")
                    },
                }
                if v.cwe:
                    rules_seen[v.rule_id]["relationships"] = [
                        {"target": {"id": v.cwe, "toolComponent": {"name": "CWE"}}}
                    ]

            level_map = {
                "CRITICAL": "error", "HIGH": "error",
                "MEDIUM": "warning", "LOW": "note", "INFO": "none",
            }
            results.append({
                "ruleId": v.rule_id,
                "level": level_map.get(v.severity.name, "warning"),
                "message": {"text": v.name},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": v.file_path.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                        "region": {
                            "startLine": v.line_number,
                            "snippet": {"text": v.line_content},
                        },
                    },
                }],
                "fingerprints": {
                    "vulnscan/v1": f"{v.rule_id}:{v.file_path}:{v.line_number}",
                },
                "properties": {
                    "confidence": v.confidence.name,
                    "category":   v.category.value,
                    "in_comment": v.in_comment,
                },
            })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":            "vulnscan",
                    "version":         "1.0.0",
                    "informationUri":  "https://github.com/your-org/CodeVulnerableAnalyzer",
                    "organization":    "CodeVulnerableAnalyzer",
                    "rules":           list(rules_seen.values()),
                }
            },
            "results":    results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.datetime.utcnow().isoformat() + "Z",
            }],
            "properties": {
                "target":        report.target,
                "filesScanned":  report.files_scanned,
                "totalIssues":   report.total_vulnerabilities,
            },
        }],
    }

    Path(output_path).write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[bold bright_green]✔[/] SARIF salvo → [cyan]{output_path}[/cyan]")


# ── CSV export ────────────────────────────────────────────────────────────────

def export_csv(report: ScanReport, output_path: str) -> None:
    """Exporta resultados em CSV (compatível com Excel/Google Sheets)."""
    import csv, io

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
    writer.writerow([
        "severity", "rule_id", "name", "language", "file", "line",
        "category", "cwe", "owasp", "confidence", "in_comment", "description",
    ])
    for r in report.results:
        for v in r.vulnerabilities:
            writer.writerow([
                v.severity.name, v.rule_id, v.name, v.language.value,
                v.file_path, v.line_number, v.category.value,
                v.cwe or "", v.owasp or "", v.confidence.name,
                "yes" if v.in_comment else "no",
                v.description.replace("\n", " "),
            ])

    Path(output_path).write_text(buf.getvalue(), encoding="utf-8-sig")
    console.print(f"[bold bright_green]✔[/] CSV salvo → [cyan]{output_path}[/cyan]")


# ── JUnit XML export ──────────────────────────────────────────────────────────

def export_junit(report: ScanReport, output_path: str) -> None:
    """Exporta resultados em JUnit XML (Jenkins, GitLab CI, Azure DevOps)."""
    from html import escape
    import datetime

    total     = report.total_vulnerabilities
    failures  = report.critical_count + report.high_count
    errors    = 0
    timestamp = datetime.datetime.utcnow().isoformat()

    cases: List[str] = []
    for r in report.results:
        for v in r.vulnerabilities:
            cls  = escape(f"vulnscan.{v.language.value}.{v.category.value}".replace(" ", "_"))
            name = escape(f"{v.rule_id}: {v.name}")
            body = escape(
                f"File: {v.file_path}:{v.line_number}\n"
                f"Severity: {v.severity.name}\n"
                f"Description: {v.description}\n"
                f"Remediation: {v.remediation}"
            )
            is_fail = v.severity.name in ("CRITICAL", "HIGH")
            tag     = "failure" if is_fail else "warning"
            cases.append(
                f'  <testcase classname="{cls}" name="{name}">\n'
                f'    <{tag} type="{escape(v.severity.name)}" message="{escape(v.name)}">'
                f'{body}</{tag}>\n'
                f'  </testcase>'
            )

    xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="vulnscan" tests="{total}" failures="{failures}" '
        f'errors="{errors}" timestamp="{timestamp}" time="{report.total_time:.3f}">\n'
        + "\n".join(cases)
        + "\n</testsuite>\n"
    )

    Path(output_path).write_text(xml, encoding="utf-8")
    console.print(f"[bold bright_green]✔[/] JUnit XML salvo → [cyan]{output_path}[/cyan]")


# ── Markdown export ───────────────────────────────────────────────────────────

def export_markdown(report: ScanReport, output_path: str) -> None:
    """Exporta relatório em Markdown (PRs, wikis, GitHub Issues)."""
    from collections import Counter

    lines: List[str] = [
        "# Vulnerability Scan Report",
        "",
        f"| Métrica | Valor |",
        f"|---------|-------|",
        f"| Target | `{report.target}` |",
        f"| Arquivos escaneados | {report.files_scanned} |",
        f"| Arquivos com problemas | {report.files_with_issues} |",
        f"| Total de problemas | {report.total_vulnerabilities} |",
        f"| Tempo de scan | {report.total_time:.2f}s |",
        "",
        "## Distribuição por Severidade",
        "",
        "| Severidade | Quantidade |",
        "|------------|-----------|",
        f"| 🔴 CRITICAL | {report.critical_count} |",
        f"| 🟠 HIGH     | {report.high_count} |",
        f"| 🟡 MEDIUM   | {report.medium_count} |",
        f"| 🔵 LOW      | {report.low_count} |",
        f"| ⚪ INFO     | {report.info_count} |",
        "",
    ]

    all_vulns = [v for r in report.results for v in r.vulnerabilities]
    if all_vulns:
        lines += [
            "## Achados",
            "",
            "| # | Sev | Regra | Arquivo | Linha | Nome |",
            "|---|-----|-------|---------|-------|------|",
        ]
        sev_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
        for i, v in enumerate(sorted(all_vulns, key=lambda x: -x.severity.value), 1):
            icon = sev_icons.get(v.severity.name, "⚪")
            fname = Path(v.file_path).name
            lines.append(
                f"| {i} | {icon} {v.severity.name} | `{v.rule_id}` | "
                f"`{fname}` | {v.line_number} | {v.name} |"
            )

        lines += [
            "",
            "## Detalhes",
            "",
        ]
        for v in sorted(all_vulns, key=lambda x: -x.severity.value)[:50]:
            icon = sev_icons.get(v.severity.name, "⚪")
            lines += [
                f"### {icon} {v.rule_id} — {v.name}",
                "",
                f"- **Arquivo:** `{v.file_path}:{v.line_number}`",
                f"- **Severidade:** {v.severity.name}",
                f"- **Categoria:** {v.category.value}",
            ]
            if v.cwe:
                lines.append(f"- **CWE:** {v.cwe}")
            if v.owasp:
                lines.append(f"- **OWASP:** {v.owasp}")
            lines += [
                "",
                f"**Descrição:** {v.description}",
                "",
                f"**Remediação:** {v.remediation}",
                "",
            ]
            if v.snippet:
                lines += [
                    "```",
                    *v.snippet,
                    "```",
                    "",
                ]

    lines += [
        "---",
        "",
        "*Gerado por [CodeVulnerableAnalyzer](https://github.com/your-org/CodeVulnerableAnalyzer)*",
    ]

    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
    console.print(f"[bold bright_green]✔[/] Markdown salvo → [cyan]{output_path}[/cyan]")


# ── Diff de baseline ──────────────────────────────────────────────────────────

def print_baseline_diff(diff) -> None:
    """Imprime comparação com baseline de forma legível."""
    console.print()
    console.print(f"[bold bright_white]  📊  Comparação com Baseline  [/]")
    console.print()

    t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2))
    t.add_column(style="dim", min_width=20)
    t.add_column(style="bold white")
    t.add_row("Novos achados",     f"[bold {'red' if diff.new_count else 'green'}]{diff.new_count}[/]")
    t.add_row("Resolvidos",        f"[bold bright_green]{diff.resolved_count}[/]")
    t.add_row("Regressões",        f"[bold {'red' if diff.regression_count else 'green'}]{diff.regression_count}[/]")
    t.add_row("Sem alteração",     str(diff.unchanged_count))
    console.print(t)

    if diff.new_findings:
        console.print(f"\n[bold red] Novos ({diff.new_count}) [/]")
        for f in diff.new_findings[:10]:
            console.print(f"  [red]+[/] [{f['severity']}] {f['rule_id']} — {f['file']}:{f['line']}")
        if diff.new_count > 10:
            console.print(f"  [dim]... +{diff.new_count - 10} mais[/dim]")

    if diff.resolved_findings:
        console.print(f"\n[bold bright_green] Resolvidos ({diff.resolved_count}) [/]")
        for f in diff.resolved_findings[:5]:
            console.print(f"  [bright_green]-[/] [{f['severity']}] {f['rule_id']} — {f.get('file','')}:{f.get('line','')}")

    if diff.regression_findings:
        console.print(f"\n[bold yellow] Regressões ({diff.regression_count}) [/]")
        for f in diff.regression_findings[:5]:
            console.print(
                f"  [yellow]↑[/] [{f.get('old_severity','')}→{f['severity']}] "
                f"{f['rule_id']} — {f['file']}:{f['line']}"
            )
    console.print()


# ── Badge SVG ─────────────────────────────────────────────────────────────────

def export_badge(report: ScanReport, output_path: str) -> None:
    """Gera badge SVG estilo shields.io com a contagem de achados."""
    total = report.total_vulnerabilities
    if total == 0:
        color, label = "brightgreen", "0 issues"
    elif report.critical_count > 0:
        color, label = "critical", f"{total} issues"
    elif report.high_count > 0:
        color, label = "red", f"{total} issues"
    elif report.medium_count > 0:
        color, label = "yellow", f"{total} issues"
    else:
        color, label = "blue", f"{total} issues"

    colors = {
        "brightgreen": "#44cc11", "critical": "#e05d44",
        "red": "#e05d44", "yellow": "#dfb317", "blue": "#4c97ff",
    }
    bg = colors.get(color, "#999")
    left_w, right_w = 88, 68
    total_w = left_w + right_w

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="{total_w}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{left_w}" height="20" fill="#555"/>
    <rect x="{left_w}" width="{right_w}" height="20" fill="{bg}"/>
    <rect width="{total_w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110">
    <text x="{left_w//2 * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="780" lengthAdjust="spacing">vulnscan</text>
    <text x="{left_w//2 * 10}" y="140" transform="scale(.1)" textLength="780" lengthAdjust="spacing">vulnscan</text>
    <text x="{(left_w + right_w//2) * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="580" lengthAdjust="spacing">{label}</text>
    <text x="{(left_w + right_w//2) * 10}" y="140" transform="scale(.1)" textLength="580" lengthAdjust="spacing">{label}</text>
  </g>
</svg>"""

    Path(output_path).write_text(svg, encoding="utf-8")
    console.print(f"[bold bright_green]✔[/] Badge SVG salvo → [cyan]{output_path}[/cyan]")


# ── Error helper ──────────────────────────────────────────────────────────────

def print_error(message: str) -> None:
    console.print(Panel(Text(message, style="bold red"), border_style="red", title="[red]Error[/red]"))
