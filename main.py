#!/usr/bin/env python3
"""
Code Vulnerability Analyzer — Multi-language static analysis tool.
Usage: python main.py [target] [options]
"""
from __future__ import annotations
import sys
import os
import argparse
from pathlib import Path
from typing import List, Optional

# Force UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.progress import Progress
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich import box as rbox

from analyzer import __version__
from analyzer.models import Severity, Language, ScanResult
from analyzer.engine import ScanEngine
from analyzer.reporter import (
    console as _reporter_console, print_banner, make_progress, print_report,
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
Exemplos:
  python main.py myapp/                       Escanear diretório recursivamente
  python main.py src/auth.py                  Escanear arquivo único
  python main.py . --severity HIGH            Apenas HIGH e CRITICAL
  python main.py . --json report.json         Exportar JSON
  python main.py . --html report.html         Exportar HTML
  python main.py . --sarif report.sarif       Exportar SARIF 2.1 (GitHub/VS Code)
  python main.py . --csv report.csv           Exportar CSV
  python main.py . --junit report.xml         Exportar JUnit XML
  python main.py . --markdown REPORT.md       Exportar Markdown
  python main.py . --diff baseline.json       Comparar com baseline
  python main.py . --watch                    Monitorar alterações
  python main.py . --serve 8080               Servidor HTTP para CI
  python main.py . --sbom sbom.json           Gerar SBOM CycloneDX
  python main.py . --deps                     Escanear dependências vulneráveis
  python main.py . --entropy                  Detectar segredos por entropia
  python main.py . --pii                      Detectar dados PII
  cat file.py | python main.py --stdin --lang python   Ler de stdin
  python main.py . --badge badge.svg          Gerar badge SVG
  python main.py --install-hook               Instalar git pre-commit hook
        """,
    )

    p.add_argument("target", nargs="?", default=None,
                   help="Arquivo ou diretório (padrão: modo interativo)")
    p.add_argument("--severity", "-s",
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], default="INFO",
                   help="Severidade mínima (padrão: INFO)")
    p.add_argument("--lang", "-l", nargs="+", metavar="LANGUAGE",
                   help="Filtrar por linguagem(ns)")
    p.add_argument("--json", metavar="FILE", help="Exportar JSON")
    p.add_argument("--html", metavar="FILE", help="Exportar HTML")
    p.add_argument("--sarif", metavar="FILE", help="Exportar SARIF 2.1")
    p.add_argument("--csv", metavar="FILE", help="Exportar CSV")
    p.add_argument("--junit", metavar="FILE", help="Exportar JUnit XML")
    p.add_argument("--markdown", metavar="FILE", help="Exportar Markdown")
    p.add_argument("--no-snippet", action="store_true", help="Sem snippets de código")
    p.add_argument("--no-comments", action="store_true", help="Ignorar achados em comentários")
    p.add_argument("--flat", action="store_true", help="Lista plana por severidade")
    p.add_argument("--quiet", "-q", action="store_true", help="Apenas resumo")
    p.add_argument("--summary-only", action="store_true", help="Apenas métricas (sem detalhes)")
    p.add_argument("--rules", action="store_true", help="Listar todas as regras")
    p.add_argument("--list-langs", "--langs", action="store_true", dest="list_langs",
                   help="Listar linguagens suportadas")
    p.add_argument("--interactive", "-i", action="store_true", dest="interactive",
                   help="Interface TUI interativa")
    p.add_argument("--diff", metavar="BASELINE_JSON",
                   help="Comparar com baseline JSON (mostra apenas novos achados)")
    p.add_argument("--save-baseline", metavar="FILE",
                   help="Salvar scan como novo baseline")
    p.add_argument("--watch", action="store_true",
                   help="Watch mode: re-escaneia ao detectar alterações")
    p.add_argument("--serve", metavar="PORT", type=int,
                   help="Iniciar servidor HTTP API na porta especificada")
    p.add_argument("--stdin", action="store_true",
                   help="Ler código de stdin (requer --lang)")
    p.add_argument("--sbom", metavar="FILE",
                   help="Gerar SBOM das dependências")
    p.add_argument("--sbom-format", choices=["cyclonedx", "spdx"], default="cyclonedx",
                   help="Formato do SBOM (padrão: cyclonedx)")
    p.add_argument("--deps", action="store_true",
                   help="Escanear dependências vulneráveis (CVE)")
    p.add_argument("--entropy", action="store_true",
                   help="Detectar segredos por entropia de Shannon")
    p.add_argument("--pii", action="store_true",
                   help="Detectar PII: CPF, CNPJ, cartão de crédito, e-mail, telefone BR")
    p.add_argument("--badge", metavar="FILE",
                   help="Gerar badge SVG com contagem de achados")
    p.add_argument("--install-hook", action="store_true",
                   help="Instalar git pre-commit hook no repositório atual")
    p.add_argument("--trend", action="store_true",
                   help="Exibir histórico de scans e gráfico de tendência")
    p.add_argument("--lsp", action="store_true",
                   help="Iniciar servidor LSP sobre stdio (para VS Code/Neovim/Emacs)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


# ── List languages ────────────────────────────────────────────────────────────

def cmd_list_langs() -> None:
    from analyzer.models import Language
    from analyzer.rules import LANGUAGE_RULES

    categories = Language.by_category()
    console.print()
    console.print(Panel(
        Text("  Linguagens Suportadas  ", style="bold bright_white", justify="center"),
        border_style="#444466", box=rbox.DOUBLE_EDGE,
    ))
    console.print()
    for cat_name, langs in categories.items():
        t = Table(title=f"[bold bright_cyan]{cat_name}[/]", box=rbox.SIMPLE,
                  show_header=True, header_style="bold bright_white",
                  padding=(0, 2), border_style="#333355")
        t.add_column("Linguagem", min_width=20)
        t.add_column("ID Interno", style="dim", min_width=16)
        t.add_column("Regras Específicas", justify="right", min_width=8)
        for lang in langs:
            specific = len(LANGUAGE_RULES.get(lang, []))
            t.add_row(f"[bold {lang.color()}]{lang.value}[/]", lang.name,
                      str(specific) if specific else "[dim]—[/dim]")
        console.print(t)
        console.print()


# ── List rules ────────────────────────────────────────────────────────────────

def cmd_list_rules() -> None:
    from analyzer.rules import get_all_rules
    from analyzer.reporter import SEVERITY_COLORS

    rules = get_all_rules()
    table = Table(
        title=f"[bold bright_white]Regras disponíveis ({len(rules)} total)[/]",
        box=rbox.SIMPLE_HEAVY, border_style="#444466",
        show_lines=False, header_style="bold bright_cyan", padding=(0, 1),
    )
    table.add_column("ID",         min_width=10, style="bright_black")
    table.add_column("Severity",   min_width=10)
    table.add_column("Language",   min_width=12)
    table.add_column("Category",   min_width=24)
    table.add_column("Name")
    table.add_column("CWE",        min_width=10, style="dim")
    for rule in sorted(rules, key=lambda r: (-r.severity.value, r.id)):
        color = SEVERITY_COLORS[rule.severity]
        table.add_row(
            rule.id,
            Text(rule.severity.name, style=f"bold {color}"),
            Text(rule.language.value, style=rule.language.color()),
            rule.category.value, rule.name, rule.cwe or "",
        )
    console.print()
    console.print(table)
    console.print()


# ── Language filter ───────────────────────────────────────────────────────────

_LANG_MAP: dict[str, Language] = {
    "python": Language.PYTHON, "py": Language.PYTHON,
    "javascript": Language.JAVASCRIPT, "js": Language.JAVASCRIPT,
    "typescript": Language.TYPESCRIPT, "ts": Language.TYPESCRIPT,
    "java": Language.JAVA,
    "csharp": Language.CSHARP, "cs": Language.CSHARP,
    "php": Language.PHP,
    "go": Language.GO, "golang": Language.GO,
    "ruby": Language.RUBY, "rb": Language.RUBY,
    "c": Language.C, "cpp": Language.CPP, "c++": Language.CPP,
    "sql": Language.SQL, "cobol": Language.COBOL,
    "shell": Language.SHELL, "sh": Language.SHELL, "bash": Language.SHELL,
    "kotlin": Language.KOTLIN, "swift": Language.SWIFT,
    "rust": Language.RUST, "rs": Language.RUST,
    "scala": Language.SCALA, "perl": Language.PERL,
    "lua": Language.LUA, "dart": Language.DART, "r": Language.R,
    "julia": Language.JULIA,
}


def parse_languages(names: List[str]) -> List[Language]:
    result: List[Language] = []
    for name in names:
        lang = _LANG_MAP.get(name.lower())
        if lang:
            result.append(lang)
        else:
            console.print(f"[yellow]Aviso:[/yellow] linguagem desconhecida '{name}' — ignorada.")
    return result or []


# ── Progress tracking ─────────────────────────────────────────────────────────

class ScanTracker:
    def __init__(self, progress: Progress, task_id: int) -> None:
        self.progress = progress
        self.task_id  = task_id

    def on_file_start(self, path: str) -> None:
        name = Path(path).name
        self.progress.update(self.task_id, description=f"[cyan]{name[:50]}[/cyan]")

    def on_file_done(self, _result: ScanResult) -> None:
        self.progress.advance(self.task_id)


# ── Stdin mode ────────────────────────────────────────────────────────────────

def run_stdin_mode(lang_name: str, min_severity: Severity) -> int:
    """Lê código de stdin, escaneia e imprime resultados."""
    import tempfile
    lang = _LANG_MAP.get(lang_name.lower(), Language.UNKNOWN)
    if lang == Language.UNKNOWN:
        print_error(f"Linguagem '{lang_name}' não reconhecida para modo stdin.")
        return 2

    content = sys.stdin.read()
    suffix_map = {
        Language.PYTHON: ".py", Language.JAVASCRIPT: ".js",
        Language.TYPESCRIPT: ".ts", Language.JAVA: ".java",
        Language.PHP: ".php", Language.RUBY: ".rb",
        Language.GO: ".go", Language.RUST: ".rs",
    }
    suffix = suffix_map.get(lang, ".txt")

    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as f:
        f.write(content)
        tmp = f.name

    try:
        engine = ScanEngine(min_severity=min_severity)
        report = engine.scan_files([tmp])
        if not args_global.quiet and not args_global.summary_only:
            print_report(report, show_snippets=not args_global.no_snippet,
                         group_by_file=not args_global.flat)
        else:
            from analyzer.reporter import print_summary
            print_summary(report)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    return 1 if (report.critical_count > 0 or report.high_count > 0) else 0


# ── Server mode ───────────────────────────────────────────────────────────────

def run_server_mode(port: int) -> None:
    """Inicia servidor HTTP simples: POST /scan → JSON de resultados."""
    import json as _json
    from http.server import BaseHTTPRequestHandler, HTTPServer

    console.print(f"[bold bright_cyan]🌐  Servidor vulnscan na porta {port}[/]")
    console.print("[dim]Endpoints: POST /scan  {'path': '...', 'min_severity': 'HIGH'}[/dim]")
    console.print("[dim]Ctrl+C para parar[/dim]\n")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_GET(self):
            if self.path == "/health":
                self._json(200, {"status": "ok", "version": __version__, "rules": rule_count()})
            else:
                self._json(404, {"error": "Not found"})

        def do_POST(self):
            if self.path != "/scan":
                self._json(404, {"error": "Not found"})
                return
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            try:
                req   = _json.loads(body)
            except Exception:
                self._json(400, {"error": "Invalid JSON"})
                return

            target    = req.get("path", ".")
            min_sev   = Severity[req.get("min_severity", "INFO").upper()]
            lang_list = req.get("languages")
            languages = parse_languages(lang_list) if lang_list else None

            engine = ScanEngine(min_severity=min_sev, languages=languages)
            tp     = Path(target)
            if tp.is_dir():
                report = engine.scan_directory(target)
            elif tp.is_file():
                report = engine.scan_files([target])
            else:
                self._json(400, {"error": f"Target not found: {target}"})
                return

            findings = []
            for r in report.results:
                for v in r.vulnerabilities:
                    findings.append({
                        "rule_id":     v.rule_id,
                        "name":        v.name,
                        "severity":    v.severity.name,
                        "file":        v.file_path,
                        "line":        v.line_number,
                        "category":    v.category.value,
                        "language":    v.language.value,
                        "cwe":         v.cwe,
                        "owasp":       v.owasp,
                        "description": v.description,
                        "remediation": v.remediation,
                        "confidence":  v.confidence.name,
                    })

            self._json(200, {
                "target":       report.target,
                "files_scanned": report.files_scanned,
                "total_issues": report.total_vulnerabilities,
                "critical":     report.critical_count,
                "high":         report.high_count,
                "medium":       report.medium_count,
                "low":          report.low_count,
                "scan_time":    round(report.total_time, 3),
                "findings":     findings,
            })

        def _json(self, code: int, data: dict) -> None:
            body = _json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


# ── Pre-commit hook installer ─────────────────────────────────────────────────

def install_hook() -> int:
    """Instala o git pre-commit hook no repositório atual."""
    git_dir = Path(".git")
    if not git_dir.is_dir():
        print_error("Não estou num repositório git (.git não encontrado).")
        return 2

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    script_src = Path(__file__).parent / "scripts" / "pre-commit"
    if script_src.exists():
        hook_content = script_src.read_text(encoding="utf-8")
    else:
        hook_content = f"""#!/bin/sh
# vulnscan pre-commit hook — gerado automaticamente
echo "[vulnscan] Escaneando arquivos staged..."
python "{Path(__file__).resolve()}" --diff --severity HIGH --summary-only
STATUS=$?
if [ $STATUS -ne 0 ]; then
    echo "[vulnscan] ❌ Achados CRITICAL/HIGH detectados. Commit bloqueado."
    echo "           Use 'git commit --no-verify' para ignorar."
    exit 1
fi
echo "[vulnscan] ✅ Nenhum problema CRITICAL/HIGH encontrado."
exit 0
"""

    hook_path.write_text(hook_content, encoding="utf-8")
    if sys.platform != "win32":
        os.chmod(hook_path, 0o755)

    console.print(f"[bold bright_green]✔[/] Pre-commit hook instalado em: [cyan]{hook_path}[/cyan]")
    console.print("[dim]O hook bloqueará commits com achados CRITICAL/HIGH.[/dim]")
    return 0


# ── Trend display ─────────────────────────────────────────────────────────────

def cmd_trend() -> None:
    from analyzer.trend import TrendDB, ascii_trend

    db      = TrendDB()
    history = db.history(limit=20)
    if not history:
        console.print("[dim]Nenhum histórico de scans encontrado.[/dim]")
        return

    console.print()
    console.print(Panel(
        Text("  Histórico de Scans  ", style="bold bright_white", justify="center"),
        border_style="#444466", box=rbox.DOUBLE_EDGE,
    ))
    console.print()

    t = Table(box=rbox.SIMPLE_HEAVY, border_style="#444466",
              header_style="bold bright_cyan", padding=(0, 1))
    t.add_column("ID",      min_width=4,  justify="right", style="dim")
    t.add_column("Data",    min_width=14)
    t.add_column("Target",  min_width=20)
    t.add_column("Total",   min_width=6,  justify="right", style="bold white")
    t.add_column("Crit",    min_width=5,  justify="right", style="#ff2244")
    t.add_column("High",    min_width=5,  justify="right", style="#ff6600")
    t.add_column("Tempo",   min_width=8,  justify="right", style="dim")
    for e in history:
        t.add_row(
            str(e.id), e.dt,
            e.target[:28], str(e.total_vulns),
            str(e.critical) if e.critical else "—",
            str(e.high) if e.high else "—",
            f"{e.scan_time:.2f}s",
        )
    console.print(t)
    console.print()
    console.print("[bold bright_white]Tendência (total de vulnerabilidades):[/]")
    console.print()
    console.print(ascii_trend(history))
    console.print()


# ── Main ──────────────────────────────────────────────────────────────────────

args_global = None


def main() -> int:
    global args_global

    parser = build_parser()
    args   = parser.parse_args()
    args_global = args

    num_rules = rule_count()
    print_banner(num_rules)

    # ── Comandos informativos ─────────────────────────────────────────────────
    if args.rules:
        cmd_list_rules()
        return 0

    if args.list_langs:
        cmd_list_langs()
        return 0

    if args.lsp:
        from analyzer.lsp import run_lsp
        run_lsp()
        return 0

    if args.install_hook:
        return install_hook()

    if args.trend:
        cmd_trend()
        return 0

    # ── Modo stdin ────────────────────────────────────────────────────────────
    if args.stdin:
        if not args.lang:
            print_error("--stdin requer --lang LINGUAGEM (ex: --lang python)")
            return 2
        return run_stdin_mode(args.lang[0], Severity[args.severity])

    # ── Modo servidor ─────────────────────────────────────────────────────────
    if args.serve:
        run_server_mode(args.serve)
        return 0

    target = args.target

    # ── TUI interativo ────────────────────────────────────────────────────────
    if target is None or args.interactive:
        from analyzer.tui import run_tui
        run_tui(Path(target) if target else None)
        return 0

    target_path = Path(target)
    if not target_path.exists():
        print_error(f"Alvo não encontrado: {target}")
        return 2

    # ── SBOM ──────────────────────────────────────────────────────────────────
    if args.sbom:
        from analyzer.sbom import collect_components, export_cyclonedx, export_spdx
        components = collect_components(target)
        if args.sbom_format == "spdx":
            export_spdx(components, args.sbom, Path(target).name)
        else:
            export_cyclonedx(components, args.sbom, Path(target).name)
        console.print(f"[bold bright_green]✔[/] SBOM com {len(components)} componentes → [cyan]{args.sbom}[/cyan]")
        return 0

    # ── Dependências CVE ──────────────────────────────────────────────────────
    if args.deps:
        from analyzer.deps import scan_manifest_dir
        _SEV_C = {"CRITICAL": "#ff2244", "HIGH": "#ff6600", "MEDIUM": "#ffcc00", "LOW": "#33aaff"}
        vulns = scan_manifest_dir(target)
        if not vulns:
            console.print("[bold bright_green]✅  Nenhuma dependência vulnerável encontrada.[/]")
        else:
            t = Table(title=f"[bold bright_white]Dependências Vulneráveis ({len(vulns)})[/]",
                      box=rbox.SIMPLE_HEAVY, border_style="#444466",
                      header_style="bold bright_cyan", padding=(0, 1))
            t.add_column("CVE",       min_width=14, style="dim")
            t.add_column("Sev",       min_width=10)
            t.add_column("Pacote",    min_width=20)
            t.add_column("Instalado", min_width=10)
            t.add_column("Corrigido", min_width=10, style="bright_green")
            t.add_column("Descrição")
            for v in sorted(vulns, key=lambda x: {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}.get(x.severity,0), reverse=True):
                c = _SEV_C.get(v.severity, "#888")
                t.add_row(v.cve_id, Text(v.severity, style=f"bold {c}"),
                          v.package, v.installed_version, v.fixed_version,
                          v.description[:60])
            console.print()
            console.print(t)
        return 0

    # ── Entropia ──────────────────────────────────────────────────────────────
    if args.entropy:
        from analyzer.entropy import scan_entropy
        _collect_and_scan_entropy(target, target_path)
        return 0

    # ── PII ───────────────────────────────────────────────────────────────────
    if args.pii:
        from analyzer.pii import scan_pii
        _collect_and_scan_pii(target, target_path)
        return 0

    # ── Scan principal ────────────────────────────────────────────────────────
    min_severity = Severity[args.severity]
    languages    = parse_languages(args.lang) if args.lang else None

    # Coletar arquivos para barra de progresso
    if target_path.is_dir():
        from analyzer.detector import is_scannable, SKIP_DIRS
        files: List[Path] = []
        for item in target_path.rglob("*"):
            if item.is_file() and is_scannable(str(item)):
                skip = False
                try:
                    for part in item.relative_to(target_path).parts[:-1]:
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
        f"[dim]({total_files} arquivo{'s' if total_files != 1 else ''})[/dim]"
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

        progress.update(task_id, description="[bold bright_green]Concluído![/bold bright_green]",
                        completed=total_files)

    console.print()

    # ── Watch mode ────────────────────────────────────────────────────────────
    if args.watch:
        from analyzer.engine import watch_mode
        watch_mode(target, {
            "min_severity": min_severity,
            "languages": languages,
            "include_comments": not args.no_comments,
        })
        return 0

    # ── Comparar com baseline ──────────────────────────────────────────────────
    if args.diff:
        from analyzer.baseline import compare_with_baseline
        from analyzer.reporter import print_baseline_diff
        diff = compare_with_baseline(report, args.diff)
        print_baseline_diff(diff)
        if args.save_baseline:
            from analyzer.baseline import save_baseline
            save_baseline(report, args.save_baseline)
        return 1 if (diff.new_count > 0 or diff.regression_count > 0) else 0

    # ── Exibir relatório ──────────────────────────────────────────────────────
    if args.summary_only or args.quiet:
        from analyzer.reporter import print_summary
        print_summary(report)
    else:
        print_report(report, show_snippets=not args.no_snippet, group_by_file=not args.flat)

    # ── Exportar relatórios ───────────────────────────────────────────────────
    if args.json:
        export_json(report, args.json)
    if args.html:
        export_html(report, args.html)
    if args.sarif:
        from analyzer.reporter import export_sarif
        export_sarif(report, args.sarif)
    if args.csv:
        from analyzer.reporter import export_csv
        export_csv(report, args.csv)
    if args.junit:
        from analyzer.reporter import export_junit
        export_junit(report, args.junit)
    if args.markdown:
        from analyzer.reporter import export_markdown
        export_markdown(report, args.markdown)
    if args.badge:
        from analyzer.reporter import export_badge
        export_badge(report, args.badge)
    if args.save_baseline:
        from analyzer.baseline import save_baseline
        save_baseline(report, args.save_baseline)

    # ── Registrar no trend DB ─────────────────────────────────────────────────
    try:
        from analyzer.trend import TrendDB
        TrendDB().record(report)
    except Exception:
        pass

    return 1 if (report.critical_count > 0 or report.high_count > 0) else 0


# ── Helpers extras ────────────────────────────────────────────────────────────

def _collect_and_scan_entropy(target: str, target_path: Path) -> None:
    from analyzer.entropy import scan_entropy
    from analyzer.detector import is_scannable

    _SEV_C = {"hex": "#33aaff", "base64": "#ffcc00", "alnum": "#ff6600"}
    all_findings = []
    files = [target_path] if target_path.is_file() else [
        p for p in target_path.rglob("*")
        if p.is_file() and is_scannable(str(p))
    ]
    for fp in files:
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
            all_findings.extend(scan_entropy(str(fp), content))
        except (OSError, PermissionError):
            pass

    if not all_findings:
        console.print("[bold bright_green]✅  Nenhum segredo de alta entropia encontrado.[/]")
        return

    t = Table(
        title=f"[bold bright_white]Segredos por Entropia ({len(all_findings)})[/]",
        box=rbox.SIMPLE_HEAVY, border_style="#444466",
        header_style="bold bright_cyan", padding=(0, 1)
    )
    t.add_column("Arquivo",   min_width=20)
    t.add_column("Linha",     min_width=5,  justify="right", style="dim")
    t.add_column("Variável",  min_width=16)
    t.add_column("Entropia",  min_width=8,  justify="right")
    t.add_column("Charset",   min_width=8)
    t.add_column("Valor",     min_width=22, style="dim")
    for f in sorted(all_findings, key=lambda x: -x.entropy):
        c = _SEV_C.get(f.charset, "white")
        t.add_row(
            Path(f.file_path).name, str(f.line_number),
            f.variable_name, Text(f"{f.entropy:.3f}", style=c),
            f.charset, f.secret_value,
        )
    console.print()
    console.print(t)


def _collect_and_scan_pii(target: str, target_path: Path) -> None:
    from analyzer.pii import scan_pii
    from analyzer.detector import is_scannable

    _PII_C = {"CPF": "bright_cyan", "CNPJ": "bright_blue", "CartaoCredito": "bright_red",
              "Email": "yellow", "TelefoneBR": "green"}
    all_findings = []
    files = [target_path] if target_path.is_file() else [
        p for p in target_path.rglob("*")
        if p.is_file() and is_scannable(str(p))
    ]
    for fp in files:
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
            all_findings.extend(scan_pii(str(fp), content))
        except (OSError, PermissionError):
            pass

    if not all_findings:
        console.print("[bold bright_green]✅  Nenhum dado PII encontrado.[/]")
        return

    t = Table(
        title=f"[bold bright_white]Dados PII Encontrados ({len(all_findings)})[/]",
        box=rbox.SIMPLE_HEAVY, border_style="#444466",
        header_style="bold bright_cyan", padding=(0, 1)
    )
    t.add_column("Arquivo",  min_width=20)
    t.add_column("Linha",    min_width=5,  justify="right", style="dim")
    t.add_column("Tipo PII", min_width=14)
    t.add_column("Mascarado", min_width=22)
    for f in all_findings:
        c = _PII_C.get(f.pii_type, "white")
        t.add_row(
            Path(f.file_path).name, str(f.line_number),
            Text(f.pii_type, style=f"bold {c}"), f.masked_value,
        )
    console.print()
    console.print(t)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrompido pelo usuário.[/yellow]")
        sys.exit(130)
