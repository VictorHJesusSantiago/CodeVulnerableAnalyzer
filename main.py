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
    p.add_argument("--pdf", metavar="FILE", help="Exportar PDF técnico")
    p.add_argument("--docx", metavar="FILE", help="Exportar DOCX técnico")
    p.add_argument("--xlsx", metavar="FILE", help="Exportar XLSX de achados")
    p.add_argument("--gitlab-sast", metavar="FILE", help="Exportar relatório GitLab SAST JSON")
    p.add_argument("--interactive-html", metavar="FILE", help="Exportar dashboard HTML interativo")
    p.add_argument("--education", action="store_true", help="Explicar achados em modo educacional")
    p.add_argument("--autofix-diff", metavar="FILE", help="Gerar unified diff com codemods determinísticos")
    p.add_argument("--apply-fixes", action="store_true", help="Aplicar codemods (requer --autofix-diff)")
    p.add_argument("--profile-json", metavar="FILE", help="Salvar métricas de profiling")
    p.add_argument("--mobile-archive", action="store_true", help="Inspecionar alvo APK/IPA")
    p.add_argument("--secret-history", action="store_true", help="Buscar segredos em patch de histórico")
    p.add_argument("--iac-kind", choices=["vagrant","packer","rego","falco","cloud-init","crossplane","kyverno"],
                   help="Analisar alvo como formato IaC estendido")
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
                   help="Escanear dependências vulneráveis (CVE) — requirements.txt, package.json, pom.xml, Cargo.toml, go.mod, .csproj")
    p.add_argument("--osv", action="store_true",
                   help="Com --deps: cruzar também com a base online OSV.dev (requer rede)")

    # ── Dependências / supply chain — expansões ────────────────────────────────
    dg = p.add_argument_group("Dependências / Supply Chain (expansões)")
    dg.add_argument("--deps-ext", action="store_true",
                     help="Escanear ecossistemas estendidos: Composer, Gemfile, NuGet, pubspec, SwiftPM, CocoaPods, Carthage, Conan, vcpkg, Hex, CPAN, CRAN, Conda, Helm, Dockerfile")
    dg.add_argument("--dep-tree", action="store_true",
                     help="Construir e exibir a árvore de dependências transitivas a partir dos lockfiles")
    dg.add_argument("--vex", metavar="ARQUIVO",
                     help="Com --deps: suprimir CVEs marcados not_affected/fixed num documento VEX")
    dg.add_argument("--typosquat-check", action="store_true",
                     help="Verificar nomes de dependências quanto a typosquatting/dependency confusion")
    dg.add_argument("--license-check", action="store_true",
                     help="Verificar dependências quanto a licenças copyleft (GPL/AGPL)")
    dg.add_argument("--check-abandoned", action="store_true",
                     help="Verificar (via rede, PyPI/npm) se dependências estão sem manutenção há muito tempo")
    dg.add_argument("--check-pinning", action="store_true",
                     help="Verificar integridade de hash/pinning de versões em requirements.txt, package-lock.json, Cargo.lock")
    dg.add_argument("--sbom-xml", metavar="ARQUIVO",
                     help="Gerar SBOM em CycloneDX 1.4 XML")
    dg.add_argument("--sbom-spdx-json", metavar="ARQUIVO",
                     help="Gerar SBOM em SPDX 2.3 JSON")
    dg.add_argument("--bump-plan", action="store_true",
                     help="Com --deps: gerar plano de atualização (diff) para as dependências vulneráveis, sem tocar em git")

    # ── Detecção de segredos — expansões ────────────────────────────────────────
    sg = p.add_argument_group("Detecção de segredos (expansões)")
    sg.add_argument("--secrets-scan", action="store_true",
                     help="Scan completo de segredos: 100+ provedores, chaves privadas (PEM/DER), JWT, binários/EXIF/PDF/.env")
    sg.add_argument("--validate-secrets", action="store_true",
                     help="Com --secrets-scan: valida ATIVAMENTE as credenciais encontradas contra a API do provedor (requer rede; use só com autorização)")
    sg.add_argument("--secrets-baseline", metavar="ARQUIVO",
                     help="Suprimir segredos já presentes neste arquivo de baseline")
    sg.add_argument("--save-secrets-baseline", metavar="ARQUIVO",
                     help="Salvar os segredos encontrados nesta execução como baseline")

    # ── Cofre de segredos (vault) ──────────────────────────────────────────────
    vg = p.add_argument_group("Cofre de segredos (AES-256)")
    vg.add_argument("--vault", metavar="ARQUIVO",
                    help="Caminho do arquivo de cofre (ativa o modo cofre)")
    vg.add_argument("--vault-init",   action="store_true", help="Criar um novo cofre")
    vg.add_argument("--vault-set",    metavar="NOME",  help="Armazenar um segredo")
    vg.add_argument("--vault-value",  metavar="VALOR", help="Valor do segredo (senão lê de stdin/prompt)")
    vg.add_argument("--vault-get",    metavar="NOME",  help="Recuperar um segredo (valor puro no stdout)")
    vg.add_argument("--vault-list",   action="store_true", help="Listar nomes de segredos")
    vg.add_argument("--vault-delete", metavar="NOME",  help="Remover um segredo")
    vg.add_argument("--vault-passwd", action="store_true", help="Alterar a senha mestre")
    vg.add_argument("--vault-serve",  metavar="PORTA", type=int, help="Subir a API REST do cofre")
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

    # ── Motor de análise estática avançada (AST/call graph) ────────────────────
    ag = p.add_argument_group("Motor de análise avançada")
    ag.add_argument("--ast-analysis", action="store_true",
                     help="Habilita análise AST real para Python: CFG, dataflow, dead code, complexidade, recursão sem caso-base, TOCTOU, use-after-close, null-deref")
    ag.add_argument("--cpp-macros", action="store_true",
                     help="Expande macros #define/#ifdef antes de escanear arquivos C/C++")
    ag.add_argument("--incremental", action="store_true",
                     help="Cache incremental: reaproveita resultados de arquivos cujo conteúdo não mudou")
    ag.add_argument("--call-graph", action="store_true",
                     help="Constrói o call graph do projeto Python e roda taint interprocedural/cross-file")
    ag.add_argument("--impact", metavar="FUNC",
                     help="Impact analysis: lista quem chama (direto/transitivo) a função FUNC")

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
    # Em modo LSP o stdout é o canal de protocolo JSON-RPC; em stdin é o pipe
    # de saída; em modo cofre o --vault-get emite o valor puro no stdout. O
    # banner corromperia esses canais, então é suprimido nesses modos.
    if not args.lsp and not args.stdin and not args.vault:
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

    # ── Modo cofre de segredos ─────────────────────────────────────────────────
    if args.vault:
        from analyzer.vault_cli import run_vault_cli
        return run_vault_cli(args)

    if args.install_hook:
        return install_hook()

    if args.trend:
        cmd_trend()
        return 0

    # ── Call graph / Impact analysis / Taint interprocedural ──────────────────
    if args.call_graph or args.impact:
        from analyzer.callgraph import build_call_graph
        target_cg = args.target or "."
        console.print(f"[dim]Construindo call graph em {target_cg}...[/dim]")
        cg = build_call_graph(target_cg)

        if args.impact:
            report = cg.impact_report(args.impact)
            if not report["defined_in"]:
                console.print(f"[yellow]Função '{args.impact}' não encontrada.[/]")
                return 1
            console.print()
            t = Table(title=f"[bold bright_white]Impact Analysis — {args.impact}[/]",
                      box=rbox.SIMPLE_HEAVY, border_style="#444466", padding=(0, 1))
            t.add_column("Definida em", style="cyan")
            t.add_column("Chamadores diretos", style="bright_yellow")
            t.add_column("Impacto transitivo total", justify="right", style="bold white")
            t.add_row(
                ", ".join(report["defined_in"]),
                ", ".join(report["direct_callers"]) or "(nenhum)",
                str(report["total_impact"]),
            )
            console.print(t)
            if report["transitive_callers"]:
                console.print(f"\n[dim]Cadeia completa de impacto:[/] {', '.join(report['transitive_callers'])}")

        cg_findings = []
        if args.call_graph:
            summary = cg.summary()
            console.print()
            console.print(f"[bold bright_white]Call Graph:[/] {summary['total_functions']} funções "
                          f"({summary['unique_names']} nomes únicos), {summary['total_edges']} arestas de chamada")
            cg_findings = cg.analyze_taint()
            if cg_findings:
                console.print(f"\n[bold red]{len(cg_findings)} achado(s) de taint interprocedural:[/]")
                for f in cg_findings:
                    console.print(f"  [red]•[/] {f.file_path}:{f.line_number} — {f.name}")
            else:
                console.print("\n[bold bright_green]✅ Nenhum taint interprocedural encontrado.[/]")

        # ── Exportação JSON deste modo (não passa pelo pipeline normal de scan) ──
        if args.json:
            import json as _json
            payload = {
                "mode": "call-graph",
                "summary": cg.summary() if args.call_graph else None,
                "impact": cg.impact_report(args.impact) if args.impact else None,
                "taint_findings": [
                    {"file": f.file_path, "line": f.line_number, "rule_id": f.rule_id,
                     "name": f.name, "description": f.description, "severity": f.severity.name}
                    for f in cg_findings
                ],
            }
            Path(args.json).write_text(_json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            console.print(f"\n[bold bright_green]✔[/] JSON salvo em [cyan]{args.json}[/cyan]")
        elif any([args.sarif, args.csv, args.junit, args.markdown]):
            console.print(
                "\n[yellow]Aviso:[/] --call-graph/--impact só exportam para --json nesta versão; "
                "os demais formatos (--sarif/--csv/--junit/--markdown) não se aplicam a este modo."
            )
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
    if args.mobile_archive:
        from analyzer.mobile_archive import scan_mobile_archive
        import json
        result = scan_mobile_archive(target_path)
        console.print_json(json.dumps(result, ensure_ascii=False))
        return 1 if result["findings"] else 0

    if args.secret_history:
        from analyzer.secret_history import scan_patch_history
        import json
        findings = scan_patch_history(target_path.read_text(encoding="utf-8", errors="replace"))
        console.print_json(json.dumps({"findings": findings}, ensure_ascii=False))
        return 1 if findings else 0

    if args.iac_kind:
        from analyzer.iac_render import scan_extended_iac
        import json
        findings = scan_extended_iac(
            target_path.read_text(encoding="utf-8", errors="replace"), args.iac_kind
        )
        console.print_json(json.dumps({"findings": findings}, ensure_ascii=False))
        return 1 if findings else 0

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
        if args.osv:
            from analyzer.deps import scan_manifest_dir_osv
            console.print("[dim]Consultando OSV.dev (requer rede)...[/]")
            osv_vulns = scan_manifest_dir_osv(target)
            if osv_vulns:
                # Evita duplicar CVEs já encontrados localmente
                local_keys = {(v.package, v.cve_id) for v in vulns}
                vulns.extend(v for v in osv_vulns if (v.package, v.cve_id) not in local_keys)
            else:
                console.print("[dim]OSV: nenhuma resposta (offline ou sem achados).[/]")

        if args.vex:
            from analyzer.vex import VexDocument, suppress_by_vex
            vex_doc = VexDocument.load(args.vex)
            vulns, suppressed = suppress_by_vex(vulns, vex_doc)
            if suppressed:
                console.print(f"[dim]{len(suppressed)} CVE(s) suprimido(s) via VEX (not_affected/fixed).[/]")

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

            if args.bump_plan:
                from analyzer.dep_autofix import build_bump_plan
                by_manifest: dict = {}
                for v in vulns:
                    by_manifest.setdefault(v.manifest_file, []).append(v)
                for manifest_file, mvulns in by_manifest.items():
                    try:
                        content = Path(manifest_file).read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    plan = build_bump_plan(manifest_file, content, mvulns)
                    if plan.diff:
                        console.print(f"\n[bold bright_white]Bump plan para {manifest_file}:[/]")
                        console.print(plan.diff)
        return 0

    # ── Dependências / supply chain: expansões (deps-ext, dep-tree, saúde) ────
    if args.deps_ext or args.dep_tree or args.typosquat_check or args.license_check or args.check_abandoned or args.check_pinning or args.sbom_xml or args.sbom_spdx_json:
        if args.deps_ext:
            from analyzer.manifests_ext import collect_extended_components
            comps = collect_extended_components(target)
            console.print(f"[bold bright_white]Componentes de ecossistemas estendidos: {len(comps)}[/]")
            for c in comps[:50]:
                console.print(f"  [cyan]{c.package_type:12}[/] {c.name} @ {c.version}")
            if len(comps) > 50:
                console.print(f"  [dim]... +{len(comps)-50} mais[/]")

        if args.dep_tree:
            from analyzer.lockfiles import build_dependency_tree
            tree = build_dependency_tree(target)
            summary = tree.summary()
            console.print(f"\n[bold bright_white]Árvore de dependências:[/] {summary['total_packages']} pacotes, "
                          f"{summary['total_edges']} arestas, profundidade máx. {summary['max_depth']}")

        if args.typosquat_check or args.license_check or args.check_abandoned:
            from analyzer.sbom import collect_components
            from analyzer.dep_health import check_typosquatting, check_dependency_confusion, check_license, check_abandoned
            comps = collect_components(target)
            eco_map = {"pypi": "pypi", "npm": "npm", "cargo": "cargo", "gem": "gem"}

            if args.typosquat_check:
                console.print("\n[bold bright_white]Verificação de typosquatting/dependency confusion:[/]")
                found_any = False
                for c in comps:
                    eco = eco_map.get(c.package_type)
                    if eco:
                        r = check_typosquatting(c.name, eco)
                        if r:
                            found_any = True
                            console.print(f"  [red]⚠[/] '{r.package_name}' parecido com '{r.similar_to}' (distância {r.edit_distance})")
                    cf = check_dependency_confusion(c.name)
                    if cf:
                        found_any = True
                        console.print(f"  [red]⚠[/] {cf.reason}")
                if not found_any:
                    console.print("  [bright_green]✅ Nenhum indício encontrado.[/]")

            if args.license_check:
                console.print("\n[bold bright_white]Verificação de licenças:[/]")
                found_any = False
                for c in comps:
                    lf = check_license(c.name, c.license_id if c.license_id != "NOASSERTION" else None)
                    if lf:
                        found_any = True
                        console.print(f"  [yellow]⚠[/] {lf.package_name}: {lf.concern}")
                if not found_any:
                    console.print("  [bright_green]✅ Nenhuma preocupação de licença encontrada.[/]")

            if args.check_abandoned:
                console.print("\n[dim]Verificando pacotes abandonados (requer rede)...[/]")
                found_any = False
                for c in comps:
                    eco = eco_map.get(c.package_type)
                    if eco not in ("pypi", "npm"):
                        continue
                    af = check_abandoned(c.name, eco)
                    if af and af.days_since_release:
                        found_any = True
                        console.print(f"  [yellow]⚠[/] {af.package_name}: última publicação há {af.days_since_release} dias")
                if not found_any:
                    console.print("  [bright_green]✅ Nenhum pacote abandonado detectado.[/]")

        if args.check_pinning:
            from analyzer.hash_pinning import scan_pinning
            findings = scan_pinning(target)
            console.print(f"\n[bold bright_white]Integridade de pinning ({len(findings)} achado(s)):[/]")
            for f in findings[:50]:
                console.print(f"  [yellow]⚠[/] {f.file_path}: {f.package} — {f.issue} ({f.severity})")

        if args.sbom_xml or args.sbom_spdx_json:
            from analyzer.sbom import collect_components
            from analyzer.sbom_ext import export_cyclonedx_xml, export_spdx_json
            comps = collect_components(target)
            if args.sbom_xml:
                export_cyclonedx_xml(comps, args.sbom_xml, Path(target).name or "project")
                console.print(f"[bold bright_green]✔[/] SBOM CycloneDX XML salvo → {args.sbom_xml}")
            if args.sbom_spdx_json:
                export_spdx_json(comps, args.sbom_spdx_json, Path(target).name or "project")
                console.print(f"[bold bright_green]✔[/] SBOM SPDX JSON salvo → {args.sbom_spdx_json}")
        return 0

    # ── Detecção de segredos: scan completo (provedores/chaves/JWT/binários) ──
    if args.secrets_scan:
        from analyzer.secrets_providers import classify_secret
        from analyzer.key_material import scan_key_material
        from analyzer.jwt_scan import scan_jwt
        from analyzer.binary_scan import scan_non_text_file
        from analyzer.detector import is_scannable, SKIP_DIRS

        all_findings: List[dict] = []
        files_to_scan: List[Path] = []
        if target_path.is_dir():
            for item in target_path.rglob("*"):
                if item.is_file() and not any(p in SKIP_DIRS for p in item.parts):
                    files_to_scan.append(item)
        else:
            files_to_scan = [target_path]

        for f in files_to_scan:
            try:
                content = f.read_text(encoding="utf-8", errors="strict")
                is_text = True
            except (UnicodeDecodeError, OSError):
                is_text = False
                content = ""

            if is_text:
                for provider, secret_type, matched, revoke_url in classify_secret(content):
                    line_no = content[:content.find(matched)].count("\n") + 1 if matched in content else 0
                    all_findings.append({"file_path": str(f), "line_number": line_no, "provider": provider,
                                          "secret_type": secret_type, "matched": matched, "revoke_url": revoke_url})
                for k in scan_key_material(str(f), content):
                    all_findings.append({"file_path": str(f), "line_number": k.line_number, "provider": "Key Material",
                                          "secret_type": f"{k.key_type} ({'criptografada' if k.is_encrypted else 'em claro'})",
                                          "matched": k.header, "revoke_url": "N/A"})
                for j in scan_jwt(str(f), content):
                    if j.issues:
                        all_findings.append({"file_path": str(f), "line_number": j.line_number, "provider": "JWT",
                                              "secret_type": "; ".join(j.issues), "matched": j.token_preview, "revoke_url": "N/A"})
            else:
                for bf in scan_non_text_file(str(f)):
                    bf.setdefault("line_number", 0)
                    all_findings.append(bf)

        if args.secrets_baseline:
            from analyzer.secrets_baseline import filter_new_secrets
            diff = filter_new_secrets(all_findings, args.secrets_baseline)
            console.print(f"[dim]{diff.unchanged_count} segredo(s) já no baseline (suprimidos).[/]")
            all_findings = diff.new_secrets

        if not all_findings:
            console.print("[bold bright_green]✅  Nenhum segredo encontrado.[/]")
        else:
            t = Table(title=f"[bold bright_white]Segredos Encontrados ({len(all_findings)})[/]",
                      box=rbox.SIMPLE_HEAVY, border_style="#444466",
                      header_style="bold bright_cyan", padding=(0, 1))
            t.add_column("Arquivo", min_width=20)
            t.add_column("Linha", min_width=5, justify="right")
            t.add_column("Provedor", min_width=14, style="bright_yellow")
            t.add_column("Tipo", min_width=20)
            t.add_column("Revogação", style="dim")
            for f in all_findings[:100]:
                t.add_row(str(f["file_path"]), str(f.get("line_number", 0)), f["provider"],
                          f["secret_type"][:50], f["revoke_url"][:40])
            console.print()
            console.print(t)
            if len(all_findings) > 100:
                console.print(f"[dim]... +{len(all_findings)-100} mais[/]")

            if args.validate_secrets:
                from analyzer.credential_validators import validate_by_provider
                console.print("\n[bold yellow]Validando credenciais ativamente (requer rede)...[/]")
                for f in all_findings:
                    result = validate_by_provider(f["provider"], f["matched"])
                    if result:
                        color = {"VALID": "red", "INVALID": "dim", "UNKNOWN": "yellow"}.get(result.status, "white")
                        console.print(f"  [{color}]{result.status}[/] — {f['provider']} em {f['file_path']}")

        if args.save_secrets_baseline:
            from analyzer.secrets_baseline import save_secrets_baseline
            save_secrets_baseline(args.save_secrets_baseline, all_findings)
            console.print(f"[bold bright_green]✔[/] Baseline de segredos salvo → {args.save_secrets_baseline}")

        return 1 if all_findings else 0

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

        incremental_cache = None
        if args.incremental:
            from analyzer.incremental import IncrementalCache
            incremental_cache = IncrementalCache()

        engine = ScanEngine(
            min_severity=min_severity,
            languages=languages,
            include_comments=not args.no_comments,
            on_file_start=tracker.on_file_start,
            on_file_done=tracker.on_file_done,
            ast_analysis=args.ast_analysis,
            cpp_macros=args.cpp_macros,
            incremental_cache=incremental_cache,
        )

        if target_path.is_dir():
            report = engine.scan_directory(target)
        else:
            report = engine.scan_files([target])

        progress.update(task_id, description="[bold bright_green]Concluído![/bold bright_green]",
                        completed=total_files)

    console.print()

    # ── Watch mode ────────────────────────────────────────────────────────────
    if args.profile_json:
        import json
        profile_path = Path(args.profile_json)
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile_path.write_text(json.dumps({
            "label": "scan",
            "wall_seconds": report.total_time,
            "files_scanned": report.files_scanned,
            "findings": report.total_vulnerabilities,
        }, indent=2), encoding="utf-8")

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
    if args.education:
        from analyzer.ai_triage import explain_finding
        console.print("\n[bold bright_cyan]Modo education[/]")
        for scan_result in report.results:
            for vuln in scan_result.vulnerabilities:
                finding = {
                    "rule_id": vuln.rule_id, "cwe": vuln.cwe,
                    "description": vuln.description, "remediation": vuln.remediation,
                }
                console.print(f"\n[bold]{vuln.rule_id}[/]: {explain_finding(finding, education=True)}")

    if args.autofix_diff:
        from analyzer.remediation import default_engine
        diffs = []
        fix_engine = default_engine()
        for scan_result in report.results:
            source_path = Path(scan_result.file_path)
            if not source_path.exists():
                continue
            source = source_path.read_text(encoding="utf-8", errors="replace")
            findings = [
                {"rule_id": v.rule_id, "line_number": v.line_number}
                for v in scan_result.vulnerabilities
            ]
            try:
                patch = fix_engine.plan(str(source_path), source, findings)
                if patch.diff:
                    diffs.append(patch.diff)
                    if args.apply_fixes:
                        fix_engine.apply(patch, Path.cwd())
            except (OSError, ValueError, RuntimeError) as exc:
                console.print(f"[yellow]Autofix ignorado para {source_path}: {exc}[/]")
        fix_output = Path(args.autofix_diff)
        fix_output.parent.mkdir(parents=True, exist_ok=True)
        fix_output.write_text("\n".join(diffs), encoding="utf-8")
        console.print(f"[bold bright_green]✔[/] Patch salvo → {args.autofix_diff}")

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
    if args.pdf:
        from analyzer.reporting_ext import export_pdf
        export_pdf(report, args.pdf)
    if args.docx:
        from analyzer.reporting_ext import export_docx
        export_docx(report, args.docx)
    if args.xlsx:
        from analyzer.reporting_ext import export_xlsx
        export_xlsx(report, args.xlsx)
    if args.gitlab_sast:
        from analyzer.reporting_ext import gitlab_sast
        import json
        gitlab_path = Path(args.gitlab_sast)
        gitlab_path.parent.mkdir(parents=True, exist_ok=True)
        gitlab_path.write_text(
            json.dumps(gitlab_sast(report), indent=2, ensure_ascii=False), encoding="utf-8"
        )
    if args.interactive_html:
        from analyzer.reporting_ext import interactive_html
        interactive_path = Path(args.interactive_html)
        interactive_path.parent.mkdir(parents=True, exist_ok=True)
        interactive_path.write_text(interactive_html(report), encoding="utf-8")
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
