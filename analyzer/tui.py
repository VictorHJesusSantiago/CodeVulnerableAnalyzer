"""
TUI Interativo — navegação por teclado, seleção de arquivos e visualização de resultados.
Zero dependências extras: usa apenas stdlib (msvcrt/termios) + rich.
"""
from __future__ import annotations
import sys
from pathlib import Path
from typing import Optional, List, Set

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax
from rich.align import Align
from rich.rule import Rule as RichRule
from rich import box as rbox

from analyzer.models import Severity, Vulnerability, ScanReport
from analyzer.detector import is_scannable, SKIP_DIRS

# ── Leitura de teclado (cross-platform, stdlib puro) ─────────────────────────
if sys.platform == "win32":
    import msvcrt

    def _key() -> str:
        ch = msvcrt.getch()
        if ch in (b"\x00", b"\xe0"):
            ext = msvcrt.getch()
            return {
                b"H": "UP",   b"P": "DOWN",  b"K": "LEFT",  b"M": "RIGHT",
                b"I": "PGUP", b"Q": "PGDN",  b"G": "HOME",  b"O": "END",
            }.get(ext, "")
        MAP = {b"\r": "ENTER", b"\n": "ENTER", b"\x1b": "ESC",
               b" ": "SPACE", b"\t": "TAB",    b"\x08": "BS", b"\x7f": "BS"}
        if ch in MAP:
            return MAP[ch]
        try:
            return ch.decode("utf-8").lower()
        except Exception:
            return ""
else:
    import tty
    import termios

    def _key() -> str:
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.buffer.read(1)
            if ch == b"\x1b":
                nxt = sys.stdin.buffer.read(2)
                return {
                    b"[A": "UP",   b"[B": "DOWN",  b"[D": "LEFT",  b"[C": "RIGHT",
                    b"[5": "PGUP", b"[6": "PGDN",  b"[H": "HOME",  b"[F": "END",
                }.get(nxt, "ESC")
            MAP = {b"\r": "ENTER", b"\n": "ENTER", b" ": "SPACE",
                   b"\t": "TAB",   b"\x08": "BS",  b"\x7f": "BS"}
            if ch in MAP:
                return MAP[ch]
            try:
                return ch.decode("utf-8").lower()
            except Exception:
                return ""
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


# ── Paleta ────────────────────────────────────────────────────────────────────
_SC = {
    Severity.CRITICAL: "#ff2244",
    Severity.HIGH:     "#ff6600",
    Severity.MEDIUM:   "#ffcc00",
    Severity.LOW:      "#33aaff",
    Severity.INFO:     "#888888",
}
_SB = {
    Severity.CRITICAL: "on #550010",
    Severity.HIGH:     "on #552000",
    Severity.MEDIUM:   "on #4a3800",
    Severity.LOW:      "on #00224d",
    Severity.INFO:     "on #222222",
}

_ICONS = {True: "📁", False: "📄"}


class TUIApp:
    """Aplicação TUI com 4 telas: browser → scanning → results → detail."""

    def __init__(self, start_path: Optional[Path] = None):
        self.con = Console(highlight=False)

        # tela atual
        self.screen = "browser"

        # ── Browser ───────────────────────────────────────────────────────
        self.cwd:      Path       = (start_path or Path.cwd()).resolve()
        self.entries:  List[Path] = []
        self.cursor:   int        = 0
        self.scroll:   int        = 0
        self.selected: Set[Path]  = set()

        # ── Resultados ────────────────────────────────────────────────────
        self.report:      Optional[ScanReport]   = None
        self.vulns:       List[Vulnerability]    = []
        self.res_cursor:  int                    = 0
        self.res_scroll:  int                    = 0
        self.sev_filter:  Optional[Severity]     = None
        self.min_sev:     Severity               = Severity.INFO

        # ── Detalhe ───────────────────────────────────────────────────────
        self.det_idx: int = 0

        self._load()

    # ── Carregamento de entradas ──────────────────────────────────────────────
    def _load(self) -> None:
        items: List[Path] = []
        try:
            for p in sorted(self.cwd.iterdir(),
                            key=lambda x: (not x.is_dir(), x.name.lower())):
                skip = p.name in SKIP_DIRS or (
                    p.name.startswith(".") and p.name not in (".env",)
                )
                if not skip:
                    items.append(p)
        except PermissionError:
            pass
        self.entries = items
        self.cursor  = 0
        self.scroll  = 0

    def _lh(self) -> int:
        """Altura útil da lista."""
        return max(3, self.con.size.height - 11)

    def _pin(self) -> None:
        """Mantém cursor visível na janela de scroll."""
        lh = self._lh()
        if self.cursor < self.scroll:
            self.scroll = self.cursor
        elif self.cursor >= self.scroll + lh:
            self.scroll = self.cursor - lh + 1

    def _vis(self) -> List[tuple]:
        lh = self._lh()
        return list(enumerate(self.entries[self.scroll:self.scroll + lh],
                               start=self.scroll))

    # ── Renderização ─────────────────────────────────────────────────────────
    def _draw(self) -> None:
        self.con.clear()
        {"browser":  self._draw_browser,
         "scanning": self._draw_scanning,
         "results":  self._draw_results,
         "detail":   self._draw_detail}[self.screen]()

    def _topbar(self, left: str, right: str = "") -> None:
        w = self.con.size.width
        # Truncate right-side controls if terminal is narrow
        max_right = max(0, w - len(left) - 10)
        right_t = right if len(right) <= max_right else right[:max_right - 1] + "…"
        g = Table.grid(padding=(0, 2), expand=True)
        g.add_column(ratio=1)
        g.add_column(justify="right", no_wrap=True)
        g.add_row(
            Text(left,    style="bold bright_white"),
            Text(right_t, style="dim white"),
        )
        self.con.print(Panel(g, border_style="#444466", box=rbox.HEAVY,
                             padding=(0, 1)))

    def _statusbar(self, text: Text) -> None:
        self.con.print(RichRule(style="#333355"))
        self.con.print(text)

    # ────────────────────────────────────────────────────────────── BROWSER ──
    def _draw_browser(self) -> None:
        w = self.con.size.width
        sel_n = len(self.selected)

        self._topbar(
            "⚡ Vulnerability Analyzer — Selecionar Arquivos",
            f"v1.0.0  •  {self._rule_count()} regras"
        )

        # caminho atual
        pt = Text()
        pt.append("  📂 ", style="bright_yellow")
        pt.append(str(self.cwd), style="bold bright_cyan")
        self.con.print(pt)
        self.con.print()

        # ── painel esquerdo: lista de arquivos ────────────────────────────
        lft = Table(box=None, show_header=False, padding=(0, 0))
        lft.add_column("", min_width=max(20, w - 38))

        if not self.entries:
            lft.add_row(Text("  (diretório vazio)", style="dim"))
        else:
            for idx, entry in self._vis():
                active   = idx == self.cursor
                is_dir   = entry.is_dir()
                scanable = not is_dir and is_scannable(str(entry))
                sel      = entry in self.selected

                row = Text()
                row.append("▶ " if active else "  ",
                            style="bold bright_yellow" if active else "dim")
                row.append(_ICONS[is_dir] + " ")
                row.append(
                    entry.name,
                    style=(
                        "bold bright_cyan" if is_dir else
                        "white"            if scanable else
                        "dim"
                    )
                )
                if is_dir:
                    try:
                        nc = sum(1 for _ in entry.iterdir())
                        row.append(f"  ({nc} itens)", style="dim")
                    except Exception:
                        pass
                elif sel:
                    row.append("  ✓", style="bold bright_green")
                elif not scanable:
                    row.append("  (não suportado)", style="dim")

                lft.add_row(row, style="on #111128" if active else "")

        # ── painel direito: selecionados ──────────────────────────────────
        if sel_n:
            lines = [f"[bold bright_green]{sel_n}[/bold bright_green] arquivo(s) selecionado(s)\n"]
            for p in sorted(self.selected)[:15]:
                lang_color = "white"
                try:
                    from analyzer.detector import detect_language
                    lc = detect_language(str(p))
                    lang_color = lc.color()
                except Exception:
                    pass
                lines.append(f"  [bright_green]✓[/bright_green] "
                              f"[{lang_color}]{p.name}[/{lang_color}]")
            if sel_n > 15:
                lines.append(f"  [dim]... +{sel_n - 15} mais[/dim]")
            lines += ["", "[bold bright_white on #003355]  [S]  Iniciar Scan  [/]"]
            rgt_body = "\n".join(lines)
        else:
            rgt_body = ("[dim]Nenhum arquivo\nselecionado.\n\n"
                        "[bold]Espaço[/bold] → arquivo\n"
                        "[bold]Enter[/bold]  → entrar pasta\n"
                        "[bold]A[/bold]      → todos do dir\n"
                        "[bold]U[/bold]      → pasta acima[/dim]")

        outer = Table.grid(padding=(0, 1))
        outer.add_column(ratio=1)
        outer.add_column(min_width=34, max_width=36)
        outer.add_row(
            Panel(lft, border_style="#333355", box=rbox.SIMPLE, padding=(0, 0)),
            Panel(rgt_body, title="[bold bright_white] Selecionados [/]",
                  border_style="#335588", box=rbox.ROUNDED),
        )
        self.con.print(outer)

        n = len(self.entries)
        st = Text()
        st.append(f"  {self.cursor + 1 if n else 0}/{n}",  style="dim")
        if sel_n:
            st.append(f"   ✓ {sel_n} prontos para scan", style="bold bright_green")
        st.append("   [↑↓] mover  [Space] selecionar  [S] scan  [Q] sair", style="dim")
        self._statusbar(st)

    # ─────────────────────────────────────────────────────────── SCANNING ──
    def _draw_scanning(self) -> None:
        self._topbar("⚡ Analisando código...", "aguarde")
        self.con.print()
        n = len(self.selected)
        self.con.print(Align(
            Panel(
                Align(
                    Text(f"🔍  Escaneando {n} arquivo(s)…\n\n"
                         "Aguarde, aplicando 396+ regras.",
                         style="bold bright_cyan", justify="center"),
                    align="center",
                ),
                border_style="#33aaff",
                box=rbox.DOUBLE_EDGE,
                padding=(2, 8),
            ),
            align="center",
        ))

    # ─────────────────────────────────────────────────────────── RESULTS ──
    def _draw_results(self) -> None:
        vulns = self._fvulns()
        lh    = self._lh()

        filt  = f"  [Filtro: {self.sev_filter.name}]" if self.sev_filter else ""
        self._topbar(
            f"⚡ Resultados{filt}",
            "[↑↓] mover  [Enter] detalhe  [F] filtrar  [E] HTML  [B] voltar  [Q] sair"
        )

        if not vulns:
            self.con.print()
            self.con.print(Align(
                Panel(
                    Text("✅  Nenhum problema encontrado!",
                         style="bold bright_green", justify="center"),
                    border_style="bright_green",
                    padding=(2, 8),
                ),
                align="center",
            ))
            return

        # scroll
        if self.res_cursor < self.res_scroll:
            self.res_scroll = self.res_cursor
        elif self.res_cursor >= self.res_scroll + lh:
            self.res_scroll = self.res_cursor - lh + 1

        w = self.con.size.width
        # fixed cols use ~56 chars; remainder goes to Nome
        nome_w = max(14, w - 58)
        t = Table(box=rbox.SIMPLE, show_header=True,
                  header_style="bold bright_white", padding=(0, 1))
        t.add_column("#",       min_width=4,  justify="right", style="dim")
        t.add_column("Sev",     min_width=10, no_wrap=True)
        t.add_column("Arquivo", min_width=18, max_width=24, no_wrap=True)
        t.add_column("L",       min_width=4,  justify="right", style="dim")
        t.add_column("Regra",   min_width=8,  style="bright_black", no_wrap=True)
        t.add_column("Nome",    min_width=nome_w, no_wrap=True)

        vis = vulns[self.res_scroll:self.res_scroll + lh]
        for rel, vuln in enumerate(vis, start=self.res_scroll):
            active = (rel == self.res_cursor)
            sc = _SC[vuln.severity]
            sv = Text(f" {vuln.severity.name:8}", style=f"bold {sc}")
            nm = Path(vuln.file_path).name
            pre = "▶ " if active else "  "
            display_name = vuln.name if len(vuln.name) <= nome_w else vuln.name[:nome_w - 1] + "…"
            t.add_row(
                str(rel + 1), sv,
                pre + (nm[:20] if len(nm) > 20 else nm),
                str(vuln.line_number),
                vuln.rule_id,
                display_name,
                style="on #111128" if active else "",
            )

        self.con.print(t)

        # barra de stats
        st = Text()
        if self.report:
            st.append(f"  {len(vulns)} problemas", style="bold white")
            st.append(f"  em {self.report.files_with_issues} arquivo(s)", style="dim")
            for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                cnt = sum(1 for v in vulns if v.severity == s)
                if cnt:
                    st.append(f"   {s.name} {cnt}", style=f"bold {_SC[s]}")
        self._statusbar(st)

    # ──────────────────────────────────────────────────────────── DETAIL ──
    def _draw_detail(self) -> None:
        vulns = self._fvulns()
        if not vulns:
            self.screen = "results"
            return

        idx  = max(0, min(self.det_idx, len(vulns) - 1))
        vuln = vulns[idx]
        sc   = _SC[vuln.severity]

        self._topbar(
            f"⚡ Detalhe  {idx + 1}/{len(vulns)}",
            "[←→ / ↑↓] navegar  [B] lista  [Q] sair"
        )

        badge = Text()
        badge.append(f" {vuln.severity.name:8} ",
                     style=f"bold {sc} {_SB[vuln.severity]}")
        badge.append(f"   {vuln.name}", style=f"bold {sc}")

        meta = Table(box=None, show_header=False, padding=(0, 2))
        meta.add_column(style="dim", min_width=12)
        meta.add_column()
        meta.add_row("Arquivo",   f"[bold white]{Path(vuln.file_path).name}[/]"
                                   f"  [dim]:{vuln.line_number}[/dim]")
        meta.add_row("Regra",     f"[bright_black]{vuln.rule_id}[/]")
        if vuln.cwe or vuln.owasp:
            refs = Text()
            if vuln.cwe:
                refs.append(vuln.cwe, style="cyan")
            if vuln.owasp:
                refs.append("   " + vuln.owasp, style="bright_magenta")
            meta.add_row("Refs", refs)
        meta.add_row("Categoria", f"[bright_blue]{vuln.category.value}[/]")
        meta.add_row("Confiança", vuln.confidence.label())
        meta.add_row("Linguagem", f"[{vuln.language.color()}]{vuln.language.value}[/]")

        body = Table.grid(padding=(0, 1))
        body.add_column()
        body.add_row(badge)
        body.add_row(Text(""))
        body.add_row(meta)
        body.add_row(Text(""))
        body.add_row(Text("Descrição", style="bold bright_white"))
        body.add_row(Text(vuln.description, style="white"))
        body.add_row(Text(""))
        body.add_row(Text("Remediação", style="bold bright_green"))
        body.add_row(Text(vuln.remediation, style="bright_green"))

        if vuln.snippet:
            from analyzer.reporter import LANG_SYNTAX_MAP
            lex  = LANG_SYNTAX_MAP.get(vuln.language, "text")
            code = "\n".join(vuln.snippet)
            try:
                syn = Syntax(
                    code, lex,
                    theme="monokai",
                    line_numbers=True,
                    start_line=vuln.snippet_start_line,
                    highlight_lines={vuln.line_number},
                    word_wrap=True,
                )
                body.add_row(Text(""))
                body.add_row(Text("Código", style="bold bright_yellow"))
                body.add_row(syn)
            except Exception:
                pass

        self.con.print(Panel(body, border_style=sc, padding=(0, 1)))

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _fvulns(self) -> List[Vulnerability]:
        if not self.report:
            return []
        all_v = sorted(
            (v for r in self.report.results for v in r.vulnerabilities),
            key=lambda v: -v.severity.value,
        )
        if self.sev_filter:
            return [v for v in all_v if v.severity == self.sev_filter]
        return all_v

    def _cycle_sev(self) -> None:
        order = [None, Severity.CRITICAL, Severity.HIGH,
                 Severity.MEDIUM, Severity.LOW, Severity.INFO]
        try:
            i = order.index(self.sev_filter)
            self.sev_filter = order[(i + 1) % len(order)]
        except ValueError:
            self.sev_filter = None
        self.res_cursor = 0
        self.res_scroll = 0

    @staticmethod
    def _rule_count() -> int:
        try:
            from analyzer.rules import rule_count
            return rule_count()
        except Exception:
            return 0

    def _notify(self, msg: str, color: str = "bright_green") -> None:
        self.con.clear()
        self.con.print()
        self.con.print(Align(
            Panel(Text(msg, style=f"bold {color}", justify="center"),
                  border_style=color, padding=(1, 6)),
            align="center",
        ))
        _key()  # aguarda qualquer tecla

    # ── Scan ──────────────────────────────────────────────────────────────────
    def _do_scan(self) -> None:
        if not self.selected:
            self._notify("⚠  Nenhum arquivo selecionado.", "yellow")
            return

        self.screen = "scanning"
        self._draw()

        from analyzer.engine import ScanEngine
        engine = ScanEngine(min_severity=self.min_sev)
        self.report = engine.scan_files([str(p) for p in sorted(self.selected)])

        self.res_cursor = 0
        self.res_scroll = 0
        self.sev_filter = None
        self.screen     = "results"

    # ── Handlers de teclado ───────────────────────────────────────────────────
    def _on_browser(self, k: str) -> bool:
        n = len(self.entries)

        if k == "UP":
            if self.cursor > 0:
                self.cursor -= 1
                self._pin()
        elif k == "DOWN":
            if self.cursor < n - 1:
                self.cursor += 1
                self._pin()
        elif k == "PGUP":
            self.cursor = max(0, self.cursor - self._lh())
            self._pin()
        elif k == "PGDN":
            self.cursor = min(max(0, n - 1), self.cursor + self._lh())
            self._pin()
        elif k == "HOME":
            self.cursor = 0
            self._pin()
        elif k == "END":
            self.cursor = max(0, n - 1)
            self._pin()
        elif k == "ENTER":
            if self.entries and self.entries[self.cursor].is_dir():
                self.cwd = self.entries[self.cursor]
                self._load()
        elif k in ("u", "LEFT", "BS"):
            parent = self.cwd.parent
            if parent != self.cwd:
                self.cwd = parent
                self._load()
        elif k == "SPACE":
            if not self.entries:
                return True
            p = self.entries[self.cursor]
            if p.is_dir():
                files = [f for f in p.rglob("*")
                         if f.is_file() and is_scannable(str(f))]
                if any(f in self.selected for f in files):
                    for f in files:
                        self.selected.discard(f)
                else:
                    for f in files:
                        self.selected.add(f)
            elif is_scannable(str(p)):
                if p in self.selected:
                    self.selected.discard(p)
                else:
                    self.selected.add(p)
            # avança cursor
            if self.cursor < n - 1:
                self.cursor += 1
                self._pin()
        elif k == "a":
            files = [e for e in self.entries
                     if e.is_file() and is_scannable(str(e))]
            if all(e in self.selected for e in files):
                for e in files:
                    self.selected.discard(e)
            else:
                for e in files:
                    self.selected.add(e)
        elif k == "s":
            self._do_scan()
        elif k in ("q", "ESC"):
            return False
        return True

    def _on_results(self, k: str) -> bool:
        vulns = self._fvulns()
        n     = len(vulns)
        lh    = self._lh()

        if k == "UP":
            if self.res_cursor > 0:
                self.res_cursor -= 1
        elif k == "DOWN":
            if self.res_cursor < n - 1:
                self.res_cursor += 1
        elif k == "PGUP":
            self.res_cursor = max(0, self.res_cursor - lh)
        elif k == "PGDN":
            self.res_cursor = min(max(0, n - 1), self.res_cursor + lh)
        elif k == "HOME":
            self.res_cursor = 0
        elif k == "END":
            self.res_cursor = max(0, n - 1)
        elif k == "ENTER":
            if vulns:
                self.det_idx = self.res_cursor
                self.screen  = "detail"
        elif k == "f":
            self._cycle_sev()
        elif k == "e":
            if self.report:
                try:
                    from analyzer.reporter import export_html
                    path = "relatorio_vulnerabilidades.html"
                    export_html(self.report, path)
                    self._notify(f"✅  Relatório salvo em: {path}")
                except Exception as ex:
                    self._notify(f"Erro ao exportar: {ex}", "red")
        elif k == "j":
            if self.report:
                try:
                    from analyzer.reporter import export_json
                    path = "relatorio_vulnerabilidades.json"
                    export_json(self.report, path)
                    self._notify(f"✅  JSON salvo em: {path}")
                except Exception as ex:
                    self._notify(f"Erro ao exportar: {ex}", "red")
        elif k in ("b", "u", "LEFT", "BS"):
            self.screen = "browser"
        elif k in ("q", "ESC"):
            return False
        return True

    def _on_detail(self, k: str) -> bool:
        vulns = self._fvulns()
        n     = len(vulns)

        if k in ("RIGHT", "DOWN", "n"):
            self.det_idx = min(n - 1, self.det_idx + 1)
            self.res_cursor = self.det_idx
        elif k in ("LEFT", "UP", "p"):
            self.det_idx = max(0, self.det_idx - 1)
            self.res_cursor = self.det_idx
        elif k in ("b", "BS", "ESC"):
            self.screen = "results"
        elif k == "q":
            return False
        return True

    # ── Loop principal ────────────────────────────────────────────────────────
    def run(self) -> None:
        handlers = {
            "browser": self._on_browser,
            "results": self._on_results,
            "detail":  self._on_detail,
        }
        try:
            while True:
                self._draw()
                k = _key()
                fn = handlers.get(self.screen)
                if fn and not fn(k):
                    break
                elif not fn and k in ("q", "ESC"):
                    break
        finally:
            self.con.clear()
            self.con.print("[dim]TUI encerrado.[/dim]")


# ── Ponto de entrada público ──────────────────────────────────────────────────
def run_tui(start_path: Optional[Path] = None) -> None:
    TUIApp(start_path).run()
