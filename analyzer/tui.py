"""
TUI Interativo — navegação por teclado, busca, ordenação, agrupamento,
dashboard de métricas, histórico de scans e configuração inline.
Zero dependências extras: usa apenas stdlib (msvcrt/termios) + rich.
"""
from __future__ import annotations
import os
import sys
import subprocess
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
        fd  = sys.stdin.fileno()
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

_ICONS     = {True: "📁", False: "📄"}
_SORT_MODES  = ["severity", "file", "rule", "line"]
_GROUP_MODES = ["flat", "file", "category", "language"]


class TUIApp:
    """
    Aplicação TUI com telas: browser → scanning → results → detail
                             → metrics → history → config.
    """

    def __init__(self, start_path: Optional[Path] = None):
        self.con = Console(highlight=False)
        self.screen = "browser"

        # ── Browser ───────────────────────────────────────────────────────
        self.cwd:      Path       = (start_path or Path.cwd()).resolve()
        self.entries:  List[Path] = []
        self.cursor:   int        = 0
        self.scroll:   int        = 0
        self.selected: Set[Path]  = set()

        # ── Resultados ────────────────────────────────────────────────────
        self.report:     Optional[ScanReport] = None
        self.res_cursor: int                  = 0
        self.res_scroll: int                  = 0
        self.sev_filter: Optional[Severity]   = None
        self.min_sev:    Severity             = Severity.INFO

        # ── Busca em tempo real ───────────────────────────────────────────
        self.search_mode:  bool = False
        self.search_query: str  = ""

        # ── Ordenação e agrupamento ────────────────────────────────────────
        self.sort_idx:  int = 0   # índice em _SORT_MODES
        self.group_idx: int = 0   # índice em _GROUP_MODES

        # ── Detalhe ───────────────────────────────────────────────────────
        self.det_idx: int = 0

        # ── Histórico ─────────────────────────────────────────────────────
        self.hist_cursor: int = 0

        # ── Config ────────────────────────────────────────────────────────
        self.cfg_cursor: int = 0

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
        return max(3, self.con.size.height - 11)

    def _pin(self) -> None:
        lh = self._lh()
        if self.cursor < self.scroll:
            self.scroll = self.cursor
        elif self.cursor >= self.scroll + lh:
            self.scroll = self.cursor - lh + 1

    def _vis(self) -> List[tuple]:
        lh = self._lh()
        return list(enumerate(self.entries[self.scroll:self.scroll + lh], start=self.scroll))

    # ── Renderização ─────────────────────────────────────────────────────────
    def _draw(self) -> None:
        self.con.clear()
        {
            "browser":  self._draw_browser,
            "scanning": self._draw_scanning,
            "results":  self._draw_results,
            "detail":   self._draw_detail,
            "metrics":  self._draw_metrics,
            "history":  self._draw_history,
            "config":   self._draw_config,
        }[self.screen]()

    def _topbar(self, left: str, right: str = "") -> None:
        w = self.con.size.width
        max_right = max(0, w - len(left) - 10)
        right_t = right if len(right) <= max_right else right[:max_right - 1] + "…"
        g = Table.grid(padding=(0, 2), expand=True)
        g.add_column(ratio=1)
        g.add_column(justify="right", no_wrap=True)
        g.add_row(Text(left, style="bold bright_white"), Text(right_t, style="dim white"))
        self.con.print(Panel(g, border_style="#444466", box=rbox.HEAVY, padding=(0, 1)))

    def _statusbar(self, text: Text) -> None:
        self.con.print(RichRule(style="#333355"))
        self.con.print(text)

    # ─────────────────────────────────────────────────────────── BROWSER ──
    def _draw_browser(self) -> None:
        w     = self.con.size.width
        sel_n = len(self.selected)

        self._topbar(
            "⚡ Vulnerability Analyzer — Selecionar Arquivos",
            f"v1.0.0  •  {self._rule_count()} regras"
        )

        pt = Text()
        pt.append("  📂 ", style="bright_yellow")
        pt.append(str(self.cwd), style="bold bright_cyan")
        self.con.print(pt)
        self.con.print()

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
                row.append(entry.name, style=(
                    "bold bright_cyan" if is_dir else
                    "white" if scanable else "dim"
                ))
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
                lines.append(f"  [bright_green]✓[/bright_green] [{lang_color}]{p.name}[/{lang_color}]")
            if sel_n > 15:
                lines.append(f"  [dim]... +{sel_n - 15} mais[/dim]")
            lines += ["", "[bold bright_white on #003355]  [S]  Iniciar Scan  [/]"]
            rgt_body = "\n".join(lines)
        else:
            rgt_body = (
                "[dim]Nenhum arquivo\nselecionado.\n\n"
                "[bold]Espaço[/bold] → arquivo\n"
                "[bold]Enter[/bold]  → entrar pasta\n"
                "[bold]A[/bold]      → todos do dir\n"
                "[bold]U[/bold]      → pasta acima\n"
                "[bold]D[/bold]      → métricas\n"
                "[bold]H[/bold]      → histórico\n"
                "[bold]C[/bold]      → configurações[/dim]"
            )

        outer = Table.grid(padding=(0, 1))
        outer.add_column(ratio=1)
        outer.add_column(min_width=34, max_width=36)
        outer.add_row(
            Panel(lft, border_style="#333355", box=rbox.SIMPLE, padding=(0, 0)),
            Panel(rgt_body, title="[bold bright_white] Selecionados [/]",
                  border_style="#335588", box=rbox.ROUNDED),
        )
        self.con.print(outer)

        n  = len(self.entries)
        st = Text()
        st.append(f"  {self.cursor + 1 if n else 0}/{n}", style="dim")
        if sel_n:
            st.append(f"   ✓ {sel_n} prontos", style="bold bright_green")
        st.append(
            "   [↑↓] mover  [Space] selecionar  [S] scan"
            "  [D] dash  [H] hist  [C] config  [Q] sair",
            style="dim"
        )
        self._statusbar(st)

    # ────────────────────────────────────────────────────────── SCANNING ──
    def _draw_scanning(self) -> None:
        self._topbar("⚡ Analisando código...", "aguarde")
        self.con.print()
        n = len(self.selected)
        self.con.print(Align(
            Panel(
                Align(
                    Text(
                        f"🔍  Escaneando {n} arquivo(s)…\n\nAguarde, aplicando 777+ regras.",
                        style="bold bright_cyan", justify="center",
                    ),
                    align="center",
                ),
                border_style="#33aaff", box=rbox.DOUBLE_EDGE, padding=(2, 8),
            ),
            align="center",
        ))

    # ─────────────────────────────────────────────────────────── RESULTS ──
    def _draw_results(self) -> None:
        vulns = self._fvulns()
        lh    = self._lh()

        sort_lbl  = _SORT_MODES[self.sort_idx].upper()
        group_lbl = _GROUP_MODES[self.group_idx].upper()
        filt_tag  = f"  [Filtro:{self.sev_filter.name}]" if self.sev_filter else ""
        q_tag     = f"  [Busca:'{self.search_query}']" if self.search_query else ""

        self._topbar(
            f"⚡ Resultados{filt_tag}{q_tag}",
            f"[/]busca  [O]sort:{sort_lbl}  [G]grup:{group_lbl}"
            "  [F]filtro  [D]dash  [H]hist  [Q]sair"
        )

        # ── Barra de busca inline ──────────────────────────────────────────
        if self.search_mode:
            sb = Text()
            sb.append("  🔍 Busca: ", style="bold bright_yellow")
            sb.append(self.search_query, style="bold white")
            sb.append("█", style="blink bright_yellow")
            sb.append("   [ESC] cancelar   [Enter] confirmar", style="dim")
            self.con.print(Panel(sb, border_style="#ffcc00", padding=(0, 1)))

        if not vulns:
            self.con.print()
            self.con.print(Align(
                Panel(
                    Text("✅  Nenhum problema encontrado!", style="bold bright_green", justify="center"),
                    border_style="bright_green", padding=(2, 8),
                ),
                align="center",
            ))
            st = Text()
            st.append("  [D] métricas   [H] histórico   [B] voltar   [Q] sair", style="dim")
            self._statusbar(st)
            return

        if self.res_cursor < self.res_scroll:
            self.res_scroll = self.res_cursor
        elif self.res_cursor >= self.res_scroll + lh:
            self.res_scroll = self.res_cursor - lh + 1

        w      = self.con.size.width
        nome_w = max(14, w - 62)
        t = Table(box=rbox.SIMPLE, show_header=True,
                  header_style="bold bright_white", padding=(0, 1))
        t.add_column("#",       min_width=4,      justify="right",  style="dim")
        t.add_column("Sev",     min_width=10,     no_wrap=True)
        t.add_column("Arquivo", min_width=18, max_width=24, no_wrap=True)
        t.add_column("L",       min_width=4,      justify="right",  style="dim")
        t.add_column("Regra",   min_width=8,      style="bright_black", no_wrap=True)
        t.add_column("Função",  min_width=12,     style="dim", no_wrap=True)
        t.add_column("Nome",    min_width=nome_w, no_wrap=True)

        grouped   = _GROUP_MODES[self.group_idx] != "flat"
        group_cnt = {}
        if grouped:
            for v in vulns:
                k = self._group_key(v)
                group_cnt[k] = group_cnt.get(k, 0) + 1

        vis       = vulns[self.res_scroll:self.res_scroll + lh]
        prev_grp  = self._group_key(vulns[self.res_scroll - 1]) if (grouped and self.res_scroll > 0) else None
        for rel, vuln in enumerate(vis, start=self.res_scroll):
            # Cabeçalho de seção quando o grupo muda
            if grouped:
                gk = self._group_key(vuln)
                if gk != prev_grp:
                    t.add_row(
                        "", Text("▸", style="bold bright_yellow"),
                        Text(gk[:24], style="bold bright_yellow"), "", "",
                        "", Text(f"({group_cnt.get(gk, 0)} achados)", style="dim"),
                    )
                    prev_grp = gk

            active = (rel == self.res_cursor)
            sc     = _SC[vuln.severity]
            sv     = Text(f" {vuln.severity.name:8}", style=f"bold {sc}")
            nm     = Path(vuln.file_path).name
            pre    = "▶ " if active else "  "
            dname  = vuln.name if len(vuln.name) <= nome_w else vuln.name[:nome_w - 1] + "…"
            fn_ctx = (vuln.function_context or "—")[:12]
            t.add_row(
                str(rel + 1), sv,
                pre + (nm[:20] if len(nm) > 20 else nm),
                str(vuln.line_number), vuln.rule_id, fn_ctx, dname,
                style="on #111128" if active else "",
            )
        self.con.print(t)

        st = Text()
        if self.report:
            st.append(f"  {len(vulns)} problemas", style="bold white")
            st.append(f"  em {self.report.files_with_issues} arquivo(s)", style="dim")
            for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                cnt = sum(1 for v in vulns if v.severity == s)
                if cnt:
                    st.append(f"   {s.name[0]} {cnt}", style=f"bold {_SC[s]}")
        st.append("   [Enter] detalhe  [J] JSON  [E] HTML  [B] voltar", style="dim")
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
            "[←→] navegar  [O] abrir editor  [X] suprimir  [B] lista  [Q] sair"
        )

        badge = Text()
        badge.append(f" {vuln.severity.name:8} ", style=f"bold {sc} {_SB[vuln.severity]}")
        badge.append(f"   {vuln.name}", style=f"bold {sc}")

        meta = Table(box=None, show_header=False, padding=(0, 2))
        meta.add_column(style="dim", min_width=12)
        meta.add_column()
        meta.add_row("Arquivo", f"[bold white]{Path(vuln.file_path).name}[/]  [dim]:{vuln.line_number}[/dim]")
        meta.add_row("Regra",   f"[bright_black]{vuln.rule_id}[/]")
        if vuln.function_context:
            meta.add_row("Função", f"[bright_yellow]{vuln.function_context}()[/]")
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
        if vuln.in_comment:
            meta.add_row("Aviso", "[dim](detectado em comentário)[/]")

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
                    code, lex, theme="monokai", line_numbers=True,
                    start_line=vuln.snippet_start_line,
                    highlight_lines={vuln.line_number}, word_wrap=True,
                )
                body.add_row(Text(""))
                body.add_row(Text("Código", style="bold bright_yellow"))
                body.add_row(syn)
            except Exception:
                pass

        # Preview de diff de remediação (linha problemática vs. sugestão)
        if vuln.line_content:
            body.add_row(Text(""))
            body.add_row(Text("Preview de remediação", style="bold dim"))
            diff_t = Text()
            diff_t.append("- ", style="bold red")
            diff_t.append(vuln.line_content.strip(), style="red")
            diff_t.append("\n+ ", style="bold bright_green")
            diff_t.append(vuln.remediation[:100] if vuln.remediation else "(ver descrição acima)",
                          style="bright_green")
            body.add_row(diff_t)

        self.con.print(Panel(body, border_style=sc, padding=(0, 1)))

    # ──────────────────────────────────────────────────────── METRICS ──
    def _draw_metrics(self) -> None:
        self._topbar("⚡ Dashboard de Métricas", "[B] voltar  [Q] sair")

        if not self.report:
            self.con.print(Align(
                Panel(Text("Nenhum scan realizado ainda.\nExecute um scan primeiro.",
                           style="dim", justify="center"),
                      border_style="#444466", padding=(2, 8)),
                align="center",
            ))
            st = Text()
            st.append("  [B] voltar   [Q] sair", style="dim")
            self._statusbar(st)
            return

        all_v = self._fvulns()
        if not all_v:
            self.con.print(Align(
                Panel(Text("✅ Nenhum achado!", style="bold bright_green", justify="center"),
                      border_style="bright_green", padding=(2, 8)),
                align="center",
            ))
            return

        from collections import Counter
        lang_counts = Counter(v.language.value for v in all_v)
        cat_counts  = Counter(v.category.value for v in all_v)
        bar_w       = 28

        def _bar(cnt: int, max_c: int, color: str = "bright_cyan") -> Text:
            n = int(bar_w * cnt / max_c) if max_c else 0
            t = Text()
            t.append("█" * n,        style=f"bold {color}")
            t.append("░" * (bar_w - n), style="bright_black")
            return t

        max_lang = max(lang_counts.values(), default=1)
        max_cat  = max(cat_counts.values(),  default=1)

        lang_t = Table(box=rbox.SIMPLE, show_header=True,
                       header_style="bold bright_white", padding=(0, 1),
                       title="[bold bright_cyan]Por Linguagem[/]")
        lang_t.add_column("Linguagem", min_width=14)
        lang_t.add_column("Barra",     min_width=bar_w)
        lang_t.add_column("Qtd",       min_width=5, justify="right")
        for lang, cnt in lang_counts.most_common(10):
            lang_t.add_row(lang, _bar(cnt, max_lang), str(cnt))

        cat_t = Table(box=rbox.SIMPLE, show_header=True,
                      header_style="bold bright_white", padding=(0, 1),
                      title="[bold bright_magenta]Por Categoria[/]")
        cat_t.add_column("Categoria",  min_width=26)
        cat_t.add_column("Barra",      min_width=bar_w)
        cat_t.add_column("Qtd",        min_width=5, justify="right")
        for cat, cnt in cat_counts.most_common(10):
            cat_t.add_row(cat, _bar(cnt, max_cat, "bright_magenta"), str(cnt))

        sev_t = Table(box=rbox.SIMPLE, show_header=True,
                      header_style="bold bright_white", padding=(0, 1),
                      title="[bold bright_red]Por Severidade[/]")
        sev_t.add_column("Severidade", min_width=10)
        sev_t.add_column("Barra",      min_width=bar_w)
        sev_t.add_column("Qtd",        min_width=5, justify="right")
        sev_pairs = [
            (Severity.CRITICAL, self.report.critical_count),
            (Severity.HIGH,     self.report.high_count),
            (Severity.MEDIUM,   self.report.medium_count),
            (Severity.LOW,      self.report.low_count),
            (Severity.INFO,     self.report.info_count),
        ]
        max_sev = max(c for _, c in sev_pairs) or 1
        for sev, cnt in sev_pairs:
            sev_t.add_row(
                Text(sev.name, style=f"bold {_SC[sev]}"),
                _bar(cnt, max_sev, _SC[sev]),
                str(cnt),
            )

        try:
            from analyzer.trend import TrendDB, ascii_trend
            hist      = TrendDB().history(10)
            trend_str = ascii_trend(hist, width=48, height=7)
        except Exception:
            trend_str = "(histórico não disponível)"

        grid = Table.grid(padding=(0, 1))
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_row(
            Panel(sev_t,  border_style="#553388", padding=(0, 1)),
            Panel(lang_t, border_style="#335588", padding=(0, 1)),
        )
        grid.add_row(
            Panel(cat_t, border_style="#225533", padding=(0, 1)),
            Panel(
                Text(trend_str, style="bright_cyan"),
                title="[bold bright_white] Tendência de Vulns [/]",
                border_style="#444466", padding=(0, 1)
            ),
        )
        self.con.print(grid)

        st = Text()
        st.append("  [B] voltar   [Q] sair", style="dim")
        self._statusbar(st)

    # ─────────────────────────────────────────────────────────── HISTORY ──
    def _draw_history(self) -> None:
        self._topbar("⚡ Histórico de Scans", "[↑↓] navegar  [B] voltar  [Q] sair")

        try:
            from analyzer.trend import TrendDB, ascii_trend
            history = TrendDB().history(20)
        except Exception:
            self.con.print(Align(
                Panel(Text("Banco de dados de histórico não disponível.", style="dim"),
                      border_style="#444466", padding=(1, 4)),
                align="center",
            ))
            st = Text()
            st.append("  [B] voltar   [Q] sair", style="dim")
            self._statusbar(st)
            return

        if not history:
            self.con.print(Align(
                Panel(Text("Nenhum scan registrado ainda.\nExecute um scan para criar o histórico.",
                           style="dim", justify="center"),
                      border_style="#444466", padding=(2, 8)),
                align="center",
            ))
            st = Text()
            st.append("  [B] voltar   [Q] sair", style="dim")
            self._statusbar(st)
            return

        t = Table(box=rbox.SIMPLE_HEAVY, border_style="#444466",
                  header_style="bold bright_cyan", padding=(0, 1),
                  title="[bold bright_white]Últimos 20 Scans[/]")
        t.add_column("ID",       min_width=4,  justify="right", style="dim")
        t.add_column("Data",     min_width=12)
        t.add_column("Target",   min_width=22)
        t.add_column("Arquivos", min_width=8,  justify="right")
        t.add_column("Total",    min_width=5,  justify="right", style="bold white")
        t.add_column("Crit",     min_width=4,  justify="right", style="#ff2244")
        t.add_column("High",     min_width=4,  justify="right", style="#ff6600")
        t.add_column("Tempo",    min_width=8,  justify="right", style="dim")
        for i, e in enumerate(history):
            active = (i == self.hist_cursor)
            t.add_row(
                str(e.id), e.dt,
                e.target[:22],
                str(e.files_scanned),
                str(e.total_vulns),
                str(e.critical) if e.critical else "—",
                str(e.high)     if e.high     else "—",
                f"{e.scan_time:.2f}s",
                style="on #111128" if active else "",
            )
        self.con.print(t)
        self.con.print()
        self.con.print("[bold bright_white]Gráfico de tendência:[/]")
        self.con.print(Text(ascii_trend(history, width=50), style="bright_cyan"))

        st = Text()
        st.append("  [↑↓] navegar   [B] voltar   [Q] sair", style="dim")
        self._statusbar(st)

    # ──────────────────────────────────────────────────────────── CONFIG ──
    def _draw_config(self) -> None:
        self._topbar("⚡ Configurações", "[↑↓] navegar  [Enter] alterar  [B] salvar/voltar  [Q] sair")

        opts = [
            ("Severidade mínima",  self.min_sev.name,              "Ocultar achados abaixo desta severidade"),
            ("Ordenação padrão",   _SORT_MODES[self.sort_idx],     "Como os resultados são ordenados"),
            ("Agrupamento",        _GROUP_MODES[self.group_idx],   "Como os resultados são agrupados"),
            ("Filtro de sev.",     self.sev_filter.name if self.sev_filter else "Nenhum",
             "Mostrar apenas achados desta severidade"),
        ]

        t = Table(box=rbox.ROUNDED, border_style="#444466",
                  header_style="bold bright_cyan", padding=(0, 2),
                  title="[bold bright_white]Configurações da Sessão[/]")
        t.add_column("Opção",      min_width=22)
        t.add_column("Valor",      min_width=14)
        t.add_column("Descrição",  min_width=40)
        for i, (name, val, desc) in enumerate(opts):
            active = (i == self.cfg_cursor)
            t.add_row(
                ("▶ " if active else "  ") + name,
                Text(val, style="bold bright_yellow"),
                Text(desc, style="dim"),
                style="on #111128" if active else "",
            )
        self.con.print()
        self.con.print(t)
        self.con.print()

        hint = Text()
        hint.append("  [↑↓] mover   [Enter] alterar valor   [B] voltar   [Q] sair", style="dim")
        self._statusbar(hint)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _fvulns(self) -> List[Vulnerability]:
        if not self.report:
            return []
        all_v = [v for r in self.report.results for v in r.vulnerabilities]

        # Filtro de severidade
        if self.sev_filter:
            all_v = [v for v in all_v if v.severity == self.sev_filter]

        # Filtro de busca
        if self.search_query:
            q = self.search_query.lower()
            all_v = [
                v for v in all_v
                if q in v.name.lower()
                or q in v.rule_id.lower()
                or q in v.file_path.lower()
                or q in v.description.lower()
                or q in v.category.value.lower()
            ]

        # Ordenação
        sort_mode = _SORT_MODES[self.sort_idx]
        if sort_mode == "severity":
            all_v.sort(key=lambda v: -v.severity.value)
        elif sort_mode == "file":
            all_v.sort(key=lambda v: (v.file_path, v.line_number))
        elif sort_mode == "rule":
            all_v.sort(key=lambda v: v.rule_id)
        elif sort_mode == "line":
            all_v.sort(key=lambda v: v.line_number)

        # Agrupamento: reordena para manter itens do mesmo grupo contíguos,
        # preservando a ordenação escolhida como critério secundário.
        if _GROUP_MODES[self.group_idx] != "flat":
            all_v.sort(key=lambda v: self._group_key(v).lower())

        return all_v

    def _group_key(self, vuln: Vulnerability) -> str:
        """Chave de agrupamento conforme o modo atual."""
        mode = _GROUP_MODES[self.group_idx]
        if mode == "file":
            return Path(vuln.file_path).name
        if mode == "category":
            return vuln.category.value
        if mode == "language":
            return vuln.language.value
        return ""

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
        _key()

    def _open_in_editor(self, vuln: Vulnerability) -> None:
        editor = os.environ.get("EDITOR") or os.environ.get("VISUAL")
        if not editor:
            editor = "notepad" if sys.platform == "win32" else "nano"
        fp = vuln.file_path
        ln = vuln.line_number
        try:
            if editor == "code":
                subprocess.Popen([editor, "--goto", f"{fp}:{ln}"])
            elif editor in ("vim", "nvim", "nano", "emacs"):
                subprocess.Popen([editor, f"+{ln}", fp])
            else:
                subprocess.Popen([editor, fp])
        except Exception as e:
            self._notify(f"Erro ao abrir editor: {e}", "red")

    def _inline_suppress(self, vuln: Vulnerability) -> None:
        try:
            p     = Path(vuln.file_path)
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            li    = vuln.line_number - 1
            if 0 <= li < len(lines):
                old = lines[li].rstrip("\n").rstrip("\r\n")
                if "vulnscan: ignore" not in old:
                    lines[li] = old + f"  # vulnscan: ignore {vuln.rule_id}\n"
                    p.write_text("".join(lines), encoding="utf-8")
                    self._notify(
                        f"✅ Supressão adicionada em\n{p.name}:{vuln.line_number}\n"
                        f"Regra: {vuln.rule_id}",
                        "bright_green",
                    )
                else:
                    self._notify("Linha já possui supressão.", "yellow")
        except Exception as e:
            self._notify(f"Erro ao suprimir: {e}", "red")

    # ── Scan ──────────────────────────────────────────────────────────────────
    def _do_scan(self) -> None:
        if not self.selected:
            self._notify("⚠  Nenhum arquivo selecionado.", "yellow")
            return

        self.screen = "scanning"
        self._draw()

        from analyzer.engine import ScanEngine
        engine     = ScanEngine(min_severity=self.min_sev)
        self.report = engine.scan_files([str(p) for p in sorted(self.selected)])

        try:
            from analyzer.trend import TrendDB
            TrendDB().record(self.report)
        except Exception:
            pass

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
                files = [f for f in p.rglob("*") if f.is_file() and is_scannable(str(f))]
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
            if self.cursor < n - 1:
                self.cursor += 1
                self._pin()
        elif k == "a":
            files = [e for e in self.entries if e.is_file() and is_scannable(str(e))]
            if all(e in self.selected for e in files):
                for e in files:
                    self.selected.discard(e)
            else:
                for e in files:
                    self.selected.add(e)
        elif k == "s":
            self._do_scan()
        elif k == "d":
            self.screen = "metrics"
        elif k == "h":
            self.screen = "history"
        elif k == "c":
            self.screen = "config"
        elif k in ("q", "ESC"):
            return False
        return True

    def _on_results(self, k: str) -> bool:
        # ── Modo busca ativa ──────────────────────────────────────────────
        if self.search_mode:
            if k == "ESC":
                self.search_mode  = False
                self.search_query = ""
                self.res_cursor   = 0
                self.res_scroll   = 0
            elif k == "ENTER":
                self.search_mode = False
                self.res_cursor  = 0
                self.res_scroll  = 0
            elif k == "BS":
                self.search_query = self.search_query[:-1]
            elif len(k) == 1 and k.isprintable():
                self.search_query += k
                self.res_cursor = 0
                self.res_scroll = 0
            return True

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
        elif k == "/":
            self.search_mode  = True
            self.search_query = ""
        elif k == "o":
            # Ciclar ordenação
            self.sort_idx   = (self.sort_idx + 1) % len(_SORT_MODES)
            self.res_cursor = 0
            self.res_scroll = 0
        elif k == "g":
            # Ciclar agrupamento: flat → file → category → language
            self.group_idx  = (self.group_idx + 1) % len(_GROUP_MODES)
            self.res_cursor = 0
            self.res_scroll = 0
        elif k == "f":
            self._cycle_sev()
        elif k == "d":
            self.screen = "metrics"
        elif k == "h":
            self.screen = "history"
        elif k == "c":
            self.screen = "config"
        elif k == "e":
            if self.report:
                try:
                    from analyzer.reporter import export_html
                    path = "relatorio_vulnerabilidades.html"
                    export_html(self.report, path)
                    self._notify(f"✅  HTML salvo: {path}")
                except Exception as ex:
                    self._notify(f"Erro: {ex}", "red")
        elif k == "j":
            if self.report:
                try:
                    from analyzer.reporter import export_json
                    path = "relatorio_vulnerabilidades.json"
                    export_json(self.report, path)
                    self._notify(f"✅  JSON salvo: {path}")
                except Exception as ex:
                    self._notify(f"Erro: {ex}", "red")
        elif k in ("b", "u", "LEFT", "BS"):
            self.screen = "browser"
        elif k in ("q", "ESC"):
            return False
        return True

    def _on_detail(self, k: str) -> bool:
        vulns = self._fvulns()
        n     = len(vulns)

        if k in ("RIGHT", "DOWN", "n"):
            self.det_idx    = min(n - 1, self.det_idx + 1)
            self.res_cursor = self.det_idx
        elif k in ("LEFT", "UP", "p"):
            self.det_idx    = max(0, self.det_idx - 1)
            self.res_cursor = self.det_idx
        elif k == "o" and vulns:
            self._open_in_editor(vulns[self.det_idx])
        elif k == "x" and vulns:
            self._inline_suppress(vulns[self.det_idx])
        elif k in ("b", "BS", "ESC"):
            self.screen = "results"
        elif k == "q":
            return False
        return True

    def _on_metrics(self, k: str) -> bool:
        if k in ("b", "BS", "LEFT", "ESC"):
            self.screen = "results" if self.report else "browser"
        elif k == "q":
            return False
        return True

    def _on_history(self, k: str) -> bool:
        if k == "UP":
            if self.hist_cursor > 0:
                self.hist_cursor -= 1
        elif k == "DOWN":
            self.hist_cursor += 1
        elif k in ("b", "BS", "LEFT", "ESC"):
            self.screen = "results" if self.report else "browser"
        elif k == "q":
            return False
        return True

    def _on_config(self, k: str) -> bool:
        cfg_max = 3
        if k == "UP":
            self.cfg_cursor = max(0, self.cfg_cursor - 1)
        elif k == "DOWN":
            self.cfg_cursor = min(cfg_max, self.cfg_cursor + 1)
        elif k == "ENTER":
            if self.cfg_cursor == 0:
                sevs         = list(Severity)
                idx          = sevs.index(self.min_sev)
                self.min_sev = sevs[(idx + 1) % len(sevs)]
            elif self.cfg_cursor == 1:
                self.sort_idx = (self.sort_idx + 1) % len(_SORT_MODES)
            elif self.cfg_cursor == 2:
                self.group_idx = (self.group_idx + 1) % len(_GROUP_MODES)
            elif self.cfg_cursor == 3:
                self._cycle_sev()
        elif k in ("b", "BS", "ESC"):
            self.screen = "results" if self.report else "browser"
        elif k == "q":
            return False
        return True

    # ── Loop principal ────────────────────────────────────────────────────────
    def run(self) -> None:
        handlers = {
            "browser": self._on_browser,
            "results": self._on_results,
            "detail":  self._on_detail,
            "metrics": self._on_metrics,
            "history": self._on_history,
            "config":  self._on_config,
        }
        try:
            while True:
                self._draw()
                k  = _key()
                fn = handlers.get(self.screen)
                if fn:
                    if not fn(k):
                        break
                else:
                    if k in ("q", "ESC"):
                        break
        finally:
            self.con.clear()
            self.con.print("[dim]TUI encerrado.[/dim]")


# ── Ponto de entrada público ──────────────────────────────────────────────────
def run_tui(start_path: Optional[Path] = None) -> None:
    TUIApp(start_path).run()
