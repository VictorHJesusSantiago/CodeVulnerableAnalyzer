from __future__ import annotations
import os
import re
import time
import json
from pathlib import Path
from typing import List, Optional, Callable, Set, Dict

from analyzer.models import (
    Language, Severity, Vulnerability, ScanResult, ScanReport, Confidence
)
from analyzer.detector import detect_language, is_scannable, get_comment_prefix, SKIP_DIRS
from analyzer.rules import get_rules
from analyzer.complexity import analyze_complexity

CONTEXT_LINES    = 3
MAX_FILE_SIZE_MB = 5
MAX_LINE_LENGTH  = 2000

# ── Taint: fontes e sinks ─────────────────────────────────────────────────────

_TAINT_SOURCE_RE = re.compile(
    r'\b(\w+)\s*=\s*(?:'
    r'request\.(?:args|form|json|data|values|get|params|cookies|headers)\b|'
    r'sys\.argv\[|'
    r'input\s*\(|'
    r'os\.environ\b|'
    r'os\.getenv\s*\(|'
    r'urllib\.parse\.parse_qs\s*\(|'
    r'flask\.request\b|'
    r'fastapi\.Request\b'
    r')'
)
_TAINT_SINK_RE = re.compile(
    r'(?:eval|exec|os\.system|subprocess\.(?:run|call|Popen)|'
    r'cursor\.execute|engine\.execute|render_template_string|'
    r'__import__)\s*\([^)]*\b(\w+)\b'
)

# ── Contexto de função ────────────────────────────────────────────────────────

_FUNC_DEF_RE  = re.compile(
    r'^\s*(?:def|async def|function|func|fn|method|sub|void|'
    r'public|private|protected|static|fun)\s+(\w+)'
)
_CLASS_DEF_RE = re.compile(r'^\s*(?:class|struct|interface|impl|trait)\s+(\w+)')


def _get_function_context(lines: List[str], line_idx: int) -> Optional[str]:
    for i in range(line_idx, max(-1, line_idx - 60), -1):
        m = _FUNC_DEF_RE.match(lines[i])
        if m:
            return m.group(1)
        m = _CLASS_DEF_RE.match(lines[i])
        if m:
            return m.group(1)
    return None


# ── Supressão ─────────────────────────────────────────────────────────────────

_SUPPRESS_INLINE_RE = re.compile(r'#\s*vulnscan:\s*ignore\s+(\S+)', re.IGNORECASE)


def _load_ignore_file(directory: str) -> Set[str]:
    """Carrega entradas do .vulnscan-ignore (RULE_ID ou ARQUIVO:RULE_ID por linha)."""
    path = Path(directory) / ".vulnscan-ignore"
    suppressed: Set[str] = set()
    if not path.exists():
        return suppressed
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                suppressed.add(line)
    except OSError:
        pass
    return suppressed


def _is_inline_suppressed(line: str, rule_id: str) -> bool:
    m = _SUPPRESS_INLINE_RE.search(line)
    if m:
        suppressed = m.group(1)
        return suppressed in (rule_id, "ALL", "*")
    return False


def _is_globally_suppressed(rule_id: str, file_path: str, suppressed: Set[str]) -> bool:
    return (rule_id in suppressed
            or f"{Path(file_path).name}:{rule_id}" in suppressed)


# ── Regras customizadas ───────────────────────────────────────────────────────

def _load_custom_rules() -> List:
    """Carrega regras de ./vulnscan-rules.json ou ~/.vulnscan/rules/*.json."""
    from analyzer.rules.base import Rule
    from analyzer.models import Severity, Confidence, Language, VulnCategory

    _sev_map  = {s.name: s   for s in Severity}
    _conf_map = {c.name: c   for c in Confidence}
    _cat_map  = {c.value: c  for c in VulnCategory}
    _lang_map = {l.value: l  for l in Language}

    sources: List[Path] = []
    cwd_file = Path("vulnscan-rules.json")
    if cwd_file.exists():
        sources.append(cwd_file)
    home_dir = Path.home() / ".vulnscan" / "rules"
    if home_dir.is_dir():
        sources.extend(sorted(home_dir.glob("*.json")))

    custom: List[Rule] = []
    for src in sources:
        try:
            data  = json.loads(src.read_text(encoding="utf-8"))
            items = data if isinstance(data, list) else data.get("rules", [])
            for entry in items:
                try:
                    lang_val = entry.get("language", "generic").title()
                    rule = Rule(
                        id=entry["id"],
                        name=entry.get("name", entry["id"]),
                        description=entry.get("description", ""),
                        severity=_sev_map.get(entry.get("severity", "MEDIUM").upper(), Severity.MEDIUM),
                        category=_cat_map.get(entry.get("category", "Other"), VulnCategory.OTHER),
                        language=_lang_map.get(lang_val, Language.GENERIC),
                        pattern=entry["pattern"],
                        remediation=entry.get("remediation", ""),
                        cwe=entry.get("cwe"),
                        owasp=entry.get("owasp"),
                        confidence=_conf_map.get(entry.get("confidence", "MEDIUM").upper(), Confidence.MEDIUM),
                        flags=re.IGNORECASE if entry.get("ignorecase") else 0,
                        negative_pattern=entry.get("negative_pattern"),
                        multiline=entry.get("multiline", False),
                        depends_on=entry.get("depends_on"),
                    )
                    custom.append(rule)
                except (KeyError, ValueError):
                    pass
        except (json.JSONDecodeError, OSError):
            pass
    return custom


# ── Config ────────────────────────────────────────────────────────────────────

def _load_config() -> dict:
    """Carrega vulnscan.toml ou vulnscan.json do diretório atual."""
    toml_path = Path("vulnscan.toml")
    json_path = Path("vulnscan.json")

    if toml_path.exists():
        try:
            try:
                import tomllib  # Python 3.11+
            except ImportError:
                tomllib = None
            if tomllib:
                with toml_path.open("rb") as f:
                    return tomllib.load(f)
        except Exception:
            pass

    if json_path.exists():
        try:
            return json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    return {}


# ── Engine principal ──────────────────────────────────────────────────────────

class ScanEngine:
    def __init__(
        self,
        min_severity:   Severity                          = Severity.INFO,
        languages:      Optional[List[Language]]          = None,
        include_comments: bool                            = True,
        on_file_start:  Optional[Callable[[str], None]]   = None,
        on_file_done:   Optional[Callable[[ScanResult], None]] = None,
        only_lines:     Optional[Dict[str, Set[int]]]     = None,
        custom_rules:   Optional[List]                    = None,
        global_suppress: Optional[Set[str]]               = None,
    ):
        self.min_severity      = min_severity
        self.languages         = languages
        self.include_comments  = include_comments
        self.on_file_start     = on_file_start
        self.on_file_done      = on_file_done
        self.only_lines        = only_lines or {}
        self._custom_rules     = custom_rules if custom_rules is not None else _load_custom_rules()
        self._global_suppress  = global_suppress if global_suppress is not None else set()
        self._config           = _load_config()

    # ── Arquivo único ─────────────────────────────────────────────────────────

    def scan_file(self, file_path: str) -> ScanResult:
        start = time.perf_counter()
        path  = Path(file_path)

        if self.on_file_start:
            self.on_file_start(file_path)

        if not path.exists():
            return ScanResult(file_path, Language.UNKNOWN, [], 0, 0.0, "File not found")

        try:
            size_mb = path.stat().st_size / (1024 * 1024)
            if size_mb > MAX_FILE_SIZE_MB:
                return ScanResult(
                    file_path, Language.UNKNOWN, [], 0,
                    time.perf_counter() - start,
                    f"File too large ({size_mb:.1f} MB > {MAX_FILE_SIZE_MB} MB limit)"
                )

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, PermissionError) as e:
                return ScanResult(file_path, Language.UNKNOWN, [], 0, time.perf_counter() - start, str(e))

            language = detect_language(file_path, content)

            if self.languages and language not in self.languages:
                result = ScanResult(file_path, language, [], 0, time.perf_counter() - start)
                if self.on_file_done:
                    self.on_file_done(result)
                return result

            vulnerabilities  = self._scan_content(file_path, content, language)
            vulnerabilities += analyze_complexity(file_path, content, language)
            vulnerabilities  = [v for v in vulnerabilities if v.severity.value >= self.min_severity.value]

            result = ScanResult(
                file_path=file_path,
                language=language,
                vulnerabilities=sorted(vulnerabilities, key=lambda v: -v.severity.value),
                lines_scanned=len(content.splitlines()),
                scan_time=time.perf_counter() - start,
            )
        except Exception as e:
            result = ScanResult(
                file_path, Language.UNKNOWN, [], 0,
                time.perf_counter() - start, f"Scan error: {e}"
            )

        if self.on_file_done:
            self.on_file_done(result)
        return result

    # ── Conteúdo ──────────────────────────────────────────────────────────────

    def _scan_content(
        self, file_path: str, content: str, language: Language
    ) -> List[Vulnerability]:
        all_rules      = get_rules(language) + self._custom_rules
        lines          = content.splitlines()
        total          = len(lines)
        vulns:   List[Vulnerability] = []
        seen:    set[tuple]          = set()
        fired:   Set[str]            = set()
        tainted: Set[str]            = set()

        single_pfx, blk_start, blk_end = get_comment_prefix(language)
        in_block = False

        # Linhas restritas (modo diff)
        restricted = (
            self.only_lines.get(file_path)
            or self.only_lines.get(Path(file_path).name)
        )

        # ── Passo 1: regras multiline ─────────────────────────────────────────
        for rule in all_rules:
            if not rule.multiline:
                continue
            if rule.depends_on and rule.depends_on not in fired:
                continue
            if _is_globally_suppressed(rule.id, file_path, self._global_suppress):
                continue
            for m in rule.match_content(content):
                li = content[: m.start()].count("\n")
                dk = (rule.id, file_path, li + 1)
                if dk in seen:
                    continue
                seen.add(dk)
                fired.add(rule.id)
                sc = max(0, li - CONTEXT_LINES)
                ec = min(total, li + CONTEXT_LINES + 1)
                vulns.append(Vulnerability(
                    rule_id=rule.id, name=rule.name, description=rule.description,
                    severity=rule.severity, category=rule.category, language=language,
                    file_path=file_path, line_number=li + 1,
                    line_content=lines[li].rstrip() if li < total else "",
                    remediation=rule.remediation, cwe=rule.cwe, owasp=rule.owasp,
                    confidence=rule.confidence,
                    snippet=lines[sc:ec], snippet_start_line=sc + 1,
                    in_comment=False,
                    function_context=_get_function_context(lines, li),
                ))

        # ── Passo 2: regras linha a linha ─────────────────────────────────────
        for li, line in enumerate(lines):
            if len(line) > MAX_LINE_LENGTH:
                continue
            if restricted and (li + 1) not in restricted:
                continue

            stripped = line.strip()

            if blk_start and blk_end:
                if blk_start in stripped:
                    in_block = True
                if blk_end in stripped:
                    in_block = False
                    continue

            is_comment = in_block or bool(single_pfx and stripped.startswith(single_pfx))

            # Taint: detectar variáveis contaminadas
            src = _TAINT_SOURCE_RE.search(line)
            if src:
                tainted.add(src.group(1))

            for rule in all_rules:
                if rule.multiline:
                    continue
                if rule.depends_on and rule.depends_on not in fired:
                    continue
                if not rule.match(line):
                    continue
                if _is_globally_suppressed(rule.id, file_path, self._global_suppress):
                    continue
                if _is_inline_suppressed(line, rule.id):
                    continue

                dk = (rule.id, file_path, li + 1)
                if dk in seen:
                    continue
                seen.add(dk)
                fired.add(rule.id)

                conf = rule.confidence
                if is_comment:
                    if not self.include_comments:
                        continue
                    conf = Confidence.MEDIUM if conf == Confidence.HIGH else Confidence.LOW

                # Taint: elevar confiança se var tainted num sink
                snk = _TAINT_SINK_RE.search(line)
                if snk and snk.group(1) in tainted:
                    conf = Confidence.HIGH

                sc = max(0, li - CONTEXT_LINES)
                ec = min(total, li + CONTEXT_LINES + 1)
                vulns.append(Vulnerability(
                    rule_id=rule.id, name=rule.name, description=rule.description,
                    severity=rule.severity, category=rule.category, language=language,
                    file_path=file_path, line_number=li + 1,
                    line_content=line.rstrip(),
                    remediation=rule.remediation, cwe=rule.cwe, owasp=rule.owasp,
                    confidence=conf,
                    snippet=lines[sc:ec], snippet_start_line=sc + 1,
                    in_comment=is_comment,
                    function_context=_get_function_context(lines, li),
                ))

        return vulns

    # ── Diretório ─────────────────────────────────────────────────────────────

    def scan_directory(self, directory: str) -> ScanReport:
        start = time.perf_counter()
        dir_path = Path(directory)

        dir_suppress = _load_ignore_file(directory)
        self._global_suppress.update(dir_suppress)

        files = self._collect_files(dir_path)
        results: List[ScanResult] = []
        for fp in files:
            results.append(self.scan_file(str(fp)))

        return self._build_report(results, directory, time.perf_counter() - start)

    def scan_files(self, files: List[str]) -> ScanReport:
        start = time.perf_counter()
        results = [self.scan_file(fp) for fp in files]
        return self._build_report(results, f"{len(files)} files", time.perf_counter() - start)

    def _collect_files(self, directory: Path) -> List[Path]:
        collected: List[Path] = []
        try:
            for item in directory.rglob("*"):
                if not item.is_file() or not is_scannable(str(item)):
                    continue
                skip = False
                try:
                    for part in item.relative_to(directory).parts[:-1]:
                        if part in SKIP_DIRS:
                            skip = True
                            break
                except ValueError:
                    pass
                if not skip:
                    collected.append(item)
        except PermissionError:
            pass
        return sorted(collected)

    @staticmethod
    def _build_report(
        results: List[ScanResult], target: str, total_time: float
    ) -> ScanReport:
        all_vulns = [v for r in results for v in r.vulnerabilities]
        counts    = {s: 0 for s in Severity}
        for v in all_vulns:
            counts[v.severity] += 1
        langs = sorted({r.language.value for r in results if r.language != Language.UNKNOWN})
        return ScanReport(
            results=results,
            total_time=total_time,
            files_scanned=len(results),
            files_with_issues=sum(1 for r in results if r.vulnerabilities),
            total_vulnerabilities=len(all_vulns),
            critical_count=counts[Severity.CRITICAL],
            high_count=counts[Severity.HIGH],
            medium_count=counts[Severity.MEDIUM],
            low_count=counts[Severity.LOW],
            info_count=counts[Severity.INFO],
            target=target,
            languages_found=langs,
        )


# ── Watch mode ────────────────────────────────────────────────────────────────

def watch_mode(target: str, engine_kwargs: dict, interval: float = 2.0) -> None:
    """Monitora alterações em arquivos e re-escaneia automaticamente."""
    from analyzer.reporter import print_report, console

    target_path = Path(target)
    mtimes: Dict[str, float] = {}

    def _snap() -> Dict[str, float]:
        r: Dict[str, float] = {}
        if target_path.is_file():
            try:
                r[str(target_path)] = os.stat(target_path).st_mtime
            except OSError:
                pass
        else:
            eng = ScanEngine(**engine_kwargs)
            for fp in eng._collect_files(target_path):
                try:
                    r[str(fp)] = os.stat(fp).st_mtime
                except OSError:
                    pass
        return r

    console.print(f"[bold bright_cyan]👁  Watch mode ativo → {target}[/]")
    console.print("[dim]Ctrl+C para sair[/dim]\n")

    mtimes = _snap()
    eng    = ScanEngine(**engine_kwargs)
    report = eng.scan_directory(target) if target_path.is_dir() else eng.scan_files([target])
    print_report(report)

    while True:
        time.sleep(interval)
        new_mtimes = _snap()
        changed = {f for f, t in new_mtimes.items() if mtimes.get(f) != t}
        changed |= {f for f in mtimes if f not in new_mtimes}

        if changed:
            mtimes = new_mtimes
            console.rule("[bold bright_yellow] Alteração detectada — rescaneando... [/]")
            eng2   = ScanEngine(**engine_kwargs)
            report = eng2.scan_directory(target) if target_path.is_dir() else eng2.scan_files([target])
            print_report(report)
