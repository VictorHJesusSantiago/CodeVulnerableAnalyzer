from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable
from pathlib import Path

from analyzer.complexity import analyze_complexity
from analyzer.detector import SKIP_DIRS, detect_language, get_comment_prefix, is_scannable
from analyzer.models import Confidence, Language, ScanReport, ScanResult, Severity, VulnCategory, Vulnerability
from analyzer.rules import get_rules

# Taint: primitivas compartilhadas (SSOT — ver analyzer.taint)
from analyzer.taint import TAINT_SINK_RE, TAINT_SINKS, TaintTracker

CONTEXT_LINES    = 3
MAX_FILE_SIZE_MB = 5
MAX_LINE_LENGTH  = 2000

def _localize_rule(rule_id: str, name: str, description: str, remediation: str) -> tuple:
    """Aplica overrides de i18n de conteúdo de regra (ver analyzer.i18n), se houver."""
    try:
        from analyzer.i18n import translate_rule_fields
        return translate_rule_fields(rule_id, name, description, remediation)
    except Exception:
        return name, description, remediation


# ── Taint analysis ────────────────────────────────────────────────────────────

def _analyze_taint(
    file_path: str,
    lines: list[str],
    language: Language,
    restricted: set[int] | None,
) -> list[Vulnerability]:
    """
    Taint analysis intra-arquivo: rastreia variáveis derivadas de entrada do
    usuário (com propagação por atribuição) e emite um achado quando uma
    variável contaminada alcança um sink perigoso.
    """
    tracker = TaintTracker()
    findings: list[Vulnerability] = []
    total = len(lines)

    for li, line in enumerate(lines):
        if len(line) > MAX_LINE_LENGTH:
            continue

        # ── Fontes + propagação por atribuição (estado compartilhado) ──────
        tracker.observe(line)

        # ── Sinks ─────────────────────────────────────────────────────────
        for sink_re, category, severity, label in TAINT_SINKS:
            sm = sink_re.search(line)
            if not sm:
                continue
            args = line[sm.end() - 1:]  # do '(' em diante
            used = next((t for t in tracker.tainted
                         if re.search(r'\b' + re.escape(t) + r'\b', args)), None)
            if not used:
                continue
            if restricted and (li + 1) not in restricted:
                continue
            sc = max(0, li - CONTEXT_LINES)
            ec = min(total, li + CONTEXT_LINES + 1)
            findings.append(Vulnerability(
                rule_id="TAINT-001",
                name=f"Fluxo de dados não-confiáveis até sink perigoso ({label})",
                description=(
                    f"A variável '{used}' deriva de entrada controlada pelo usuário "
                    f"e é usada em {label} sem sanitização aparente. Isso permite "
                    f"injeção ({category.value})."
                ),
                severity=severity,
                category=category,
                language=language,
                file_path=file_path,
                line_number=li + 1,
                line_content=line.rstrip(),
                remediation=(
                    "Valide e sanitize a entrada antes do sink; use APIs parametrizadas "
                    "(ex.: parâmetros de query em vez de concatenação) ou allowlists."
                ),
                cwe="CWE-20",
                owasp="A03:2021 - Injection",
                confidence=Confidence.HIGH,
                snippet=lines[sc:ec],
                snippet_start_line=sc + 1,
                in_comment=False,
                function_context=_get_function_context(lines, li),
            ))
            break

    return findings

# ── Contexto de função ────────────────────────────────────────────────────────

_FUNC_DEF_RE  = re.compile(
    r'^\s*(?:def|async def|function|func|fn|method|sub|void|'
    r'public|private|protected|static|fun)\s+(\w+)'
)
_CLASS_DEF_RE = re.compile(r'^\s*(?:class|struct|interface|impl|trait)\s+(\w+)')


def _get_function_context(lines: list[str], line_idx: int) -> str | None:
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


def _load_ignore_file(directory: str) -> set[str]:
    """Carrega entradas do .vulnscan-ignore (RULE_ID ou ARQUIVO:RULE_ID por linha)."""
    path = Path(directory) / ".vulnscan-ignore"
    suppressed: set[str] = set()
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


def _is_globally_suppressed(rule_id: str, file_path: str, suppressed: set[str]) -> bool:
    return (rule_id in suppressed
            or f"{Path(file_path).name}:{rule_id}" in suppressed)


# ── Regras customizadas ───────────────────────────────────────────────────────

def _coerce_scalar(raw: str):
    """Converte um escalar YAML/texto em bool/int/None/str."""
    s = raw.strip()
    if (len(s) >= 2) and s[0] in "\"'" and s[-1] == s[0]:
        return s[1:-1]
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", "none", ""):
        return None
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return s


def _parse_simple_yaml_rules(text: str) -> list[dict]:
    """
    Parser YAML mínimo para arquivos de regras (sem dependências externas).
    Suporta lista de mapeamentos no formato:
        - id: X
          name: Y
          pattern: "..."
    ou sob a chave de topo `rules:`. Valores são escalares de uma linha.
    """
    items: list[dict] = []
    current: dict | None = None
    for raw_line in text.splitlines():
        line = raw_line.split(" #", 1)[0].rstrip() if " #" in raw_line else raw_line.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        stripped = line.strip()
        if stripped in ("rules:", "---"):
            continue
        if stripped.startswith("- "):
            # Início de um novo item (a parte após "- " é o primeiro par chave:valor)
            current = {}
            items.append(current)
            stripped = stripped[2:].strip()
        if current is None:
            current = {}
            items.append(current)
        if ":" in stripped:
            key, _, val = stripped.partition(":")
            current[key.strip()] = _coerce_scalar(val)
    return [it for it in items if it]


def _rule_from_entry(entry: dict):
    """Constrói um objeto Rule a partir de um dict (JSON ou YAML)."""
    from analyzer.rules.base import Rule

    _sev_map  = {s.name: s   for s in Severity}
    _conf_map = {c.name: c   for c in Confidence}
    _cat_map  = {c.value: c  for c in VulnCategory}
    _lang_map = {lang.value: lang for lang in Language}

    lang_val = str(entry.get("language", "generic")).title()
    return Rule(
        id=entry["id"],
        name=entry.get("name", entry["id"]),
        description=entry.get("description", ""),
        severity=_sev_map.get(str(entry.get("severity", "MEDIUM")).upper(), Severity.MEDIUM),
        category=_cat_map.get(entry.get("category", "Other"), VulnCategory.OTHER),
        language=_lang_map.get(lang_val, Language.GENERIC),
        pattern=entry["pattern"],
        remediation=entry.get("remediation", ""),
        cwe=entry.get("cwe"),
        owasp=entry.get("owasp"),
        confidence=_conf_map.get(str(entry.get("confidence", "MEDIUM")).upper(), Confidence.MEDIUM),
        flags=re.IGNORECASE if entry.get("ignorecase") else 0,
        negative_pattern=entry.get("negative_pattern"),
        multiline=bool(entry.get("multiline", False)),
        depends_on=entry.get("depends_on"),
    )


def _load_py_plugin_rules(plugin_dirs: list[Path]) -> list:
    """
    Carrega regras de módulos Python (*.py) nos diretórios de plugin.
    Cada módulo deve expor uma variável de nível de módulo `RULES: list[Rule]`.

    SÓ é chamada quando o usuário passa explicitamente --allow-py-plugins,
    pois isso executa código Python arbitrário de terceiros — uma decisão
    de segurança deliberada que exige opt-in explícito (diferente do
    carregamento de JSON/YAML, que é passivo e seguro por padrão).
    """
    import importlib.util
    import uuid

    from analyzer.rules.base import Rule

    custom: list = []
    for d in plugin_dirs:
        if not d.is_dir():
            continue
        for py_file in sorted(d.glob("*.py")):
            try:
                mod_name = f"vulnscan_plugin_{uuid.uuid4().hex}"
                spec = importlib.util.spec_from_file_location(mod_name, py_file)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                rules = getattr(module, "RULES", None)
                if isinstance(rules, list):
                    custom.extend(r for r in rules if isinstance(r, Rule))
            except Exception:
                # Um plugin quebrado não pode derrubar o scan inteiro.
                pass
    return custom


def _load_custom_rules(extra_dirs: list[str] | None = None, allow_py_plugins: bool = False) -> list:
    """
    Carrega regras de ./vulnscan-rules.{json,yaml,yml},
    ~/.vulnscan/rules/*.{json,yaml,yml}, do diretório apontado pela
    variável de ambiente VULNSCAN_RULES_DIR e de quaisquer diretórios
    passados em `extra_dirs` (equivalente a --rules-dir na CLI).
    JSON e YAML são suportados — permite plugar regras próprias sem
    tocar no código-fonte do analisador. Com `allow_py_plugins=True`
    (--allow-py-plugins na CLI), também carrega módulos .py que expõem
    `RULES: list[Rule]` — opt-in explícito por rodar código arbitrário.
    """
    json_sources: list[Path] = []
    yaml_sources: list[Path] = []

    for stem in ("vulnscan-rules.json",):
        p = Path(stem)
        if p.exists():
            json_sources.append(p)
    for stem in ("vulnscan-rules.yaml", "vulnscan-rules.yml"):
        p = Path(stem)
        if p.exists():
            yaml_sources.append(p)

    home_dir = Path.home() / ".vulnscan" / "rules"
    if home_dir.is_dir():
        json_sources.extend(sorted(home_dir.glob("*.json")))
        yaml_sources.extend(sorted(home_dir.glob("*.yaml")))
        yaml_sources.extend(sorted(home_dir.glob("*.yml")))

    plugin_dirs: list[Path] = []
    env_dir = os.environ.get("VULNSCAN_RULES_DIR")
    if env_dir:
        plugin_dirs.extend(Path(p) for p in env_dir.split(os.pathsep) if p)
    if extra_dirs:
        plugin_dirs.extend(Path(p) for p in extra_dirs if p)

    for d in plugin_dirs:
        if d.is_dir():
            json_sources.extend(sorted(d.glob("*.json")))
            yaml_sources.extend(sorted(d.glob("*.yaml")))
            yaml_sources.extend(sorted(d.glob("*.yml")))

    entries: list[dict] = []
    for src in json_sources:
        try:
            data = json.loads(src.read_text(encoding="utf-8"))
            entries.extend(data if isinstance(data, list) else data.get("rules", []))
        except (json.JSONDecodeError, OSError):
            pass
    for src in yaml_sources:
        try:
            entries.extend(_parse_simple_yaml_rules(src.read_text(encoding="utf-8")))
        except OSError:
            pass

    custom: list = []
    for entry in entries:
        try:
            custom.append(_rule_from_entry(entry))
        except (KeyError, ValueError):
            pass

    if allow_py_plugins:
        custom.extend(_load_py_plugin_rules(plugin_dirs))

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


_SEV_NAME_MAP = {s.name: s for s in Severity}


def _severity_overrides_from_config(config: dict) -> dict[str, Severity]:
    """
    Lê `severity_overrides` de vulnscan.toml/json:

        [severity_overrides]
        PY-EVAL-001 = "LOW"
    ou
        {"severity_overrides": {"PY-EVAL-001": "LOW"}}

    Chaves desconhecidas ou valores inválidos são ignorados silenciosamente.
    """
    raw = config.get("severity_overrides", {})
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Severity] = {}
    for rule_id, sev_name in raw.items():
        sev = _SEV_NAME_MAP.get(str(sev_name).upper())
        if sev is not None:
            out[str(rule_id)] = sev
    return out


def _config_suppressed_ids(config: dict) -> set[str]:
    """Lê `suppress` (lista de rule_id) de vulnscan.toml/json."""
    raw = config.get("suppress", [])
    if not isinstance(raw, list):
        return set()
    return {str(x) for x in raw}


# ── Engine principal ──────────────────────────────────────────────────────────

class ScanEngine:
    def __init__(
        self,
        min_severity:   Severity                          = Severity.INFO,
        languages:      list[Language] | None          = None,
        include_comments: bool                            = True,
        on_file_start:  Callable[[str], None] | None   = None,
        on_file_done:   Callable[[ScanResult], None] | None = None,
        only_lines:     dict[str, set[int]] | None     = None,
        custom_rules:   list | None                    = None,
        global_suppress: set[str] | None               = None,
        ast_analysis:   bool                              = False,
        cpp_macros:     bool                              = False,
        incremental_cache = None,
        rules_dirs:     list[str] | None                = None,
        allow_py_plugins: bool                             = False,
    ):
        self.min_severity      = min_severity
        self.languages         = languages
        self.include_comments  = include_comments
        self.on_file_start     = on_file_start
        self.on_file_done      = on_file_done
        self.only_lines        = only_lines or {}
        self._custom_rules     = custom_rules if custom_rules is not None else _load_custom_rules(rules_dirs, allow_py_plugins)
        self._global_suppress  = global_suppress if global_suppress is not None else set()
        self._config           = _load_config()
        self._severity_overrides = _severity_overrides_from_config(self._config)
        self._global_suppress |= _config_suppressed_ids(self._config)
        self.ast_analysis      = ast_analysis
        self.cpp_macros        = cpp_macros
        self.incremental_cache = incremental_cache

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

            # ── Cache incremental: reaproveita resultado se o conteúdo não mudou ──
            if self.incremental_cache is not None:
                cached = self.incremental_cache.get(file_path, content)
                if cached is not None:
                    cached_vulns, cached_lines = cached
                    result = ScanResult(
                        file_path=file_path, language=language,
                        vulnerabilities=cached_vulns, lines_scanned=cached_lines,
                        scan_time=time.perf_counter() - start,
                    )
                    if self.on_file_done:
                        self.on_file_done(result)
                    return result

            # ── Pré-processamento de macros C/C++ (opt-in) ────────────────────────
            scan_content = content
            if self.cpp_macros and language in (Language.C, Language.CPP):
                from analyzer.cpreprocess import expand_macros
                scan_content = expand_macros(content)

            vulnerabilities  = self._scan_content(file_path, scan_content, language)
            vulnerabilities += analyze_complexity(file_path, scan_content, language)

            # ── Análise AST real para Python (opt-in) ─────────────────────────────
            if self.ast_analysis and language == Language.PYTHON:
                from analyzer.pyast_engine import analyze_python_ast
                vulnerabilities += analyze_python_ast(file_path, content)

            vulnerabilities  = [v for v in vulnerabilities if v.severity.value >= self.min_severity.value]
            lines_scanned = len(content.splitlines())

            if self.incremental_cache is not None:
                self.incremental_cache.put(
                    file_path, content, vulnerabilities, lines_scanned,
                    time.perf_counter() - start,
                )

            result = ScanResult(
                file_path=file_path,
                language=language,
                vulnerabilities=sorted(vulnerabilities, key=lambda v: -v.severity.value),
                lines_scanned=lines_scanned,
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
    ) -> list[Vulnerability]:
        all_rules      = get_rules(language) + self._custom_rules
        lines          = content.splitlines()
        total          = len(lines)
        vulns:   list[Vulnerability] = []
        seen:    set[tuple]          = set()
        fired:   set[str]            = set()
        tracker: TaintTracker        = TaintTracker()

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
                r_name, r_desc, r_rem = _localize_rule(rule.id, rule.name, rule.description, rule.remediation)
                vulns.append(Vulnerability(
                    rule_id=rule.id, name=r_name, description=r_desc,
                    severity=self._severity_overrides.get(rule.id, rule.severity), category=rule.category, language=language,
                    file_path=file_path, line_number=li + 1,
                    line_content=lines[li].rstrip() if li < total else "",
                    remediation=r_rem, cwe=rule.cwe, owasp=rule.owasp,
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

            # Taint: rastreia fontes + propagação (Python + PHP/JS) via o mesmo
            # TaintTracker do analisador dedicado — SSOT, nunca mais diverge.
            tracker.observe(line)

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
                snk = TAINT_SINK_RE.search(line)
                if snk and snk.group(1) in tracker.tainted:
                    conf = Confidence.HIGH

                sc = max(0, li - CONTEXT_LINES)
                ec = min(total, li + CONTEXT_LINES + 1)
                r_name, r_desc, r_rem = _localize_rule(rule.id, rule.name, rule.description, rule.remediation)
                vulns.append(Vulnerability(
                    rule_id=rule.id, name=r_name, description=r_desc,
                    severity=self._severity_overrides.get(rule.id, rule.severity), category=rule.category, language=language,
                    file_path=file_path, line_number=li + 1,
                    line_content=line.rstrip(),
                    remediation=r_rem, cwe=rule.cwe, owasp=rule.owasp,
                    confidence=conf,
                    snippet=lines[sc:ec], snippet_start_line=sc + 1,
                    in_comment=is_comment,
                    function_context=_get_function_context(lines, li),
                ))

        # ── Passo 3: taint analysis dedicado (com propagação) ─────────────────
        for tf in _analyze_taint(file_path, lines, language, restricted):
            if _is_globally_suppressed(tf.rule_id, file_path, self._global_suppress):
                continue
            dk = (tf.rule_id, file_path, tf.line_number)
            if dk in seen:
                continue
            seen.add(dk)
            if tf.rule_id in self._severity_overrides:
                tf.severity = self._severity_overrides[tf.rule_id]
            vulns.append(tf)

        return vulns

    # ── Diretório ─────────────────────────────────────────────────────────────

    def scan_directory(self, directory: str) -> ScanReport:
        start = time.perf_counter()
        dir_path = Path(directory)

        dir_suppress = _load_ignore_file(directory)
        self._global_suppress.update(dir_suppress)

        files = self._collect_files(dir_path)
        results: list[ScanResult] = []
        for fp in files:
            results.append(self.scan_file(str(fp)))

        return self._build_report(results, directory, time.perf_counter() - start)

    def scan_files(self, files: list[str]) -> ScanReport:
        start = time.perf_counter()
        results = [self.scan_file(fp) for fp in files]
        return self._build_report(results, f"{len(files)} files", time.perf_counter() - start)

    def _collect_files(self, directory: Path) -> list[Path]:
        collected: list[Path] = []
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
        results: list[ScanResult], target: str, total_time: float
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
    from analyzer.reporter import console, print_report

    target_path = Path(target)
    mtimes: dict[str, float] = {}

    def _snap() -> dict[str, float]:
        r: dict[str, float] = {}
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
