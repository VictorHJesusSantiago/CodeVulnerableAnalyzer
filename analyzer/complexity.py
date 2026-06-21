"""
Analisador de complexidade estática — métricas de função/método.
Detecta: funções longas, complexidade ciclomática alta, aninhamento profundo,
muitos parâmetros, arquivos muito grandes, ausência de docstring (Python).
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple
from analyzer.models import (
    Language, Severity, Vulnerability, VulnCategory, Confidence
)

# ── Thresholds configuráveis ───────────────────────────────────────────────
MAX_FUNCTION_LINES     = 50    # Linhas de código por função
MAX_CYCLOMATIC         = 10    # Pontos de decisão (McCabe Complexity)
MAX_NESTING_DEPTH      = 4     # Nível de aninhamento por bloco
MAX_PARAMETERS         = 5     # Parâmetros por função/método
MAX_FILE_LINES         = 500   # Linhas por arquivo (exceto testes/fixtures)
MAX_CLASS_METHODS      = 15    # Métodos por classe

# ── Padrões por linguagem ──────────────────────────────────────────────────

FUNCTION_START: dict[Language, re.Pattern] = {
    Language.PYTHON:     re.compile(r'^(\s*)(?:async\s+)?def\s+([_a-zA-Z]\w*)\s*\(([^)]*)\)\s*(?:->.*?)?\s*:'),
    Language.JAVASCRIPT: re.compile(r'^(\s*)(?:async\s+)?function\s+([_a-zA-Z]\w*)\s*\(([^)]*)\)'),
    Language.TYPESCRIPT: re.compile(r'^(\s*)(?:async\s+)?function\s+([_a-zA-Z]\w*)\s*\(([^)]*)\)'),
    Language.JAVA:       re.compile(r'^(\s*)(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)*(?:[\w<>\[\]]+\s+)+([_a-zA-Z]\w*)\s*\(([^)]*)\)'),
    Language.CSHARP:     re.compile(r'^(\s*)(?:(?:public|private|protected|internal|static|virtual|override|abstract|async)\s+)*(?:[\w<>\[\]?]+\s+)+([_a-zA-Z]\w*)\s*\(([^)]*)\)'),
    Language.GO:         re.compile(r'^(\s*)func\s+(?:\([^)]+\)\s+)?([_a-zA-Z]\w*)\s*\(([^)]*)\)'),
    Language.RUBY:       re.compile(r'^(\s*)def\s+([_a-zA-Z]\w*)\s*(?:\(([^)]*)\))?'),
    Language.PHP:        re.compile(r'^(\s*)(?:(?:public|private|protected|static|abstract)\s+)*function\s+([_a-zA-Z]\w*)\s*\(([^)]*)\)'),
    Language.KOTLIN:     re.compile(r'^(\s*)(?:(?:public|private|protected|internal|override|suspend|inline)\s+)*fun\s+([_a-zA-Z]\w*)\s*\(([^)]*)\)'),
    Language.RUST:       re.compile(r'^(\s*)(?:pub\s+)?(?:async\s+)?fn\s+([_a-zA-Z]\w*)\s*\(([^)]*)\)'),
    Language.SWIFT:      re.compile(r'^(\s*)(?:(?:public|private|internal|open|fileprivate|override|static|mutating)\s+)*func\s+([_a-zA-Z]\w*)\s*\(([^)]*)\)'),
    Language.CPP:        re.compile(r'^(\s*)(?:(?:virtual|inline|static|explicit)\s+)*(?:[\w:*&<>]+\s+)+([_a-zA-Z]\w*)\s*\(([^)]*)\)\s*(?:const\s*)?(?:override\s*)?\{'),
    Language.C:          re.compile(r'^(?!#)(\s*)(?:(?:static|inline|extern)\s+)*(?:\w+[\s*]+)+([_a-zA-Z]\w*)\s*\(([^)]*)\)\s*\{'),
}

CLASS_START: dict[Language, re.Pattern] = {
    Language.PYTHON:     re.compile(r'^\s*class\s+([_a-zA-Z]\w*)\s*(?:\([^)]*\))?\s*:'),
    Language.JAVA:       re.compile(r'^\s*(?:(?:public|private|protected|abstract|final)\s+)*class\s+([_a-zA-Z]\w*)'),
    Language.CSHARP:     re.compile(r'^\s*(?:(?:public|private|internal|abstract|sealed)\s+)*class\s+([_a-zA-Z]\w*)'),
    Language.JAVASCRIPT: re.compile(r'^\s*class\s+([_a-zA-Z]\w*)'),
    Language.TYPESCRIPT: re.compile(r'^\s*(?:(?:export|abstract)\s+)*class\s+([_a-zA-Z]\w*)'),
    Language.GO:         re.compile(r'^\s*type\s+([_a-zA-Z]\w*)\s+struct\s*\{'),
    Language.KOTLIN:     re.compile(r'^\s*(?:(?:open|abstract|data|sealed)\s+)?class\s+([_a-zA-Z]\w*)'),
}

# Palavras-chave que aumentam a complexidade ciclomática
DECISION_PATTERNS: dict[Language, list[str]] = {
    Language.PYTHON:     [r'\bif\b', r'\belif\b', r'\bfor\b', r'\bwhile\b', r'\bexcept\b', r'\band\b', r'\bor\b'],
    Language.JAVASCRIPT: [r'\bif\b', r'\belse\s+if\b', r'\bfor\b', r'\bwhile\b', r'\bcase\b', r'&&', r'\|\|', r'\?\?', r'\?\.'],
    Language.TYPESCRIPT: [r'\bif\b', r'\belse\s+if\b', r'\bfor\b', r'\bwhile\b', r'\bcase\b', r'&&', r'\|\|', r'\?\?'],
    Language.JAVA:       [r'\bif\b', r'\belse\s+if\b', r'\bfor\b', r'\bwhile\b', r'\bcase\b', r'&&', r'\|\|', r'\?(?!\?)'],
    Language.CSHARP:     [r'\bif\b', r'\belse\s+if\b', r'\bfor\b', r'\bforeach\b', r'\bwhile\b', r'\bcase\b', r'&&', r'\|\|', r'\?\?'],
    Language.GO:         [r'\bif\b', r'\bfor\b', r'\bcase\b', r'&&', r'\|\|'],
    Language.RUBY:       [r'\bif\b', r'\bunless\b', r'\belsif\b', r'\bfor\b', r'\bwhile\b', r'\buntil\b', r'\brescue\b', r'&&', r'\|\|'],
    Language.PHP:        [r'\bif\b', r'\belseif\b', r'\bfor\b', r'\bforeach\b', r'\bwhile\b', r'\bcase\b', r'&&', r'\|\|', r'\?(?!\?)'],
    Language.KOTLIN:     [r'\bif\b', r'\bwhen\b', r'\bfor\b', r'\bwhile\b', r'&&', r'\|\|', r'\?\:'],
    Language.RUST:       [r'\bif\b', r'\belse\s+if\b', r'\bfor\b', r'\bwhile\b', r'\bmatch\b', r'&&', r'\|\|'],
    Language.CPP:        [r'\bif\b', r'\belse\s+if\b', r'\bfor\b', r'\bwhile\b', r'\bcase\b', r'&&', r'\|\|', r'\?(?!\?)'],
    Language.C:          [r'\bif\b', r'\belse\s+if\b', r'\bfor\b', r'\bwhile\b', r'\bcase\b', r'&&', r'\|\|', r'\?(?!\?)'],
}


@dataclass
class FunctionInfo:
    name: str
    start_line: int
    indent: int
    params_raw: str
    language: Language
    lines: list[str]

    def param_count(self) -> int:
        raw = self.params_raw.strip()
        if not raw or raw in ('self', 'this'):
            return 0
        params = [p.strip() for p in raw.split(',') if p.strip()]
        # Remove 'self' and 'cls' from Python
        params = [p for p in params if p not in ('self', 'cls', 'this')]
        # Remove type annotations and defaults for counting
        return len(params)

    def line_count(self) -> int:
        return len([l for l in self.lines if l.strip()])

    def cyclomatic_complexity(self) -> int:
        lang_patterns = DECISION_PATTERNS.get(self.language, DECISION_PATTERNS.get(Language.PYTHON, []))
        complexity = 1
        for line in self.lines:
            for pattern in lang_patterns:
                if re.search(pattern, line):
                    complexity += 1
        return complexity

    def max_nesting(self) -> int:
        if self.language in (Language.PYTHON, Language.RUBY):
            return self._max_nesting_indent()
        return self._max_nesting_braces()

    def _max_nesting_indent(self) -> int:
        base_indent = self.indent
        max_nest = 0
        for line in self.lines:
            if not line.strip():
                continue
            curr_indent = len(line) - len(line.lstrip())
            relative = (curr_indent - base_indent) // 4
            max_nest = max(max_nest, relative)
        return max_nest

    def _max_nesting_braces(self) -> int:
        depth = 0
        max_depth = 0
        for line in self.lines:
            depth += line.count('{') - line.count('}')
            max_depth = max(max_depth, depth)
        return max_depth


class ComplexityAnalyzer:
    def __init__(self, file_path: str, content: str, language: Language):
        self.file_path = file_path
        self.content = content
        self.language = language
        self.lines = content.splitlines()

    def analyze(self) -> List[Vulnerability]:
        results: List[Vulnerability] = []
        results.extend(self._check_file_length())
        functions = self._extract_functions()
        for func in functions:
            results.extend(self._check_function(func))
        results.extend(self._check_nesting_per_line())
        return results

    # ── Comprimento do arquivo ─────────────────────────────────────────────────
    def _check_file_length(self) -> List[Vulnerability]:
        if self.language == Language.UNKNOWN:
            return []
        non_empty = sum(1 for l in self.lines if l.strip())
        if non_empty <= MAX_FILE_LINES:
            return []
        return [Vulnerability(
            rule_id="CMPLX-001",
            name="Arquivo Muito Longo (God File)",
            description=f"Arquivo com {non_empty} linhas de código (threshold: {MAX_FILE_LINES}). Viola o SRP — um arquivo com muitas linhas provavelmente agrupa múltiplas responsabilidades. Dificulta navegação, review e testes.",
            severity=Severity.MEDIUM,
            category=VulnCategory.SOLID_SRP,
            language=self.language,
            file_path=self.file_path,
            line_number=1,
            line_content=self.lines[0] if self.lines else "",
            remediation=f"Divida o arquivo em módulos menores com responsabilidades únicas. Idealmente menos de {MAX_FILE_LINES} linhas. Extraia classes ou funções em novos arquivos.",
            cwe="CWE-1093",
            confidence=Confidence.HIGH,
        )]

    # ── Extração de funções ────────────────────────────────────────────────────
    def _extract_functions(self) -> List[FunctionInfo]:
        pattern = FUNCTION_START.get(self.language)
        if not pattern:
            return []

        functions: List[FunctionInfo] = []
        starts: List[Tuple[int, re.Match]] = []

        for i, line in enumerate(self.lines):
            m = pattern.match(line)
            if m:
                starts.append((i, m))

        for idx, (line_num, match) in enumerate(starts):
            indent_str = match.group(1)
            indent = len(indent_str)
            name = match.group(2)
            params = match.group(3) if len(match.groups()) >= 3 else ""

            # Determina fim da função
            if self.language in (Language.PYTHON, Language.RUBY):
                end_line = self._find_end_python(line_num, indent)
            else:
                end_line = self._find_end_brace(line_num)

            func_lines = self.lines[line_num:end_line]
            functions.append(FunctionInfo(
                name=name,
                start_line=line_num + 1,
                indent=indent,
                params_raw=params or "",
                language=self.language,
                lines=func_lines,
            ))

        return functions

    def _find_end_python(self, start: int, base_indent: int) -> int:
        for i in range(start + 1, len(self.lines)):
            line = self.lines[i]
            if not line.strip():
                continue
            curr_indent = len(line) - len(line.lstrip())
            if curr_indent <= base_indent and not line.strip().startswith('#'):
                return i
        return len(self.lines)

    def _find_end_brace(self, start: int) -> int:
        depth = 0
        in_func = False
        for i in range(start, len(self.lines)):
            line = self.lines[i]
            opens = line.count('{')
            closes = line.count('}')
            if opens > 0:
                in_func = True
            depth += opens - closes
            if in_func and depth <= 0:
                return i + 1
        return len(self.lines)

    # ── Verificações por função ───────────────────────────────────────────────
    def _check_function(self, func: FunctionInfo) -> List[Vulnerability]:
        results: List[Vulnerability] = []
        line_count = func.line_count()
        cyclo = func.cyclomatic_complexity()
        params = func.param_count()

        if line_count > MAX_FUNCTION_LINES:
            results.append(Vulnerability(
                rule_id="CMPLX-002",
                name="Função/Método Muito Longo",
                description=f"Função '{func.name}' tem {line_count} linhas (threshold: {MAX_FUNCTION_LINES}). Funções longas violam o SRP — uma função deve fazer uma única coisa. Dificultam leitura, teste unitário e manutenção.",
                severity=Severity.MEDIUM,
                category=VulnCategory.COMPLEXITY,
                language=self.language,
                file_path=self.file_path,
                line_number=func.start_line,
                line_content=self.lines[func.start_line - 1],
                remediation=f"Extraia partes do método em funções privadas com nomes descritivos. Meta: {MAX_FUNCTION_LINES} linhas ou menos. Aplique 'Extract Method' do catálogo de Fowler.",
                cwe="CWE-1121",
                confidence=Confidence.HIGH,
            ))

        if cyclo > MAX_CYCLOMATIC:
            severity = Severity.HIGH if cyclo > 15 else Severity.MEDIUM
            results.append(Vulnerability(
                rule_id="CMPLX-003",
                name="Alta Complexidade Ciclomática (McCabe)",
                description=f"Função '{func.name}' tem complexidade ciclomática {cyclo} (threshold: {MAX_CYCLOMATIC}). Cada ponto de decisão (if/for/while/case/&&) aumenta a complexidade. Funções com CC > 10 requerem 10+ testes para cobertura de branches.",
                severity=severity,
                category=VulnCategory.COMPLEXITY,
                language=self.language,
                file_path=self.file_path,
                line_number=func.start_line,
                line_content=self.lines[func.start_line - 1],
                remediation=f"Reduza complexidade extraindo funções auxiliares, usando early return, polimorfismo no lugar de switch/if-else chains. Meta: CC <= {MAX_CYCLOMATIC}.",
                cwe="CWE-1121",
                confidence=Confidence.HIGH,
            ))

        if params > MAX_PARAMETERS:
            results.append(Vulnerability(
                rule_id="CMPLX-004",
                name="Lista de Parâmetros Excessiva",
                description=f"Função '{func.name}' tem {params} parâmetros (threshold: {MAX_PARAMETERS}). Indica baixa coesão e possível violação do SRP. Dificulta memorização da API e criação de chamadas corretas.",
                severity=Severity.LOW,
                category=VulnCategory.CODE_QUALITY,
                language=self.language,
                file_path=self.file_path,
                line_number=func.start_line,
                line_content=self.lines[func.start_line - 1],
                remediation="Agrupe parâmetros relacionados em um Parameter Object ou Value Object. Use o padrão Builder para criação complexa.",
                cwe="CWE-1040",
                confidence=Confidence.HIGH,
            ))

        return results

    # ── Aninhamento por linha ─────────────────────────────────────────────────
    def _check_nesting_per_line(self) -> List[Vulnerability]:
        results: List[Vulnerability] = []
        reported: set[int] = set()

        if self.language in (Language.PYTHON, Language.RUBY):
            for i, line in enumerate(self.lines):
                if not line.strip():
                    continue
                indent = len(line) - len(line.lstrip())
                depth = indent // 4
                if depth > MAX_NESTING_DEPTH and i not in reported:
                    reported.add(i)
                    results.append(self._nesting_vuln(i + 1, line, depth))
        else:
            depth = 0
            for i, line in enumerate(self.lines):
                depth += line.count('{') - line.count('}')
                depth = max(0, depth)
                if depth > MAX_NESTING_DEPTH + 1 and i not in reported:
                    reported.add(i)
                    results.append(self._nesting_vuln(i + 1, line, depth))

        return results[:5]  # Máximo 5 por arquivo para evitar flood

    def _nesting_vuln(self, line_num: int, line: str, depth: int) -> Vulnerability:
        return Vulnerability(
            rule_id="CMPLX-005",
            name="Aninhamento Excessivamente Profundo",
            description=f"Código com {depth} níveis de aninhamento (threshold: {MAX_NESTING_DEPTH}). Alta profundidade aumenta complexidade cognitiva exponencialmente e é sinal de código que precisa de refatoração.",
            severity=Severity.MEDIUM,
            category=VulnCategory.COMPLEXITY,
            language=self.language,
            file_path=self.file_path,
            line_number=line_num,
            line_content=line.rstrip(),
            remediation="Use Early Return / Guard Clauses para reduzir aninhamento: em vez de if (cond) { ... }, use if (!cond) return; ... Extraia blocos internos em funções.",
            cwe="CWE-1121",
            confidence=Confidence.MEDIUM,
        )


def analyze_complexity(file_path: str, content: str, language: Language) -> List[Vulnerability]:
    if language in (Language.UNKNOWN, Language.GENERIC):
        return []
    analyzer = ComplexityAnalyzer(file_path, content, language)
    return analyzer.analyze()
