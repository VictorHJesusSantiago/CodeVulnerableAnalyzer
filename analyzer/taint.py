"""
Primitivas compartilhadas de taint analysis (SSOT).

Centraliza as expressões de fonte/atribuição/sink e o rastreador de taint
(`TaintTracker`) usados por:

  1. a elevação de confiança inline em `engine._scan_content` (marca um achado
     de regra como HIGH-confidence quando a variável no sink está contaminada);
  2. o analisador de taint dedicado `engine._analyze_taint` (emite TAINT-001).

Antes, a detecção de fontes vivia duplicada nos dois lugares e havia divergido:
o caminho inline só reconhecia fontes Python (`TAINT_SOURCE_RE`), enquanto o
dedicado também reconhecia PHP/JS (`TAINT_SOURCE_EXTRA_RE`). Uma única
implementação aqui garante que os dois nunca mais divirjam.
"""

from __future__ import annotations

import re

from analyzer.models import Severity, VulnCategory



TAINT_SOURCE_RE = re.compile(
    r"\b(\w+)\s*=\s*(?:"
    r"request\.(?:args|form|json|data|values|get|params|cookies|headers)\b|"
    r"sys\.argv\[|"
    r"input\s*\(|"
    r"os\.environ\b|"
    r"os\.getenv\s*\(|"
    r"urllib\.parse\.parse_qs\s*\(|"
    r"flask\.request\b|"
    r"fastapi\.Request\b"
    r")"
)

TAINT_SOURCE_EXTRA_RE = re.compile(
    r"\b(\w+)\s*=\s*(?:"
    r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b|"
    r"req\.(?:body|query|params|cookies|headers)\b|"
    r"process\.argv\b"
    r")"
)

ASSIGN_RE = re.compile(r"^\s*\$?(\w+)\s*(?:=|\+=)\s*(.+)$")

TAINT_SINK_RE = re.compile(
    r"(?:eval|exec|os\.system|subprocess\.(?:run|call|Popen)|"
    r"cursor\.execute|engine\.execute|render_template_string|"
    r"__import__)\s*\([^)]*\b(\w+)\b"
)

TAINT_SINKS = [
    (re.compile(r"\beval\s*\("), VulnCategory.CODE_INJECTION, Severity.CRITICAL, "eval()"),
    (re.compile(r"\bexec\s*\("), VulnCategory.CODE_INJECTION, Severity.CRITICAL, "exec()"),
    (re.compile(r"\bos\.system\s*\("), VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "os.system()"),
    (
        re.compile(r"\bsubprocess\.(?:run|call|Popen|check_output)\s*\("),
        VulnCategory.COMMAND_INJECTION,
        Severity.HIGH,
        "subprocess",
    ),
    (
        re.compile(r"\brender_template_string\s*\("),
        VulnCategory.CODE_INJECTION,
        Severity.HIGH,
        "render_template_string()",
    ),
    (re.compile(r"\.execute\s*\("), VulnCategory.SQL_INJECTION, Severity.HIGH, "cursor.execute()"),
    (
        re.compile(r"\b(?:mysqli?_query|pg_query|sqlite_query)\s*\("),
        VulnCategory.SQL_INJECTION,
        Severity.CRITICAL,
        "SQL query function (PHP)",
    ),
    (re.compile(r"\bchild_process\.exec\s*\("), VulnCategory.COMMAND_INJECTION, Severity.HIGH, "child_process.exec()"),
    (
        re.compile(r"\b(?:shell_exec|passthru|popen|system)\s*\("),
        VulnCategory.COMMAND_INJECTION,
        Severity.HIGH,
        "shell exec (PHP)",
    ),
]


class TaintTracker:
    """
    Rastreia variáveis contaminadas linha a linha, com propagação por
    atribuição e "sanitização" implícita (reatribuir a partir de algo não
    contaminado limpa a variável). Stateless entre arquivos: instancie um
    tracker por arquivo/conteúdo.
    """

    def __init__(self) -> None:
        self.tainted: set[str] = set()

    def refs_tainted(self, expr: str) -> bool:
        """True se `expr` referencia (como palavra) alguma variável contaminada."""
        return any(re.search(r"\b" + re.escape(t) + r"\b", expr) for t in self.tainted)

    def observe(self, line: str) -> bool:
        """
        Atualiza o estado de taint a partir de `line`. Retorna True se a linha
        introduziu uma fonte direta de entrada do usuário.
        """
        src = TAINT_SOURCE_RE.search(line) or TAINT_SOURCE_EXTRA_RE.search(line)
        is_source = bool(src)
        if src:
            self.tainted.add(src.group(1))

        ma = ASSIGN_RE.match(line)
        if ma and not is_source:
            lhs, rhs = ma.group(1), ma.group(2)
            if self.refs_tainted(rhs):
                self.tainted.add(lhs)
            elif lhs in self.tainted:
                self.tainted.discard(lhs)
        return is_source
