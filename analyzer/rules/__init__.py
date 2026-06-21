from __future__ import annotations
from typing import List
from analyzer.models import Language
from analyzer.rules.base import Rule

# ── Regras de segurança por linguagem ─────────────────────────────────────
from analyzer.rules.generic import GENERIC_RULES
from analyzer.rules.python_rules import PYTHON_RULES
from analyzer.rules.javascript_rules import JAVASCRIPT_RULES
from analyzer.rules.java_rules import JAVA_RULES
from analyzer.rules.csharp_rules import CSHARP_RULES
from analyzer.rules.php_rules import PHP_RULES
from analyzer.rules.go_rules import GO_RULES
from analyzer.rules.ruby_rules import RUBY_RULES
from analyzer.rules.c_cpp_rules import C_CPP_RULES
from analyzer.rules.sql_rules import SQL_RULES
from analyzer.rules.cobol_rules import COBOL_RULES
from analyzer.rules.shell_rules import SHELL_RULES

# ── Qualidade de código por linguagem ─────────────────────────────────────
from analyzer.rules.quality_generic import QUALITY_GENERIC_RULES
from analyzer.rules.quality_python import QUALITY_PYTHON_RULES
from analyzer.rules.quality_javascript import QUALITY_JS_RULES
from analyzer.rules.quality_java import QUALITY_JAVA_RULES
from analyzer.rules.quality_csharp import QUALITY_CSHARP_RULES

# ── Princípios SOLID, Performance, Arquitetura, Concorrência ──────────────
from analyzer.rules.solid_rules import SOLID_RULES
from analyzer.rules.performance_rules import PERFORMANCE_RULES
from analyzer.rules.architecture_rules import ARCHITECTURE_RULES
from analyzer.rules.concurrency_rules import CONCURRENCY_RULES


def _for_lang(rules: List[Rule], *langs: Language) -> List[Rule]:
    """Filtra regras pelo campo language (ou Language.GENERIC para multi-linguagem)."""
    return [r for r in rules if r.language in langs or r.language == Language.GENERIC]


# Regras multi-linguagem aplicadas a TODOS os arquivos
CROSS_LANGUAGE_RULES: List[Rule] = (
    GENERIC_RULES
    + QUALITY_GENERIC_RULES
    + SOLID_RULES
    + [r for r in ARCHITECTURE_RULES if r.language == Language.GENERIC]
    + [r for r in PERFORMANCE_RULES  if r.language == Language.GENERIC]
)

# Regras de arquitetura específicas por linguagem
_ARCH_PYTHON  = [r for r in ARCHITECTURE_RULES if r.language == Language.PYTHON]

# Regras de performance específicas por linguagem
_PERF_PYTHON  = [r for r in PERFORMANCE_RULES if r.language == Language.PYTHON]
_PERF_JAVA    = [r for r in PERFORMANCE_RULES if r.language == Language.JAVA]
_PERF_CSHARP  = [r for r in PERFORMANCE_RULES if r.language == Language.CSHARP]
_PERF_SQL     = [r for r in PERFORMANCE_RULES if r.language == Language.SQL]

# Regras de concorrência específicas por linguagem
_CONC_JAVA    = [r for r in CONCURRENCY_RULES if r.language == Language.JAVA]
_CONC_JS      = [r for r in CONCURRENCY_RULES if r.language == Language.JAVASCRIPT]
_CONC_GO      = [r for r in CONCURRENCY_RULES if r.language == Language.GO]
_CONC_PYTHON  = [r for r in CONCURRENCY_RULES if r.language == Language.PYTHON]
_CONC_CSHARP  = [r for r in CONCURRENCY_RULES if r.language == Language.CSHARP]

LANGUAGE_RULES: dict[Language, List[Rule]] = {
    Language.PYTHON: (
        PYTHON_RULES
        + QUALITY_PYTHON_RULES
        + _PERF_PYTHON
        + _CONC_PYTHON
        + _ARCH_PYTHON
    ),
    Language.JAVASCRIPT: (
        JAVASCRIPT_RULES
        + QUALITY_JS_RULES
        + _CONC_JS
    ),
    Language.TYPESCRIPT: (
        JAVASCRIPT_RULES
        + QUALITY_JS_RULES
        + _CONC_JS
    ),
    Language.JAVA: (
        JAVA_RULES
        + QUALITY_JAVA_RULES
        + _PERF_JAVA
        + _CONC_JAVA
    ),
    Language.KOTLIN:  JAVA_RULES + QUALITY_JAVA_RULES + _CONC_JAVA,
    Language.SCALA:   JAVA_RULES + QUALITY_JAVA_RULES,
    Language.CSHARP: (
        CSHARP_RULES
        + QUALITY_CSHARP_RULES
        + _PERF_CSHARP
        + _CONC_CSHARP
    ),
    Language.PHP:   PHP_RULES,
    Language.GO: (
        GO_RULES
        + _CONC_GO
    ),
    Language.RUBY:  RUBY_RULES,
    Language.C:     C_CPP_RULES,
    Language.CPP:   C_CPP_RULES,
    Language.SQL:   SQL_RULES + _PERF_SQL,
    Language.COBOL: COBOL_RULES,
    Language.SHELL: SHELL_RULES,
}


def get_rules(language: Language) -> List[Rule]:
    """Retorna todas as regras para uma linguagem: cross-language + específicas."""
    lang_rules = LANGUAGE_RULES.get(language, [])
    return CROSS_LANGUAGE_RULES + lang_rules


def get_all_rules() -> List[Rule]:
    """Retorna todas as regras únicas do sistema (para --rules e contagem)."""
    seen_ids: set[str] = set()
    all_rules: List[Rule] = []

    for rule in CROSS_LANGUAGE_RULES:
        if rule.id not in seen_ids:
            seen_ids.add(rule.id)
            all_rules.append(rule)

    for rule in CONCURRENCY_RULES:
        if rule.id not in seen_ids:
            seen_ids.add(rule.id)
            all_rules.append(rule)

    for rules in LANGUAGE_RULES.values():
        for rule in rules:
            if rule.id not in seen_ids:
                seen_ids.add(rule.id)
                all_rules.append(rule)

    return all_rules


def rule_count() -> int:
    return len(get_all_rules())
