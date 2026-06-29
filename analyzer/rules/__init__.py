from __future__ import annotations
from typing import List
from analyzer.models import Language
from analyzer.rules.base import Rule

# ── Segurança por linguagem ────────────────────────────────────────────────
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

# ── Novas linguagens ───────────────────────────────────────────────────────
from analyzer.rules.rust_rules import RUST_RULES
from analyzer.rules.swift_rules import SWIFT_RULES
from analyzer.rules.dart_rules import DART_RULES
from analyzer.rules.kotlin_rules import KOTLIN_RULES
from analyzer.rules.powershell_rules import POWERSHELL_RULES
from analyzer.rules.docker_rules import DOCKER_RULES
from analyzer.rules.terraform_rules import TERRAFORM_RULES
from analyzer.rules.solidity_rules import SOLIDITY_RULES
from analyzer.rules.html_rules import HTML_RULES
from analyzer.rules.vb_rules import VB_RULES
from analyzer.rules.r_rules import R_RULES
from analyzer.rules.config_rules import CONFIG_RULES

# ── Qualidade de código ────────────────────────────────────────────────────
from analyzer.rules.quality_generic import QUALITY_GENERIC_RULES
from analyzer.rules.quality_python import QUALITY_PYTHON_RULES
from analyzer.rules.quality_javascript import QUALITY_JS_RULES
from analyzer.rules.quality_java import QUALITY_JAVA_RULES
from analyzer.rules.quality_csharp import QUALITY_CSHARP_RULES

# ── SOLID / Performance / Arquitetura / Concorrência ──────────────────────
from analyzer.rules.solid_rules import SOLID_RULES
from analyzer.rules.performance_rules import PERFORMANCE_RULES
from analyzer.rules.architecture_rules import ARCHITECTURE_RULES
from analyzer.rules.concurrency_rules import CONCURRENCY_RULES


def _for_lang(rules: List[Rule], *langs: Language) -> List[Rule]:
    return [r for r in rules if r.language in langs or r.language == Language.GENERIC]


# Regras aplicadas a TODOS os arquivos
CROSS_LANGUAGE_RULES: List[Rule] = (
    GENERIC_RULES
    + QUALITY_GENERIC_RULES
    + SOLID_RULES
    + [r for r in ARCHITECTURE_RULES if r.language == Language.GENERIC]
    + [r for r in PERFORMANCE_RULES  if r.language == Language.GENERIC]
    + [r for r in CONFIG_RULES       if r.language == Language.GENERIC]
)

# Partições por linguagem das regras mistas
_ARCH_PYTHON  = [r for r in ARCHITECTURE_RULES if r.language == Language.PYTHON]
_PERF_PYTHON  = [r for r in PERFORMANCE_RULES  if r.language == Language.PYTHON]
_PERF_JAVA    = [r for r in PERFORMANCE_RULES  if r.language == Language.JAVA]
_PERF_CSHARP  = [r for r in PERFORMANCE_RULES  if r.language == Language.CSHARP]
_PERF_SQL     = [r for r in PERFORMANCE_RULES  if r.language == Language.SQL]
_CONC_JAVA    = [r for r in CONCURRENCY_RULES  if r.language == Language.JAVA]
_CONC_JS      = [r for r in CONCURRENCY_RULES  if r.language == Language.JAVASCRIPT]
_CONC_GO      = [r for r in CONCURRENCY_RULES  if r.language == Language.GO]
_CONC_PYTHON  = [r for r in CONCURRENCY_RULES  if r.language == Language.PYTHON]
_CONC_CSHARP  = [r for r in CONCURRENCY_RULES  if r.language == Language.CSHARP]
_CFG_YAML     = [r for r in CONFIG_RULES if r.language == Language.YAML]
_CFG_TOML     = [r for r in CONFIG_RULES if r.language == Language.TOML]
_CFG_INI      = [r for r in CONFIG_RULES if r.language == Language.INI]
_CFG_JSON     = [r for r in CONFIG_RULES if r.language == Language.JSON]

LANGUAGE_RULES: dict[Language, List[Rule]] = {
    Language.PYTHON:     PYTHON_RULES + QUALITY_PYTHON_RULES + _PERF_PYTHON + _CONC_PYTHON + _ARCH_PYTHON,
    Language.JAVASCRIPT: JAVASCRIPT_RULES + QUALITY_JS_RULES + _CONC_JS,
    Language.TYPESCRIPT: JAVASCRIPT_RULES + QUALITY_JS_RULES + _CONC_JS,
    Language.JAVA:       JAVA_RULES + QUALITY_JAVA_RULES + _PERF_JAVA + _CONC_JAVA,
    Language.KOTLIN:     JAVA_RULES + QUALITY_JAVA_RULES + _CONC_JAVA + KOTLIN_RULES,
    Language.SCALA:      JAVA_RULES + QUALITY_JAVA_RULES,
    Language.CSHARP:     CSHARP_RULES + QUALITY_CSHARP_RULES + _PERF_CSHARP + _CONC_CSHARP,
    Language.VBNET:      VB_RULES,
    Language.PHP:        PHP_RULES,
    Language.GO:         GO_RULES + _CONC_GO,
    Language.RUBY:       RUBY_RULES,
    Language.C:          C_CPP_RULES,
    Language.CPP:        C_CPP_RULES,
    Language.SQL:        SQL_RULES + _PERF_SQL,
    Language.PLSQL:      SQL_RULES,
    Language.TSQL:       SQL_RULES,
    Language.COBOL:      COBOL_RULES,
    Language.SHELL:      SHELL_RULES,
    Language.BASH:       SHELL_RULES,
    Language.POWERSHELL: POWERSHELL_RULES,
    Language.RUST:       RUST_RULES,
    Language.SWIFT:      SWIFT_RULES,
    Language.DART:       DART_RULES,
    Language.TERRAFORM:  TERRAFORM_RULES,
    Language.DOCKERFILE: DOCKER_RULES,
    Language.SOLIDITY:   SOLIDITY_RULES,
    Language.HTML:       HTML_RULES,
    Language.YAML:       _CFG_YAML,
    Language.TOML:       _CFG_TOML,
    Language.INI:        _CFG_INI,
    Language.JSON:       _CFG_JSON,
    Language.R:          R_RULES,
}


def get_rules(language: Language) -> List[Rule]:
    lang_rules = LANGUAGE_RULES.get(language, [])
    return CROSS_LANGUAGE_RULES + lang_rules


def get_all_rules() -> List[Rule]:
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
