from __future__ import annotations
from typing import List
from analyzer.models import Language
from analyzer.rules.base import Rule

# ── Segurança por linguagem (originais) ───────────────────────────────────────
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

# ── Linguagens Batch 1 ────────────────────────────────────────────────────────
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

# ── Linguagens Batch 2 — JVM / Funcionais ─────────────────────────────────────
from analyzer.rules.scala_rules import SCALA_RULES
from analyzer.rules.groovy_rules import GROOVY_RULES
from analyzer.rules.elixir_rules import ELIXIR_RULES
from analyzer.rules.erlang_rules import ERLANG_RULES
from analyzer.rules.haskell_rules import HASKELL_RULES
from analyzer.rules.clojure_rules import CLOJURE_RULES
from analyzer.rules.fsharp_rules import FSHARP_RULES

# ── Linguagens Batch 3 — Scripting / Legado ────────────────────────────────────
from analyzer.rules.lua_rules import LUA_RULES
from analyzer.rules.perl_rules import PERL_RULES
from analyzer.rules.julia_rules import JULIA_RULES
from analyzer.rules.coffee_rules import COFFEE_RULES
from analyzer.rules.elm_rules import ELM_RULES

# ── Linguagens Batch 4 — Sistemas / Low-level ─────────────────────────────────
from analyzer.rules.nim_rules import NIM_RULES
from analyzer.rules.zig_rules import ZIG_RULES
from analyzer.rules.crystal_rules import CRYSTAL_RULES
from analyzer.rules.objc_rules import OBJC_RULES

# ── Linguagens Batch 5 — Enterprise ───────────────────────────────────────────
from analyzer.rules.apex_rules import APEX_RULES
from analyzer.rules.abap_rules import ABAP_RULES

# ── Dados / Schema ────────────────────────────────────────────────────────────
from analyzer.rules.graphql_rules import GRAPHQL_RULES
from analyzer.rules.proto_rules import PROTO_RULES

# ── Qualidade de código ────────────────────────────────────────────────────────
from analyzer.rules.quality_generic import QUALITY_GENERIC_RULES
from analyzer.rules.quality_python import QUALITY_PYTHON_RULES
from analyzer.rules.quality_javascript import QUALITY_JS_RULES
from analyzer.rules.quality_java import QUALITY_JAVA_RULES
from analyzer.rules.quality_csharp import QUALITY_CSHARP_RULES

# ── SOLID / Performance / Arquitetura / Concorrência ──────────────────────────
from analyzer.rules.solid_rules import SOLID_RULES
from analyzer.rules.performance_rules import PERFORMANCE_RULES
from analyzer.rules.architecture_rules import ARCHITECTURE_RULES
from analyzer.rules.concurrency_rules import CONCURRENCY_RULES

# ── IaC Security (Batch 6) ────────────────────────────────────────────────────
from analyzer.rules.k8s_rules import K8S_RULES
from analyzer.rules.gha_rules import GHA_RULES
from analyzer.rules.gitlab_ci_rules import GITLAB_CI_RULES
from analyzer.rules.cloudformation_rules import CFN_RULES
from analyzer.rules.arm_rules import ARM_RULES
from analyzer.rules.ansible_rules import ANSIBLE_RULES
from analyzer.rules.pulumi_rules import PULUMI_RULES

# ── API Security (Batch 6) ────────────────────────────────────────────────────
from analyzer.rules.openapi_rules import OPENAPI_RULES
from analyzer.rules.grpc_rules import GRPC_RULES
from analyzer.rules.graphql_security_rules import GRAPHQL_SECURITY_RULES

# ── Database DDL Security (Batch 6) ──────────────────────────────────────────
from analyzer.rules.pg_ddl_rules import PG_DDL_RULES
from analyzer.rules.mysql_ddl_rules import MYSQL_DDL_RULES
from analyzer.rules.tsql_proc_rules import TSQL_PROC_RULES
from analyzer.rules.plsql_rules import PLSQL_RULES

# ── Mobile Security (Batch 6) ─────────────────────────────────────────────────
from analyzer.rules.android_manifest_rules import ANDROID_MANIFEST_RULES
from analyzer.rules.ios_plist_rules import IOS_PLIST_RULES
from analyzer.rules.react_native_rules import REACT_NATIVE_RULES
from analyzer.rules.flutter_rules import FLUTTER_RULES

# ── Blockchain (Batch 6) ──────────────────────────────────────────────────────
from analyzer.rules.vyper_rules import VYPER_RULES
from analyzer.rules.move_rules import MOVE_RULES
from analyzer.rules.cairo_rules import CAIRO_RULES

# ── AI/ML Security (Batch 6) ─────────────────────────────────────────────────
from analyzer.rules.ml_security_rules import ML_SECURITY_RULES
from analyzer.rules.notebook_rules import NOTEBOOK_RULES


def _for_lang(rules: List[Rule], *langs: Language) -> List[Rule]:
    return [r for r in rules if r.language in langs or r.language == Language.GENERIC]


# ── Regras aplicadas a TODOS os arquivos ──────────────────────────────────────
CROSS_LANGUAGE_RULES: List[Rule] = (
    GENERIC_RULES
    + QUALITY_GENERIC_RULES
    + SOLID_RULES
    + [r for r in ARCHITECTURE_RULES if r.language == Language.GENERIC]
    + [r for r in PERFORMANCE_RULES  if r.language == Language.GENERIC]
    + [r for r in CONFIG_RULES       if r.language == Language.GENERIC]
)

# ── Partições por linguagem de regras mistas ──────────────────────────────────
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

# ── F# e OCaml separados da mesma lista de regras ─────────────────────────────
_FS_ONLY  = [r for r in FSHARP_RULES if r.language == Language.FSHARP]
_ML_ONLY  = [r for r in FSHARP_RULES if r.language == Language.OCAML]

# ── Dicionário principal: linguagem → regras específicas ─────────────────────
LANGUAGE_RULES: dict[Language, List[Rule]] = {
    # ── JVM / .NET ─────────────────────────────────────────────────────────────
    Language.PYTHON:       PYTHON_RULES + QUALITY_PYTHON_RULES + _PERF_PYTHON + _CONC_PYTHON + _ARCH_PYTHON + ML_SECURITY_RULES + NOTEBOOK_RULES + PULUMI_RULES,
    Language.JAVASCRIPT:   JAVASCRIPT_RULES + QUALITY_JS_RULES + _CONC_JS + REACT_NATIVE_RULES,
    Language.TYPESCRIPT:   JAVASCRIPT_RULES + QUALITY_JS_RULES + _CONC_JS + REACT_NATIVE_RULES,
    Language.COFFEESCRIPT: COFFEE_RULES + JAVASCRIPT_RULES + QUALITY_JS_RULES,
    Language.JAVA:         JAVA_RULES + QUALITY_JAVA_RULES + _PERF_JAVA + _CONC_JAVA,
    Language.KOTLIN:       JAVA_RULES + QUALITY_JAVA_RULES + _CONC_JAVA + KOTLIN_RULES,
    Language.SCALA:        JAVA_RULES + QUALITY_JAVA_RULES + SCALA_RULES,
    Language.GROOVY:       JAVA_RULES + GROOVY_RULES,
    Language.CLOJURE:      JAVA_RULES + CLOJURE_RULES,
    Language.CSHARP:       CSHARP_RULES + QUALITY_CSHARP_RULES + _PERF_CSHARP + _CONC_CSHARP,
    Language.FSHARP:       _FS_ONLY,
    Language.OCAML:        _ML_ONLY,
    Language.VBNET:        VB_RULES,

    # ── Web / Backend ─────────────────────────────────────────────────────────
    Language.PHP:          PHP_RULES,
    Language.RUBY:         RUBY_RULES,
    Language.GO:           GO_RULES + _CONC_GO,
    Language.PERL:         PERL_RULES,
    Language.ELM:          ELM_RULES,

    # ── Sistemas ──────────────────────────────────────────────────────────────
    Language.C:            C_CPP_RULES,
    Language.CPP:          C_CPP_RULES,
    Language.RUST:         RUST_RULES,
    Language.ZIG:          ZIG_RULES,
    Language.NIM:          NIM_RULES,
    Language.CRYSTAL:      CRYSTAL_RULES,
    Language.OBJECTIVEC:   OBJC_RULES,

    # ── Mobile ────────────────────────────────────────────────────────────────
    Language.SWIFT:        SWIFT_RULES,
    Language.DART:         DART_RULES + FLUTTER_RULES,

    # ── Scripting ─────────────────────────────────────────────────────────────
    Language.LUA:          LUA_RULES,
    Language.JULIA:        JULIA_RULES,
    Language.SHELL:        SHELL_RULES,
    Language.BASH:         SHELL_RULES,
    Language.POWERSHELL:   POWERSHELL_RULES,

    # ── Funcionais / Académicas ───────────────────────────────────────────────
    Language.ELIXIR:       ELIXIR_RULES,
    Language.ERLANG:       ERLANG_RULES,
    Language.HASKELL:      HASKELL_RULES,

    # ── DB / Query ────────────────────────────────────────────────────────────
    Language.SQL:          SQL_RULES + _PERF_SQL + PG_DDL_RULES + MYSQL_DDL_RULES,
    Language.PLSQL:        SQL_RULES + PLSQL_RULES,
    Language.TSQL:         SQL_RULES + TSQL_PROC_RULES,
    Language.COBOL:        COBOL_RULES,
    Language.GRAPHQL:      GRAPHQL_RULES + GRAPHQL_SECURITY_RULES,
    Language.PROTOBUF:     PROTO_RULES + GRPC_RULES,

    # ── Enterprise ────────────────────────────────────────────────────────────
    Language.APEX:         APEX_RULES,
    Language.ABAP:         ABAP_RULES,

    # ── IaC / DevOps ─────────────────────────────────────────────────────────
    Language.TERRAFORM:    TERRAFORM_RULES,
    Language.DOCKERFILE:   DOCKER_RULES,

    # ── Blockchain ────────────────────────────────────────────────────────────
    Language.SOLIDITY:     SOLIDITY_RULES,
    Language.VYPER:        VYPER_RULES,
    Language.MOVE:         MOVE_RULES,
    Language.CAIRO:        CAIRO_RULES,

    # ── Web / Frontend ───────────────────────────────────────────────────────
    Language.HTML:         HTML_RULES,
    Language.XML:          ANDROID_MANIFEST_RULES + IOS_PLIST_RULES,

    # ── Dados / Config ────────────────────────────────────────────────────────
    Language.YAML:         _CFG_YAML + K8S_RULES + GHA_RULES + GITLAB_CI_RULES + CFN_RULES + ANSIBLE_RULES + OPENAPI_RULES,
    Language.TOML:         _CFG_TOML,
    Language.INI:          _CFG_INI,
    Language.JSON:         _CFG_JSON + ARM_RULES,

    # ── Científico ───────────────────────────────────────────────────────────
    Language.R:            R_RULES,
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
