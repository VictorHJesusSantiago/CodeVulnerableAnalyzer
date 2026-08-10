"""
i18n leve para os rótulos fixos da UI (painéis, cabeçalhos, resumo).

Escopo: strings de interface (rótulos de painel, cabeçalhos de tabela,
mensagens de status). As descrições/remediations das 900+ regras de
vulnerabilidade permanecem em inglês — são o corpus técnico original
e traduzi-las 1:1 introduziria risco de imprecisão sem uma revisão de
segurança dedicada por regra.

Seleção: variável de ambiente VULNSCAN_LOCALE=pt|en, ou flag --locale.
Padrão: pt (idioma original da CLI).
"""

from __future__ import annotations

import json as _json
import os
from pathlib import Path as _Path

_STRINGS: dict[str, dict[str, str]] = {
    "pt": {
        "scan_info": "Scan Info",
        "severity_distribution": "Severity Distribution",
        "top_categories": "Top Vulnerability Categories",
        "target": "Target",
        "files_scanned": "Files Scanned",
        "files_with_issues": "Files With Issues",
        "total_issues": "Total Issues",
        "scan_time": "Scan Time",
        "languages": "Languages",
        "risk_grade": "Risk Grade",
        "report_title": "VULNERABILITY SCAN REPORT",
        "scan_complete": "SCAN COMPLETE",
        "no_vulns": "✅  Nenhuma vulnerabilidade detectada!",
        "summary": "Resumo:",
        "grade_excellent": "Excelente",
        "grade_good": "Bom",
        "grade_fair": "Regular",
        "grade_bad": "Ruim",
        "grade_critical": "Crítico",
    },
    "en": {
        "scan_info": "Scan Info",
        "severity_distribution": "Severity Distribution",
        "top_categories": "Top Vulnerability Categories",
        "target": "Target",
        "files_scanned": "Files Scanned",
        "files_with_issues": "Files With Issues",
        "total_issues": "Total Issues",
        "scan_time": "Scan Time",
        "languages": "Languages",
        "risk_grade": "Risk Grade",
        "report_title": "VULNERABILITY SCAN REPORT",
        "scan_complete": "SCAN COMPLETE",
        "no_vulns": "✅  No vulnerabilities detected!",
        "summary": "Summary:",
        "grade_excellent": "Excellent",
        "grade_good": "Good",
        "grade_fair": "Fair",
        "grade_bad": "Poor",
        "grade_critical": "Critical",
    },
}

VALID_LOCALES = tuple(_STRINGS.keys())

_active_locale = os.environ.get("VULNSCAN_LOCALE", "pt")
if _active_locale not in _STRINGS:
    _active_locale = "pt"


def set_locale(name: str) -> None:
    global _active_locale
    if name in _STRINGS:
        _active_locale = name


def get_locale() -> str:
    return _active_locale


def t(key: str) -> str:
    """Traduz uma chave de UI para o locale ativo. Fallback: a própria chave."""
    return _STRINGS.get(_active_locale, _STRINGS["pt"]).get(key, key)


# ── i18n de CONTEÚDO de regras (name/description/remediation) ─────────────────
#
# As 900+ regras têm texto técnico em inglês (o corpus original). Traduzir
# manualmente 1:1 aqui, sem revisão de segurança por regra, arriscaria
# introduzir imprecisão técnica em texto de segurança — pior que não traduzir.
#
# Em vez disso, esta é a INFRAESTRUTURA funcional e testada para tradução
# de conteúdo: qualquer um pode fornecer um arquivo de overrides por rule_id,
# carregado de (nesta ordem de precedência):
#   1. ./vulnscan-i18n-<locale>.json           (projeto)
#   2. ~/.vulnscan/i18n/<locale>.json          (usuário)
#
# Formato: {"RULE-ID": {"name": "...", "description": "...", "remediation": "..."}}
# Chaves parciais são aceitas (ex.: só "description"). Regras sem entrada no
# arquivo mantêm o texto original em inglês — nunca há tradução "quebrada".

_rule_overrides: dict[str, dict[str, str]] = {}
_rule_overrides_locale: str | None = None


def _load_rule_overrides(locale: str) -> dict[str, dict[str, str]]:
    sources = [
        _Path(f"vulnscan-i18n-{locale}.json"),
        _Path.home() / ".vulnscan" / "i18n" / f"{locale}.json",
    ]
    merged: dict[str, dict[str, str]] = {}
    for src in sources:
        try:
            if src.exists():
                data = _json.loads(src.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    for rule_id, fields in data.items():
                        if isinstance(fields, dict):
                            merged.setdefault(rule_id, {}).update(fields)
        except (OSError, _json.JSONDecodeError):
            pass
    return merged


def translate_rule_fields(rule_id: str, name: str, description: str, remediation: str) -> tuple[str, str, str]:
    """
    Aplica overrides de tradução de conteúdo de regra para `rule_id`, se
    existirem no locale ativo. Retorna (name, description, remediation)
    — originais em inglês se não houver override para aquele campo/regra.
    """
    global _rule_overrides, _rule_overrides_locale
    if _rule_overrides_locale != _active_locale:
        _rule_overrides = _load_rule_overrides(_active_locale)
        _rule_overrides_locale = _active_locale

    ov = _rule_overrides.get(rule_id)
    if not ov:
        return name, description, remediation
    return (
        ov.get("name", name),
        ov.get("description", description),
        ov.get("remediation", remediation),
    )
