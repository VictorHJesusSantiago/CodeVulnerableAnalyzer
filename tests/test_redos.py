"""
Guarda de ReDoS para todo o ruleset (912+ regras) — ESTÁTICO e à prova de hang.

Por que estático e não "rodar cada regex com timeout":
    O módulo `re` do CPython segura o GIL durante o match. Um regex com
    backtracking exponencial nunca cede o GIL, então NÃO dá para abandoná-lo
    com timeout de thread (o executor trava no shutdown esperando o worker).
    Testar ReDoS executando o padrão catastrófico é, portanto, inseguro em CI.

Invariante verificado (a assinatura real do DoS explorável neste engine):
    Uma regra só roda seu regex sobre conteúdo multi-linha ilimitado quando é
    `multiline=True` (via `match_content(full_content)`). Regras line-based
    rodam por linha, limitadas a MAX_LINE_LENGTH=2000 chars pelo engine, onde
    até um regex polinomial termina em milissegundos.

    Logo, o vetor de ReDoS explorável = uma regra `multiline=True` com
    quantificador aninhado ilimitado — `(a+)+`, `(.*)*`, `(?:...\\n)*` etc.
    Este teste garante que NENHUMA regra multiline tem esse shape.

Estado atual (verificado empiricamente uma vez, ver histórico):
    - 10 regras multiline → nenhuma com quantificador aninhado; todas rápidas
      contra bloco adversário grande.
    - 15 regras line-based contêm o shape, mas são `multiline=False` e têm `\\n`
      no pattern → nunca casam por linha (inócuas) e nunca rodam sobre conteúdo.
"""

from __future__ import annotations

import re

import pytest

from analyzer.rules import get_all_rules

_UNBOUNDED_NESTED = re.compile(r"\((?:\?[:=!])?[^()]*[+*][^()]*\)[+*]")


def _has_unbounded_nested_quant(pattern: str) -> bool:
    return bool(_UNBOUNDED_NESTED.search(pattern))


def test_no_multiline_rule_has_unbounded_nested_quantifier():
    """O vetor real de ReDoS: regra que roda regex sobre conteúdo ilimitado
    (multiline) E tem quantificador aninhado ilimitado."""
    offenders = []
    for rule in get_all_rules():
        if not rule.multiline:
            continue
        for field in ("pattern", "negative_pattern"):
            pat = getattr(rule, field, None)
            if pat and _has_unbounded_nested_quant(pat):
                offenders.append(f"{rule.id}.{field}")
    assert not offenders, (
        "Regra(s) multiline com quantificador aninhado ilimitado (risco de "
        "ReDoS ao rodar sobre o conteúdo inteiro do arquivo): " + ", ".join(offenders)
    )


_REVIEWED_SAFE_NESTED_QUANT = frozenset(
    {
        "QG-006",
        "SLD-004",
        "TSQLP-007",
        "K8S-004",
        "K8S-008",
        "GHA-007",
        "GHA-010",
        "GLCI-002",
        "GLCI-003",
        "GLCI-006",
        "CFN-005",
        "CFN-008",
        "ANSIBLE-009",
        "OAPI-004",
        "OAPI-006",
    }
)


def test_new_nested_quant_rules_require_review():
    """Baseline/ratchet: qualquer regra com quantificador aninhado ilimitado
    precisa estar na allowlist revisada. Uma regra nova com esse shape falha
    aqui — forçando verificação empírica de que não é exponencial antes de mergear."""
    unreviewed = []
    for rule in get_all_rules():
        for field in ("pattern", "negative_pattern"):
            pat = getattr(rule, field, None)
            if pat and _has_unbounded_nested_quant(pat) and rule.id not in _REVIEWED_SAFE_NESTED_QUANT:
                unreviewed.append(f"{rule.id}.{field}")
    assert not unreviewed, (
        "Regra(s) com quantificador aninhado ilimitado NÃO revisadas para ReDoS: "
        + ", ".join(unreviewed)
        + ". Verifique empiricamente (match < 0.5s em linha de 2000 chars) e "
        "adicione a _REVIEWED_SAFE_NESTED_QUANT, ou reescreva o pattern."
    )


@pytest.mark.parametrize(
    "dangerous",
    [
        r"(a+)+",
        r"(a*)*",
        r"(?:\s+[^\n]+\n)*",
        r"([^{}]*\{[^{}]*\})+",
    ],
)
def test_detector_flags_known_dangerous_shapes(dangerous):
    """Sanidade: o detector estático reconhece os shapes catastróficos conhecidos."""
    assert _has_unbounded_nested_quant(dangerous)


@pytest.mark.parametrize(
    "safe",
    [
        r"\w+(?:\.\w+){4,}",
        r"(abc)+",
        r"[a-z]+\d+",
    ],
)
def test_detector_ignores_safe_shapes(safe):
    """O detector não gera falso-positivo em quantificadores limitados/simples."""
    assert not _has_unbounded_nested_quant(safe)
