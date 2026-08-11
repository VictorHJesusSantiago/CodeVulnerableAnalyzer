"""
Suite de regressão estilo Juliet Test Suite (NIST SAMATE): para cada CWE do
mini-corpus em tests/benchmark/corpus.py, garante que:
  1. A versão "bad" (vulnerável conhecida) produz >=1 achado com o CWE esperado.
  2. A versão "good" (corrigida) NÃO produz achados com o mesmo CWE
     (elimina falsos positivos na correção idiomática).

Rodar: python -m pytest tests/test_benchmark.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.engine import ScanEngine
from analyzer.models import Severity
from tests.benchmark.corpus import CASES, BenchmarkCase


def _scan_code(tmp_path: Path, filename: str, code: str):
    f = tmp_path / filename
    f.write_text(code, encoding="utf-8")
    eng = ScanEngine(min_severity=Severity.INFO)
    result = eng.scan_file(str(f))
    return result.vulnerabilities


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_bad_variant_detected(tmp_path, case: BenchmarkCase):
    vulns = _scan_code(tmp_path, f"{case.name}_bad.{case.language}", case.bad_code)
    matching = [v for v in vulns if v.cwe == case.cwe]
    assert matching, (
        f"[{case.name}] esperava >=1 achado com {case.cwe} no código vulnerável, "
        f"mas achados foram: {[(v.rule_id, v.cwe) for v in vulns]}"
    )


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_good_variant_clean(tmp_path, case: BenchmarkCase):
    vulns = _scan_code(tmp_path, f"{case.name}_good.{case.language}", case.good_code)
    matching = [v for v in vulns if v.cwe == case.cwe]
    assert not matching, (
        f"[{case.name}] falso positivo: a versão corrigida ainda dispara {case.cwe} via {[v.rule_id for v in matching]}"
    )
