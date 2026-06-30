"""
Testes de regressão e funcionais do CodeVulnerableAnalyzer.
Rodar: python -m pytest tests/ -q
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path

import pytest

# Garante import do pacote a partir da raiz do projeto
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.engine import ScanEngine, _load_custom_rules, _parse_simple_yaml_rules, _analyze_taint
from analyzer.models import Severity, Language
from analyzer.rules import get_rules, rule_count


# ── Helpers ───────────────────────────────────────────────────────────────────

def _scan(tmp_path: Path, name: str, code: str):
    f = tmp_path / name
    f.write_text(code, encoding="utf-8")
    eng = ScanEngine(min_severity=Severity.INFO)
    return eng.scan_file(str(f))


# ── 1. Regressão do bug de taint (group(2) → IndexError) ───────────────────────

def test_engine_detects_dangerous_calls_without_error(tmp_path):
    """
    Regressão: arquivos com eval/os.system NÃO podem retornar 0 por exceção
    silenciosa. O bug de _TAINT_SINK_RE.group(2) fazia o scan_file engolir
    IndexError e devolver lista vazia com error preenchido.
    """
    res = _scan(tmp_path, "danger.py",
                'eval(request.form["x"])\nos.system("rm " + x)\n')
    assert res.error is None, f"scan_file não deveria ter erro: {res.error}"
    assert len(res.vulnerabilities) > 0, "deveria detectar eval/os.system"


def test_rules_load_and_match():
    assert rule_count() > 100
    rules = get_rules(Language.PYTHON)
    assert any(r.match('eval(request.form["x"])') for r in rules)


# ── 2. Taint analysis: propagação e sanitização ────────────────────────────────

def test_taint_propagation_multi_hop():
    code = (
        'user = request.args.get("c")\n'
        'tmp = user\n'
        'final = "p " + tmp\n'
        'os.system(final)\n'
    )
    findings = _analyze_taint("t.py", code.splitlines(), Language.PYTHON, None)
    assert len(findings) == 1
    assert findings[0].rule_id == "TAINT-001"
    assert findings[0].severity == Severity.CRITICAL


def test_taint_does_not_flag_constant():
    code = 'safe = "ls -la"\nos.system(safe)\n'
    findings = _analyze_taint("t.py", code.splitlines(), Language.PYTHON, None)
    assert findings == []


def test_taint_sql_category():
    code = 'q = request.form["id"]\ncursor.execute("SELECT " + q)\n'
    findings = _analyze_taint("t.py", code.splitlines(), Language.PYTHON, None)
    assert len(findings) == 1
    assert findings[0].category.value == "SQL Injection"


# ── 3. Regras customizadas: JSON e YAML ────────────────────────────────────────

def test_custom_rules_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "vulnscan-rules.yaml").write_text(
        "rules:\n"
        "  - id: CUSTOM-Y1\n"
        "    name: Teste YAML\n"
        "    severity: HIGH\n"
        "    category: Other\n"
        "    language: python\n"
        "    pattern: \"FOOBAR\"\n"
        "    ignorecase: true\n",
        encoding="utf-8",
    )
    rules = _load_custom_rules()
    ids = [r.id for r in rules]
    assert "CUSTOM-Y1" in ids
    r = next(r for r in rules if r.id == "CUSTOM-Y1")
    assert r.severity == Severity.HIGH
    assert r.match("xx FOOBAR xx")          # ignorecase aplicado
    assert r.match("xx foobar xx")


def test_custom_rules_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "vulnscan-rules.json").write_text(
        json.dumps([{
            "id": "CUSTOM-J1", "name": "Teste JSON", "severity": "LOW",
            "category": "Other", "language": "python", "pattern": "BAZ",
        }]),
        encoding="utf-8",
    )
    rules = _load_custom_rules()
    assert "CUSTOM-J1" in [r.id for r in rules]


def test_yaml_parser_scalars():
    items = _parse_simple_yaml_rules(
        "- id: A\n  multiline: true\n  ignorecase: false\n  num: 5\n"
    )
    assert items[0]["multiline"] is True
    assert items[0]["ignorecase"] is False
    assert items[0]["num"] == 5


# ── 4. SBOM e deps com ranges de versão ─────────────────────────────────────────

def test_sbom_parses_version_ranges():
    from analyzer.sbom import _from_requirements
    comps = _from_requirements("rich>=13.7.0,<14.0.0\nflask==2.0.0\nplain\n")
    by_name = {c.name: c.version for c in comps}
    assert by_name["rich"] == "13.7.0"
    assert by_name["flask"] == "2.0.0"


def test_deps_flags_range_below_fixed():
    from analyzer.deps import _parse_requirements
    vulns = _parse_requirements("django>=3.0\n", "requirements.txt")
    assert any(v.package == "django" for v in vulns)


def test_deps_ignores_comment_and_marker():
    from analyzer.deps import _parse_requirements
    vulns = _parse_requirements('flask==2.0.0 ; python_version < "3.8"  # comentário\n',
                                "requirements.txt")
    assert any(v.package == "flask" for v in vulns)


# ── 5. Exporters ────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_report(tmp_path):
    f = tmp_path / "vuln.py"
    f.write_text('eval(request.form["x"])\n', encoding="utf-8")
    return ScanEngine(min_severity=Severity.INFO).scan_files([str(f)])


def test_sarif_contains_severity_property(sample_report, tmp_path):
    from analyzer.reporter import export_sarif
    out = tmp_path / "r.sarif"
    export_sarif(sample_report, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    results = data["runs"][0]["results"]
    assert results, "SARIF sem resultados"
    assert "severity" in results[0]["properties"], "action.yml depende de properties.severity"


def test_json_csv_junit_markdown_badge(sample_report, tmp_path):
    from analyzer.reporter import (
        export_json, export_csv, export_junit, export_markdown, export_badge
    )
    for fn, name in [
        (export_json, "r.json"), (export_csv, "r.csv"),
        (export_junit, "r.xml"), (export_markdown, "r.md"),
        (export_badge, "r.svg"),
    ]:
        out = tmp_path / name
        fn(sample_report, str(out))
        assert out.exists() and out.stat().st_size > 0, f"{name} vazio"
    assert "<svg" in (tmp_path / "r.svg").read_text(encoding="utf-8")


# ── 6. Entropy e PII ────────────────────────────────────────────────────────────

def test_entropy_detects_high_entropy_secret():
    from analyzer.entropy import scan_entropy
    code = 'api_key = "a8Zx91Kf02Lm83Qp74Rt65Yv56Bn47"\n'
    findings = scan_entropy("s.py", code, threshold=4.0)
    assert len(findings) >= 1


def test_pii_detects_email():
    from analyzer.pii import scan_pii
    findings = scan_pii("s.py", 'email = "joao.silva@gmail.com"\n')
    assert any(f.pii_type == "Email" for f in findings)


# ── 7. Baseline ──────────────────────────────────────────────────────────────────

def test_baseline_roundtrip(sample_report, tmp_path):
    from analyzer.baseline import save_baseline, compare_with_baseline
    base = tmp_path / "base.json"
    save_baseline(sample_report, str(base))
    diff = compare_with_baseline(sample_report, str(base))
    assert diff.new_findings == []           # mesmo report → nada novo
    assert diff.unchanged_count > 0
