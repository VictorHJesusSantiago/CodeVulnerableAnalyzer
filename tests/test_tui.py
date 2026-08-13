"""
Testes das funções puras de estado da TUI (analyzer.tui.TUIApp): filtragem,
ordenação, agrupamento, estado de revisão e ciclo de severidade.

A renderização (rich) e o loop interativo de teclado não são cobertos por unit
tests — exigiriam um harness de terminal. Aqui cobrimos a LÓGICA que decide o
que é exibido, que é o que realmente importa para correção.
"""

from __future__ import annotations

import analyzer.tui as tui_mod
from analyzer.models import (
    Confidence,
    Language,
    ScanReport,
    ScanResult,
    Severity,
    VulnCategory,
    Vulnerability,
)
from analyzer.tui import TUIApp


def _v(rule_id, sev, path, line, cat=VulnCategory.SQL_INJECTION, lang=Language.PYTHON, name="Nome"):
    return Vulnerability(
        rule_id=rule_id,
        name=name,
        description="desc",
        severity=sev,
        category=cat,
        language=lang,
        file_path=path,
        line_number=line,
        line_content="",
        remediation="",
        confidence=Confidence.HIGH,
    )


def _report(vulns):
    res = ScanResult(file_path="f.py", language=Language.PYTHON, vulnerabilities=vulns, lines_scanned=10, scan_time=0.1)
    return ScanReport(
        results=[res],
        total_time=0.1,
        files_scanned=1,
        files_with_issues=1,
        total_vulnerabilities=len(vulns),
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        info_count=0,
        target="t",
    )


def _app(tmp_path, vulns):
    app = TUIApp(tmp_path)
    app.report = _report(vulns)
    return app


def test_fvulns_empty_without_report(tmp_path):
    app = TUIApp(tmp_path)
    assert app._fvulns() == []


def test_fvulns_severity_filter(tmp_path):
    app = _app(tmp_path, [_v("A", Severity.CRITICAL, "a.py", 1), _v("B", Severity.LOW, "b.py", 2)])
    app.sev_filter = Severity.CRITICAL
    out = app._fvulns()
    assert [v.rule_id for v in out] == ["A"]


def test_fvulns_search_query(tmp_path):
    app = _app(
        tmp_path,
        [
            _v("SQLI", Severity.HIGH, "login.py", 1, name="SQL Injection"),
            _v("XSS", Severity.HIGH, "view.py", 2, name="Cross Site"),
        ],
    )
    app.search_query = "login"
    assert [v.rule_id for v in app._fvulns()] == ["SQLI"]


def test_fvulns_hide_reviewed(tmp_path):
    v1, v2 = _v("A", Severity.HIGH, "a.py", 1), _v("B", Severity.HIGH, "b.py", 2)
    app = _app(tmp_path, [v1, v2])
    app._toggle_reviewed(v1)
    app.hide_reviewed = True
    assert [v.rule_id for v in app._fvulns()] == ["B"]


def test_fvulns_sort_by_file(tmp_path):
    app = _app(tmp_path, [_v("A", Severity.LOW, "z.py", 1), _v("B", Severity.LOW, "a.py", 1)])
    app.sort_idx = tui_mod._SORT_MODES.index("file")
    assert [v.file_path for v in app._fvulns()] == ["a.py", "z.py"]


def test_group_key_modes(tmp_path):
    app = _app(tmp_path, [])
    v = _v("A", Severity.HIGH, "dir/app.py", 1, cat=VulnCategory.XSS, lang=Language.PYTHON)
    app.group_idx = tui_mod._GROUP_MODES.index("file")
    assert app._group_key(v) == "app.py"
    app.group_idx = tui_mod._GROUP_MODES.index("category")
    assert app._group_key(v) == VulnCategory.XSS.value
    app.group_idx = tui_mod._GROUP_MODES.index("language")
    assert app._group_key(v) == "Python"


def test_vuln_key_is_identity_tuple(tmp_path):
    v = _v("R", Severity.HIGH, "a.py", 42)
    assert TUIApp._vuln_key(v) == ("R", "a.py", 42)


def test_reviewed_persistence_roundtrip(tmp_path):
    v = _v("R", Severity.HIGH, "a.py", 5)
    app = _app(tmp_path, [v])
    assert app._is_reviewed(v) is False
    app._toggle_reviewed(v)
    assert app._is_reviewed(v) is True
    assert (tmp_path / ".vulnscan_reviewed.json").exists()

    app2 = TUIApp(tmp_path)
    assert app2._is_reviewed(v) is True

    app2._toggle_reviewed(v)
    assert app2._is_reviewed(v) is False
    assert not (tmp_path / ".vulnscan_reviewed.json").exists()


def test_cycle_sev(tmp_path):
    app = TUIApp(tmp_path)
    assert app.sev_filter is None
    app._cycle_sev()
    assert app.sev_filter == Severity.CRITICAL
    app._cycle_sev()
    assert app.sev_filter == Severity.HIGH
    for _ in range(4):
        app._cycle_sev()
    assert app.sev_filter is None


def test_rule_count_positive(tmp_path):
    assert TUIApp._rule_count() > 100
