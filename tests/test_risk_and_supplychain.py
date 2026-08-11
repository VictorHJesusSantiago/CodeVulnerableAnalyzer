"""Testes de risk_grade (nota agregada) e supplychain_sources (clientes de advisory)."""

from __future__ import annotations

import json

from analyzer.models import (
    Confidence,
    Language,
    ScanReport,
    ScanResult,
    Severity,
    VulnCategory,
    Vulnerability,
)

# ══════════════════════════════════════════════════════════════════════════════
#  risk_grade
# ══════════════════════════════════════════════════════════════════════════════
from analyzer.risk_grade import compute_risk_grade


def _vuln(sev: Severity, conf: Confidence = Confidence.HIGH) -> Vulnerability:
    return Vulnerability(
        rule_id="R",
        name="n",
        description="d",
        severity=sev,
        category=VulnCategory.OTHER,
        language=Language.PYTHON,
        file_path="f",
        line_number=1,
        line_content="",
        remediation="",
        confidence=conf,
    )


def _report(vulns, files_scanned=1) -> ScanReport:
    res = ScanResult(file_path="f", language=Language.PYTHON, vulnerabilities=vulns, lines_scanned=10, scan_time=0.1)
    sev_counts = {s: 0 for s in Severity}
    for v in vulns:
        sev_counts[v.severity] += 1
    return ScanReport(
        results=[res],
        total_time=0.1,
        files_scanned=files_scanned,
        files_with_issues=1 if vulns else 0,
        total_vulnerabilities=len(vulns),
        critical_count=sev_counts[Severity.CRITICAL],
        high_count=sev_counts[Severity.HIGH],
        medium_count=sev_counts[Severity.MEDIUM],
        low_count=sev_counts[Severity.LOW],
        info_count=sev_counts[Severity.INFO],
        target="t",
    )


def test_risk_grade_clean_project_is_a():
    grade = compute_risk_grade(_report([]))
    assert grade.grade == "A"
    assert grade.penalty_total == 0.0
    assert grade.label  # rótulo i18n preenchido


def test_risk_grade_critical_drops_grade():
    # 1 CRITICAL (peso 10) * confiança HIGH (1.0) / 1 arquivo = 10.0 → F (>10 é F, ==10 é D)
    grade = compute_risk_grade(_report([_vuln(Severity.CRITICAL)]))
    assert grade.grade in ("D", "F")
    assert grade.score >= 5.0
    assert grade.files_scanned == 1


def test_risk_grade_normalized_by_file_count():
    # Mesma penalidade diluída por muitos arquivos → nota melhor
    vulns = [_vuln(Severity.LOW, Confidence.LOW) for _ in range(2)]
    good = compute_risk_grade(_report(vulns, files_scanned=100))
    assert good.grade == "A"


def test_risk_grade_label_localized():
    from analyzer import i18n

    grade = compute_risk_grade(_report([]))
    i18n.set_locale("en")
    assert grade.label == "Excellent"
    i18n.set_locale("pt")
    assert grade.label == "Excelente"


# ══════════════════════════════════════════════════════════════════════════════
#  supplychain_sources (urlopen mockado — sem rede real)
# ══════════════════════════════════════════════════════════════════════════════
import analyzer.supplychain_sources as scs


class _Resp:
    def __init__(self, doc):
        self._doc = doc

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return json.dumps(self._doc).encode("utf-8")


def _patch(monkeypatch, doc):
    monkeypatch.setattr(scs.urllib.request, "urlopen", lambda req, timeout=None: _Resp(doc))


def test_query_deps_dev(monkeypatch):
    _patch(monkeypatch, {"advisoryKeys": [{"advisoryKey": {"id": "GHSA-abc"}}]})
    advs = scs.query_deps_dev("pypi", "requests", "2.0.0")
    assert len(advs) == 1
    assert advs[0].id == "GHSA-abc" and advs[0].source == "deps.dev"


def test_query_nvd_extracts_severity(monkeypatch):
    _patch(
        monkeypatch,
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-1",
                        "descriptions": [{"lang": "en", "value": "boom"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
                    }
                }
            ]
        },
    )
    advs = scs.query_nvd("cpe:2.3:a:x:y:1.0")
    assert advs[0].id == "CVE-2021-1"
    assert advs[0].severity == "HIGH"
    assert advs[0].summary == "boom"


def test_query_github_advisories(monkeypatch):
    _patch(monkeypatch, [{"ghsa_id": "GHSA-xyz", "severity": "high", "summary": "s"}])
    advs = scs.query_github_advisories("pip", "requests", "tok")
    assert advs[0].id == "GHSA-xyz"
    assert advs[0].severity == "HIGH"  # .upper()


def test_query_oss_index(monkeypatch):
    _patch(
        monkeypatch,
        [
            {
                "coordinates": "pkg:pypi/requests@2.0.0",
                "vulnerabilities": [{"id": "OSS-1", "cvssScore": 7.5, "title": "t"}],
            }
        ],
    )
    advs = scs.query_oss_index(["pkg:pypi/requests@2.0.0"], "user", "tok")
    assert advs[0].id == "OSS-1" and advs[0].source == "OSS Index"
