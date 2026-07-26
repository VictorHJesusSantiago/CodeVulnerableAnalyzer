"""
Nota de risco agregada do projeto (A-F), similar a ferramentas como
Code Climate/SonarQube, calculada 100% offline a partir do ScanReport.

Fórmula: penalidade ponderada por severidade e confiança, normalizada
pelo número de arquivos escaneados (arquivos maiores/mais numerosos
naturalmente acumulam mais achados, então dividimos por arquivo para
não punir só por tamanho de projeto).
"""
from __future__ import annotations

from dataclasses import dataclass

from analyzer.models import Confidence, ScanReport

_SEVERITY_WEIGHT = {
    "CRITICAL": 10.0,
    "HIGH": 5.0,
    "MEDIUM": 2.0,
    "LOW": 0.5,
    "INFO": 0.05,
}

_CONFIDENCE_WEIGHT = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.6,
    Confidence.LOW: 0.3,
}

# Limiares de penalidade-por-arquivo -> nota. Calibrado para que um
# projeto limpo (0 achados) seja A e que poucos CRITICAL por arquivo
# já derrubem para D/F.
_GRADE_THRESHOLDS = (
    (0.5, "A"),
    (2.0, "B"),
    (5.0, "C"),
    (10.0, "D"),
)


@dataclass
class RiskGrade:
    grade: str
    score: float          # penalidade ponderada por arquivo (quanto menor, melhor)
    penalty_total: float
    files_scanned: int

    @property
    def label(self) -> str:
        # Delega ao sistema de i18n (SSOT) em vez de duplicar os rótulos aqui,
        # para respeitar o locale ativo (--locale) e não divergir de reporter.py.
        from analyzer.i18n import t
        return t({
            "A": "grade_excellent",
            "B": "grade_good",
            "C": "grade_fair",
            "D": "grade_bad",
            "F": "grade_critical",
        }[self.grade])


def compute_risk_grade(report: ScanReport) -> RiskGrade:
    penalty_total = 0.0
    for result in report.results:
        for vuln in result.vulnerabilities:
            sev_w = _SEVERITY_WEIGHT.get(vuln.severity.name, 0.1)
            conf_w = _CONFIDENCE_WEIGHT.get(vuln.confidence, 0.6)
            penalty_total += sev_w * conf_w

    files = max(1, report.files_scanned)
    score = penalty_total / files

    grade = "F"
    for threshold, letter in _GRADE_THRESHOLDS:
        if score <= threshold:
            grade = letter
            break

    return RiskGrade(grade=grade, score=round(score, 3), penalty_total=round(penalty_total, 2), files_scanned=files)
