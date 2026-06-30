"""Comparação com baseline — reporta apenas novos achados em relação a scan anterior."""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Set

from analyzer.models import ScanReport


@dataclass
class BaselineDiff:
    new_findings:        List[Dict] = field(default_factory=list)
    resolved_findings:   List[Dict] = field(default_factory=list)
    regression_findings: List[Dict] = field(default_factory=list)
    unchanged_count:     int = 0

    @property
    def new_count(self) -> int:
        return len(self.new_findings)

    @property
    def resolved_count(self) -> int:
        return len(self.resolved_findings)

    @property
    def regression_count(self) -> int:
        return len(self.regression_findings)

    def is_clean(self) -> bool:
        return self.new_count == 0 and self.regression_count == 0


_SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _key(f: dict) -> tuple:
    return (f.get("rule_id", ""), f.get("file", ""), f.get("line", 0))


def load_baseline(path: str) -> List[Dict]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data.get("findings", [])
    except (json.JSONDecodeError, OSError):
        return []


def compare_with_baseline(report: ScanReport, baseline_path: str) -> BaselineDiff:
    """Compara o scan atual com o baseline JSON e retorna as diferenças."""
    baseline = load_baseline(baseline_path)
    base_keys: Set[tuple] = {_key(f) for f in baseline}
    base_sev:  Dict[tuple, str] = {_key(f): f.get("severity", "") for f in baseline}

    current: List[Dict] = []
    for result in report.results:
        for v in result.vulnerabilities:
            current.append({
                "rule_id":  v.rule_id,
                "file":     v.file_path,
                "line":     v.line_number,
                "severity": v.severity.name,
                "name":     v.name,
                "category": v.category.value,
            })

    current_keys: Set[tuple] = {_key(f) for f in current}

    new_findings      = [f for f in current  if _key(f) not in base_keys]
    resolved_findings = [f for f in baseline if _key(f) not in current_keys]
    unchanged_count   = len([f for f in current if _key(f) in base_keys])

    regression_findings: List[Dict] = []
    for f in current:
        k = _key(f)
        if k in base_sev:
            old_r = _SEV_RANK.get(base_sev[k], 0)
            new_r = _SEV_RANK.get(f.get("severity", ""), 0)
            if new_r > old_r:
                regression_findings.append({**f, "old_severity": base_sev[k]})

    return BaselineDiff(
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        regression_findings=regression_findings,
        unchanged_count=unchanged_count,
    )


def save_baseline(report: ScanReport, output_path: str) -> None:
    """Salva o scan atual como baseline JSON para comparações futuras."""
    from analyzer.reporter import export_json
    export_json(report, output_path)
