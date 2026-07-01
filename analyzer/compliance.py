"""Catálogo, mapeamento, gap analysis, evidências e score de maturidade."""
from __future__ import annotations
import hashlib, json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

FRAMEWORKS = {
 "OWASP": {"A01": ["CWE-284","CWE-639"], "A03": ["CWE-78","CWE-89","CWE-79"]},
 "ASVS": {"V4": ["CWE-284","CWE-639"], "V5": ["CWE-20","CWE-89"]},
 "PCI-DSS": {"6.2.4": ["CWE-79","CWE-89","CWE-78"], "8.3": ["CWE-287"]},
 "HIPAA": {"164.312(a)": ["CWE-284"], "164.312(e)": ["CWE-319"]},
 "GDPR-LGPD": {"Art.32/46": ["CWE-311","CWE-319"], "Art.25/46": ["CWE-359"]},
 "SOC2": {"CC6": ["CWE-284","CWE-287"], "CC7": ["CWE-778"]},
 "ISO27001": {"A.8.26": ["CWE-20","CWE-89"], "A.8.24": ["CWE-311"]},
 "NIST": {"AC": ["CWE-284","CWE-287"], "SI-10": ["CWE-20"], "AU": ["CWE-778"]},
 "FedRAMP": {"AC": ["CWE-284"], "SC": ["CWE-311","CWE-319"]},
 "MITRE": {"T1190": ["CWE-20","CWE-89"], "T1552": ["CWE-798"]},
 "CAPEC": {"CAPEC-66": ["CWE-89"], "CAPEC-242": ["CWE-78"]},
 "CWE-TOP-25": {"Injection": ["CWE-78","CWE-79","CWE-89"], "Access": ["CWE-284","CWE-639"]},
}

def map_finding(finding: Dict[str, Any]) -> Dict[str, List[str]]:
    cwe = finding.get("cwe", "")
    return {fw: [control for control, cwes in controls.items() if cwe in cwes]
            for fw, controls in FRAMEWORKS.items() if any(cwe in c for c in controls.values())}

def compliance_report(findings: Iterable[Dict[str, Any]], framework: str) -> Dict[str, Any]:
    controls = FRAMEWORKS[framework]
    rows = []
    findings = list(findings)
    for control, cwes in controls.items():
        related = [f for f in findings if f.get("cwe") in cwes]
        rows.append({"control": control, "status": "fail" if related else "pass",
                     "findings": [f.get("rule_id", "unknown") for f in related]})
    passed = sum(r["status"] == "pass" for r in rows)
    return {"framework": framework, "score": round(100 * passed / max(1, len(rows)), 1),
            "controls": rows, "gaps": [r["control"] for r in rows if r["status"] == "fail"]}

def audit_evidence(payload: Dict[str, Any], actor: str = "vulnscan") -> Dict[str, Any]:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "actor": actor,
            "sha256": hashlib.sha256(canonical.encode()).hexdigest(), "payload": payload}

def maturity_score(metrics: Dict[str, float]) -> Dict[str, Any]:
    dimensions = ("governance", "design", "implementation", "verification", "operations")
    values = {d: max(0, min(5, float(metrics.get(d, 0)))) for d in dimensions}
    score = round(sum(values.values()) / len(values), 2)
    return {"score": score, "level": min(5, int(score) + (score > 0)), "dimensions": values,
            "model": "OWASP SAMM/BSIMM-inspired"}

class PolicyDSL:
    """DSL: ``deny|warn <campo> <op> <valor> : mensagem``."""
    OPS = {"==": lambda a,b: a == b, "!=": lambda a,b: a != b,
           "contains": lambda a,b: b in (a or []), "exists": lambda a,b: a is not None}
    def __init__(self, source: str):
        self.rules = []
        for n, line in enumerate(source.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"): continue
            expr, _, message = line.partition(":")
            parts = expr.split(maxsplit=3)
            if len(parts) < 3 or parts[0] not in ("deny","warn") or parts[2] not in self.OPS:
                raise ValueError(f"Política inválida na linha {n}")
            self.rules.append((parts[0], parts[1], parts[2], parts[3] if len(parts)>3 else "", message.strip()))
    def evaluate(self, document: Dict[str, Any]) -> List[Dict[str, str]]:
        out = []
        for effect, field, op, expected, message in self.rules:
            value: Any = document
            for key in field.split("."):
                value = value.get(key) if isinstance(value, dict) else None
            expected = expected.strip()
            expected = {"true": True, "false": False, "null": None}.get(expected.lower(), expected)
            if self.OPS[op](value, expected):
                out.append({"effect": effect, "field": field, "message": message or f"{field} viola a política"})
        return out
