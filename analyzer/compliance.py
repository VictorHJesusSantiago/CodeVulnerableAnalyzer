"""Catálogo, mapeamento, gap analysis, evidências e score de maturidade."""
from __future__ import annotations
import hashlib, json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

# Mapeamentos baseados nas publicações oficiais de cada framework (OWASP Top
# 10 2021, ASVS v4.0, PCI-DSS v4.0, NIST SP 800-53 Rev.5, ISO/IEC 27001:2022
# Anexo A, CWE Top 25 2023 da MITRE, MITRE ATT&CK/CAPEC). Cobertura ampliada
# e real, mas ainda NÃO é exaustiva de toda cláusula/subcontrole de cada
# norma — isso exigiria manutenção contínua por um time de compliance
# dedicado, não uma tabela estática de código.
FRAMEWORKS = {
 "OWASP": {  # OWASP Top 10 2021 (A01-A10)
    "A01:2021 Broken Access Control":            ["CWE-284","CWE-639","CWE-862","CWE-863","CWE-306","CWE-269"],
    "A02:2021 Cryptographic Failures":            ["CWE-327","CWE-328","CWE-338","CWE-311","CWE-319","CWE-295"],
    "A03:2021 Injection":                         ["CWE-78","CWE-89","CWE-79","CWE-94","CWE-95","CWE-611","CWE-77"],
    "A04:2021 Insecure Design":                    ["CWE-1173","CWE-657","CWE-841"],
    "A05:2021 Security Misconfiguration":          ["CWE-16","CWE-1188","CWE-614","CWE-732"],
    "A06:2021 Vulnerable and Outdated Components": ["CWE-1104","CWE-937"],
    "A07:2021 Identification and Auth Failures":   ["CWE-287","CWE-306","CWE-798","CWE-521","CWE-613"],
    "A08:2021 Software and Data Integrity Failures": ["CWE-502","CWE-829","CWE-494"],
    "A09:2021 Security Logging and Monitoring Failures": ["CWE-778","CWE-223","CWE-532"],
    "A10:2021 Server-Side Request Forgery":        ["CWE-918"],
 },
 "ASVS": {  # OWASP ASVS v4.0 (categorias V1-V14, resumidas)
    "V2 Authentication":            ["CWE-287","CWE-521","CWE-307","CWE-798"],
    "V3 Session Management":        ["CWE-613","CWE-614","CWE-384"],
    "V4 Access Control":            ["CWE-284","CWE-639","CWE-862","CWE-863"],
    "V5 Validation, Sanitization":  ["CWE-20","CWE-89","CWE-79","CWE-78","CWE-94"],
    "V6 Stored Cryptography":       ["CWE-327","CWE-328","CWE-338","CWE-798"],
    "V7 Error Handling and Logging":["CWE-209","CWE-532","CWE-778"],
    "V8 Data Protection":           ["CWE-311","CWE-319","CWE-359"],
    "V9 Communications":            ["CWE-295","CWE-319","CWE-326"],
    "V10 Malicious Code":           ["CWE-506","CWE-829"],
    "V12 Files and Resources":      ["CWE-22","CWE-434","CWE-611"],
    "V14 Configuration":            ["CWE-16","CWE-1188","CWE-489"],
 },
 "PCI-DSS": {  # PCI-DSS v4.0 (requisitos principais)
    "3.5 Proteção de dados armazenados (crypto)": ["CWE-311","CWE-327","CWE-338"],
    "4.2 Criptografia em trânsito":               ["CWE-319","CWE-295","CWE-326"],
    "6.2.4 Prevenção de vulnerabilidades comuns (injection)": ["CWE-79","CWE-89","CWE-78","CWE-94"],
    "6.3.1 Gestão de vulnerabilidades e patches":  ["CWE-1104","CWE-937"],
    "7.2 Controle de acesso baseado em necessidade": ["CWE-284","CWE-862","CWE-863"],
    "8.3 Autenticação forte":                      ["CWE-287","CWE-521","CWE-307"],
    "10.2 Trilhas de auditoria":                    ["CWE-778","CWE-223"],
 },
 "HIPAA": {  # HIPAA Security Rule (45 CFR 164.312)
    "164.312(a) Controle de Acesso":                ["CWE-284","CWE-862","CWE-306"],
    "164.312(b) Auditoria (Audit Controls)":        ["CWE-778","CWE-223"],
    "164.312(c) Integridade":                       ["CWE-502","CWE-353"],
    "164.312(d) Autenticação de Pessoa/Entidade":   ["CWE-287","CWE-798"],
    "164.312(e) Segurança de Transmissão":          ["CWE-319","CWE-295"],
 },
 "GDPR-LGPD": {  # GDPR (UE) / LGPD (Brasil) — artigos correspondentes
    "Art.5 Princípios (minimização/integridade)":   ["CWE-359","CWE-200"],
    "Art.25 Privacy by Design/Default":             ["CWE-359","CWE-284"],
    "Art.32 Segurança do Tratamento":               ["CWE-311","CWE-319","CWE-327","CWE-798"],
    "Art.33 Notificação de Violação":               ["CWE-778","CWE-223"],
 },
 "SOC2": {  # SOC 2 Trust Services Criteria
    "CC6 Controles de Acesso Lógico":               ["CWE-284","CWE-287","CWE-862"],
    "CC7 Operações de Sistema (detecção/resposta)": ["CWE-778","CWE-223"],
    "CC8 Gestão de Mudanças":                       ["CWE-1104"],
    "CC9 Mitigação de Riscos":                      ["CWE-937"],
 },
 "ISO27001": {  # ISO/IEC 27001:2022 Anexo A (controles tecnológicos, seleção)
    "A.8.2 Direitos de Acesso Privilegiado":        ["CWE-269","CWE-284"],
    "A.8.5 Autenticação Segura":                    ["CWE-287","CWE-521","CWE-307"],
    "A.8.9 Gestão de Configuração":                 ["CWE-16","CWE-1188"],
    "A.8.24 Uso de Criptografia":                   ["CWE-311","CWE-327","CWE-338"],
    "A.8.25 Ciclo de Vida de Desenvolvimento Seguro": ["CWE-1104","CWE-937"],
    "A.8.26 Requisitos de Segurança em Aplicações": ["CWE-20","CWE-89","CWE-79","CWE-78"],
    "A.8.28 Codificação Segura":                    ["CWE-94","CWE-502","CWE-798"],
 },
 "NIST": {  # NIST SP 800-53 Rev. 5 (famílias de controle, seleção)
    "AC Access Control":                            ["CWE-284","CWE-862","CWE-863","CWE-306"],
    "AU Audit and Accountability":                  ["CWE-778","CWE-223"],
    "IA Identification and Authentication":         ["CWE-287","CWE-798","CWE-521"],
    "SC System and Communications Protection":      ["CWE-311","CWE-319","CWE-327"],
    "SI System and Information Integrity":          ["CWE-20","CWE-502","CWE-829"],
    "CM Configuration Management":                  ["CWE-16","CWE-1188"],
 },
 "FedRAMP": {  # Baseline construída sobre NIST 800-53 (mesmas famílias)
    "AC Access Control":                    ["CWE-284","CWE-862"],
    "SC System and Comms Protection":       ["CWE-311","CWE-319","CWE-327"],
    "IA Identification and Authentication": ["CWE-287","CWE-798"],
    "SI System and Information Integrity":  ["CWE-502","CWE-829"],
 },
 "MITRE": {  # MITRE ATT&CK — técnicas relevantes a vulnerabilidades de código
    "T1190 Exploit Public-Facing Application": ["CWE-20","CWE-89","CWE-79","CWE-78","CWE-94"],
    "T1552 Unsecured Credentials":             ["CWE-798","CWE-522","CWE-256"],
    "T1499 Endpoint Denial of Service":        ["CWE-400","CWE-835"],
    "T1078 Valid Accounts (comprometidas)":    ["CWE-287","CWE-521"],
    "T1611 Escape to Host (containers)":       ["CWE-269","CWE-284"],
 },
 "CAPEC": {  # Common Attack Pattern Enumeration and Classification
    "CAPEC-66 SQL Injection":            ["CWE-89"],
    "CAPEC-242 Code Injection":          ["CWE-94","CWE-95"],
    "CAPEC-88 OS Command Injection":     ["CWE-78","CWE-77"],
    "CAPEC-126 Path Traversal":          ["CWE-22"],
    "CAPEC-63 Cross-Site Scripting":     ["CWE-79"],
    "CAPEC-586 Object Injection":        ["CWE-502"],
    "CAPEC-115 Authentication Bypass":   ["CWE-287","CWE-306"],
 },
 "CWE-TOP-25": {  # CWE Top 25 Most Dangerous Software Weaknesses 2023 (MITRE)
    "1º CWE-787 Out-of-bounds Write":      ["CWE-787"],
    "2º CWE-79 Cross-site Scripting":      ["CWE-79"],
    "3º CWE-89 SQL Injection":             ["CWE-89"],
    "4º CWE-416 Use After Free":           ["CWE-416"],
    "5º CWE-78 OS Command Injection":      ["CWE-78"],
    "6º CWE-20 Improper Input Validation": ["CWE-20"],
    "7º CWE-125 Out-of-bounds Read":       ["CWE-125"],
    "8º CWE-22 Path Traversal":            ["CWE-22"],
    "9º CWE-352 CSRF":                     ["CWE-352"],
    "10º CWE-434 Unrestricted Upload":     ["CWE-434"],
    "11º CWE-862 Missing Authorization":   ["CWE-862"],
    "12º CWE-476 NULL Pointer Deref":      ["CWE-476"],
    "13º CWE-287 Improper Authentication": ["CWE-287"],
    "14º CWE-190 Integer Overflow":        ["CWE-190"],
    "15º CWE-502 Deserialization Insegura":["CWE-502"],
    "16º CWE-77 Command Injection":        ["CWE-77"],
    "18º CWE-798 Hardcoded Credentials":   ["CWE-798"],
    "19º CWE-918 SSRF":                    ["CWE-918"],
    "22º CWE-269 Improper Privilege Mgmt": ["CWE-269"],
    "23º CWE-94 Code Injection":           ["CWE-94"],
 },
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
