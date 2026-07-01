"""
Detecção e decodificação de JWT (JSON Web Token) — stdlib puro (base64+json).

Detecta tokens no formato header.payload.signature, decodifica header e
payload (sem verificar assinatura — não temos a chave), e sinaliza:
  - alg: none (token não assinado, aceito por implementações mal configuradas)
  - algoritmos fracos (HS256 com chave curta não é detectável sem a chave,
    mas RS/ES vs HS confusion attack é sinalizável estruturalmente)
  - exp ausente (token sem expiração)
  - claims sensíveis no payload (senha, segredo, etc. — não deveriam estar
    num JWT, que é apenas base64, não criptografado)
"""
from __future__ import annotations
import base64
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_JWT_RE = re.compile(r'\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*')

_SENSITIVE_CLAIM_KEYS = {"password", "senha", "secret", "api_key", "private_key", "credit_card"}


@dataclass
class JWTFinding:
    file_path: str
    line_number: int
    token_preview: str
    header: Optional[Dict[str, Any]]
    payload: Optional[Dict[str, Any]]
    issues: List[str] = field(default_factory=list)


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_jwt(token: str) -> Optional[Dict[str, Optional[dict]]]:
    """Decodifica header e payload de um JWT (sem verificar assinatura)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception:
        return None
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        payload = None
    return {"header": header, "payload": payload}


def _analyze_issues(header: Dict[str, Any], payload: Optional[Dict[str, Any]]) -> List[str]:
    issues: List[str] = []
    alg = str(header.get("alg", "")).lower()

    if alg == "none":
        issues.append("alg=none — token não assinado; qualquer cliente pode forjar claims arbitrários")
    elif alg in ("hs256", "hs384", "hs512") and header.get("kid") is None:
        pass  # não é possível avaliar força da chave sem a chave em si
    elif alg in ("rs256", "rs384", "rs512", "es256", "es384", "es512", "ps256", "ps384", "ps512"):
        pass  # assimétrico — íntegro estruturalmente sem checagem de chave

    if not alg:
        issues.append("Header sem campo 'alg' — implementação pode aceitar algoritmo arbitrário (algorithm confusion)")

    if payload is not None:
        if "exp" not in payload:
            issues.append("Claim 'exp' ausente — token sem expiração (nunca expira)")
        else:
            try:
                exp_ts = float(payload["exp"])
                if datetime.now(timezone.utc).timestamp() > exp_ts:
                    issues.append("Token já expirado (claim 'exp' no passado) — presente no código-fonte é suspeito")
            except (TypeError, ValueError):
                issues.append("Claim 'exp' com formato inválido")

        sensitive_found = [k for k in payload if str(k).lower() in _SENSITIVE_CLAIM_KEYS]
        if sensitive_found:
            issues.append(f"Claims sensíveis no payload (JWT NÃO é criptografado, apenas codificado): {', '.join(sensitive_found)}")

    return issues


def scan_jwt(file_path: str, content: str) -> List[JWTFinding]:
    findings: List[JWTFinding] = []
    for m in _JWT_RE.finditer(content):
        token = m.group(0)
        decoded = decode_jwt(token)
        if decoded is None or decoded["header"] is None:
            continue
        line_number = content[:m.start()].count("\n") + 1
        issues = _analyze_issues(decoded["header"], decoded["payload"])
        findings.append(JWTFinding(
            file_path=file_path, line_number=line_number,
            token_preview=token[:24] + "...",
            header=decoded["header"], payload=decoded["payload"],
            issues=issues,
        ))
    return findings
