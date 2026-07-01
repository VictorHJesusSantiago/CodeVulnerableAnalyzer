"""
Baseline/allowlist de segredos por fingerprint — análogo ao baseline.py
(usado para vulnerabilidades), mas dedicado a achados de segredos. Permite:
  - Salvar um baseline com todos os segredos encontrados hoje (aceitos como
    "conhecidos"/falsos-positivos/rotacionados).
  - Em scans futuros, suprimir achados cujo fingerprint já está no baseline,
    mostrando apenas segredos GENUINAMENTE NOVOS.

Fingerprint = SHA-256 de (arquivo relativo, linha, provedor, valor mascarado)
— não armazena o segredo em texto plano no baseline, apenas o hash e uma
versão mascarada para auditoria humana.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def fingerprint(file_path: str, line_number: int, provider: str, matched: str) -> str:
    raw = f"{file_path}:{line_number}:{provider}:{matched}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class SecretBaselineEntry:
    fingerprint: str
    file_path: str
    line_number: int
    provider: str
    secret_type: str
    masked_value: str
    status: str = "accepted"  # accepted | rotated | false_positive


@dataclass
class SecretsDiff:
    new_secrets: List[dict] = field(default_factory=list)
    resolved_secrets: List[str] = field(default_factory=list)
    unchanged_count: int = 0


def load_secrets_baseline(path: str) -> Dict[str, SecretBaselineEntry]:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    entries = {}
    for item in data.get("secrets", []):
        entry = SecretBaselineEntry(**item)
        entries[entry.fingerprint] = entry
    return entries


def save_secrets_baseline(path: str, findings: List[dict]) -> None:
    """findings: lista de dicts com file_path, line_number, provider,
    secret_type, matched (mesmo formato retornado pelos scanners deste projeto)."""
    entries = []
    for f in findings:
        fp = fingerprint(f["file_path"], f.get("line_number", 0), f["provider"], f["matched"])
        entries.append({
            "fingerprint": fp,
            "file_path": f["file_path"],
            "line_number": f.get("line_number", 0),
            "provider": f["provider"],
            "secret_type": f["secret_type"],
            "masked_value": _mask(f["matched"]),
            "status": "accepted",
        })
    doc = {"version": 1, "secrets": entries}
    Path(path).write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")


def filter_new_secrets(findings: List[dict], baseline_path: str) -> SecretsDiff:
    """Retorna apenas os achados cujo fingerprint NÃO está no baseline."""
    baseline = load_secrets_baseline(baseline_path)
    baseline_fps: Set[str] = set(baseline.keys())
    seen_fps: Set[str] = set()

    diff = SecretsDiff()
    for f in findings:
        fp = fingerprint(f["file_path"], f.get("line_number", 0), f["provider"], f["matched"])
        seen_fps.add(fp)
        if fp in baseline_fps:
            diff.unchanged_count += 1
        else:
            diff.new_secrets.append(f)

    diff.resolved_secrets = sorted(baseline_fps - seen_fps)
    return diff
