"""
VEX (Vulnerability Exploitability eXchange) — formato OpenVEX-like em JSON.
Permite declarar, para uma combinação (produto, CVE), um status de
exploitabilidade real:
  - not_affected      : o código vulnerável não é alcançável/usado
  - affected          : vulnerável e ainda sem mitigação
  - fixed             : já corrigido (versão atualizada)
  - under_investigation

Um documento VEX pode então ser usado para SUPRIMIR do relatório de
dependências vulneráveis os achados marcados como not_affected/fixed,
reduzindo ruído sem esconder a informação (ela fica registrada no VEX,
com a justificativa).
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

_VALID_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}
_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}


@dataclass
class VexStatement:
    vulnerability: str          # ex.: "CVE-2023-1234"
    product: str                # nome do pacote/componente afetado
    status: str                 # not_affected | affected | fixed | under_investigation
    justification: Optional[str] = None
    impact_statement: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        if self.status not in _VALID_STATUSES:
            raise ValueError(f"Status VEX inválido: {self.status}")
        if self.justification and self.justification not in _JUSTIFICATIONS:
            raise ValueError(f"Justificativa VEX inválida: {self.justification}")


class VexDocument:
    def __init__(self, author: str = "vulnscan"):
        self.author = author
        self.statements: List[VexStatement] = []

    def add_statement(self, stmt: VexStatement) -> None:
        self.statements.append(stmt)

    def status_for(self, cve_id: str, product: str) -> Optional[VexStatement]:
        for s in self.statements:
            if s.vulnerability == cve_id and s.product == product:
                return s
        return None

    def to_dict(self) -> dict:
        return {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": f"vulnscan-vex-{int(datetime.now(timezone.utc).timestamp())}",
            "author": self.author,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": 1,
            "statements": [
                {
                    "vulnerability": {"name": s.vulnerability},
                    "products": [{"@id": s.product}],
                    "status": s.status,
                    **({"justification": s.justification} if s.justification else {}),
                    **({"impact_statement": s.impact_statement} if s.impact_statement else {}),
                    "timestamp": s.timestamp,
                }
                for s in self.statements
            ],
        }

    def save(self, path: str) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, path: str) -> "VexDocument":
        doc = cls()
        p = Path(path)
        if not p.exists():
            return doc
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return doc
        doc.author = data.get("author", "vulnscan")
        for stmt in data.get("statements", []):
            vuln = stmt.get("vulnerability", {}).get("name", "")
            products = stmt.get("products", [])
            product = products[0].get("@id", "") if products else ""
            try:
                doc.add_statement(VexStatement(
                    vulnerability=vuln, product=product, status=stmt.get("status", "affected"),
                    justification=stmt.get("justification"),
                    impact_statement=stmt.get("impact_statement"),
                    timestamp=stmt.get("timestamp", ""),
                ))
            except ValueError:
                continue
        return doc


def suppress_by_vex(dep_vulns: list, vex: VexDocument) -> tuple:
    """Recebe uma lista de DepVuln (de analyzer/deps.py) e um VexDocument;
    retorna (mantidos, suprimidos) — suprimidos são os marcados not_affected
    ou fixed no VEX."""
    kept, suppressed = [], []
    for v in dep_vulns:
        stmt = vex.status_for(v.cve_id, v.package)
        if stmt and stmt.status in ("not_affected", "fixed"):
            suppressed.append((v, stmt))
        else:
            kept.append(v)
    return kept, suppressed
