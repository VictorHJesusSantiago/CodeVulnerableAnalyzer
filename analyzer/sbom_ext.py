"""
Extensões de SBOM: CycloneDX 1.4 XML (complementa o JSON já existente em
analyzer/sbom.py), SPDX 2.3 JSON (complementa o tag-value já existente), e
uma "attestation" local no formato in-toto Statement.

Aviso honesto sobre a attestation: isto NÃO é Sigstore/cosign real. Uma
attestation Sigstore genuína depende de: (1) um provedor OIDC para provar
identidade, (2) a CA Fulcio emitindo um certificado de assinatura de curta
duração, e (3) o log de transparência Rekor registrando a assinatura
publicamente — nada disso funciona offline nem é implementável com stdlib
pura sem uma infraestrutura de PKI pública real. O que é implementado aqui é
uma assinatura LOCAL via HMAC-SHA256 (mesmo padrão do cofre AES deste
projeto), que prova apenas que "quem tem esta chave local produziu este
documento" — útil para uma cadeia de custódia interna, não para verificação
pública de terceiros.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import secrets
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from xml.dom import minidom

from analyzer.sbom import Component


# ════════════════════════════════════════════════════════════════════════════
#  CycloneDX 1.4 XML
# ════════════════════════════════════════════════════════════════════════════

_CDX_NS = "http://cyclonedx.org/schema/bom/1.4"


def export_cyclonedx_xml(components: List[Component], output_path: str, project_name: str = "project") -> None:
    ET.register_namespace("", _CDX_NS)
    bom = ET.Element(f"{{{_CDX_NS}}}bom", attrib={
        "version": "1", "serialNumber": f"urn:uuid:{secrets.token_hex(16)}",
    })
    metadata = ET.SubElement(bom, f"{{{_CDX_NS}}}metadata")
    timestamp = ET.SubElement(metadata, f"{{{_CDX_NS}}}timestamp")
    timestamp.text = datetime.now(timezone.utc).isoformat()
    tools = ET.SubElement(metadata, f"{{{_CDX_NS}}}tools")
    tool = ET.SubElement(tools, f"{{{_CDX_NS}}}tool")
    ET.SubElement(tool, f"{{{_CDX_NS}}}vendor").text = "CodeVulnerableAnalyzer"
    ET.SubElement(tool, f"{{{_CDX_NS}}}name").text = "vulnscan"
    ET.SubElement(tool, f"{{{_CDX_NS}}}version").text = "1.0.0"
    component_meta = ET.SubElement(metadata, f"{{{_CDX_NS}}}component", attrib={"type": "application"})
    ET.SubElement(component_meta, f"{{{_CDX_NS}}}name").text = project_name

    components_el = ET.SubElement(bom, f"{{{_CDX_NS}}}components")
    for c in components:
        comp_el = ET.SubElement(components_el, f"{{{_CDX_NS}}}component",
                                 attrib={"type": "library", "bom-ref": secrets.token_hex(8)})
        ET.SubElement(comp_el, f"{{{_CDX_NS}}}name").text = c.name
        ET.SubElement(comp_el, f"{{{_CDX_NS}}}version").text = c.version
        ET.SubElement(comp_el, f"{{{_CDX_NS}}}purl").text = c.purl

    rough = ET.tostring(bom, encoding="unicode")
    pretty = minidom.parseString(rough).toprettyxml(indent="  ")
    Path(output_path).write_text(pretty, encoding="utf-8")


# ════════════════════════════════════════════════════════════════════════════
#  SPDX 2.3 JSON
# ════════════════════════════════════════════════════════════════════════════

def export_spdx_json(components: List[Component], output_path: str, project_name: str = "project") -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": project_name,
        "documentNamespace": f"https://spdx.org/spdxdocs/{project_name}-{secrets.token_hex(8)}",
        "creationInfo": {
            "created": now,
            "creators": ["Tool: CodeVulnerableAnalyzer-vulnscan"],
        },
        "packages": [
            {
                "SPDXID": f"SPDXRef-Package-{i}",
                "name": c.name,
                "versionInfo": c.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": c.license_id,
                "licenseDeclared": c.license_id,
                "copyrightText": "NOASSERTION",
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": c.purl,
                }],
            }
            for i, c in enumerate(components)
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": f"SPDXRef-Package-{i}",
            }
            for i in range(len(components))
        ],
    }
    Path(output_path).write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")


# ════════════════════════════════════════════════════════════════════════════
#  Attestation local (formato in-toto Statement, assinatura HMAC-SHA256)
# ════════════════════════════════════════════════════════════════════════════

_PREDICATE_TYPE = "https://vulnscan.local/attestation/local-hmac/v1"


def create_local_attestation(sbom_path: str, signing_key: bytes, predicate_extra: Optional[dict] = None) -> dict:
    """Gera uma attestation no formato in-toto Statement (in-toto.io/Statement/v1)
    sobre o hash do SBOM, assinada localmente via HMAC-SHA256.

    NÃO é equivalente a uma assinatura Sigstore/cosign — ver aviso no
    docstring do módulo. Verificável apenas por quem possui 'signing_key'.
    """
    sbom_bytes = Path(sbom_path).read_bytes()
    digest = hashlib.sha256(sbom_bytes).hexdigest()

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": Path(sbom_path).name,
            "digest": {"sha256": digest},
        }],
        "predicateType": _PREDICATE_TYPE,
        "predicate": {
            "builder": {"id": "CodeVulnerableAnalyzer/vulnscan@1.0.0"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **(predicate_extra or {}),
        },
    }
    statement_bytes = json.dumps(statement, sort_keys=True).encode("utf-8")
    signature = hmac.new(signing_key, statement_bytes, hashlib.sha256).hexdigest()

    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": statement,
        "signatures": [{"keyid": hashlib.sha256(signing_key).hexdigest()[:16], "sig": signature}],
        "_disclaimer": (
            "Attestation LOCAL (HMAC-SHA256), NÃO equivalente a Sigstore/cosign. "
            "Verificável apenas por quem possui a chave de assinatura usada aqui."
        ),
    }


def verify_local_attestation(attestation: dict, signing_key: bytes) -> bool:
    statement_bytes = json.dumps(attestation["payload"], sort_keys=True).encode("utf-8")
    expected_sig = hmac.new(signing_key, statement_bytes, hashlib.sha256).hexdigest()
    actual_sig = attestation["signatures"][0]["sig"]
    return hmac.compare_digest(expected_sig, actual_sig)


def save_attestation(attestation: dict, output_path: str) -> None:
    Path(output_path).write_text(json.dumps(attestation, indent=2, ensure_ascii=False), encoding="utf-8")
