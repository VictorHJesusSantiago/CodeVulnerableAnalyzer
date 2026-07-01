"""Scanners sem dependências para Dockerfile, Compose e camadas OCI."""
from __future__ import annotations
import json, re, tarfile
from pathlib import Path
from typing import Any, Dict, List

def scan_dockerfile(text: str) -> List[Dict[str, Any]]:
    findings, user_seen = [], False
    add = lambda rid, sev, line, msg: findings.append({"rule_id": rid, "severity": sev, "line": line, "message": msg})
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if re.match(r"USER\s+\S+", line, re.I): user_seen = not bool(re.match(r"USER\s+(?:0|root)\b", line, re.I))
        if re.match(r"FROM\s+\S+:latest\b", line, re.I): add("DOCKER-BP-001", "medium", n, "Imagem base usa tag latest")
        if re.match(r"ADD\s+https?://", line, re.I): add("DOCKER-BP-002", "high", n, "ADD remoto sem verificação de integridade")
        if re.search(r"COPY\s+.*(?:\.env|id_rsa|\.pem|credentials|secret)", line, re.I): add("DOCKER-BP-003", "critical", n, "Possível segredo copiado para a imagem")
        if re.match(r"RUN\s+.*(?:apt-get|apk|yum).*(?:install)", line, re.I) and not re.search(r"(?:rm -rf /var/lib/apt/lists|--no-cache)", line):
            add("DOCKER-BP-004", "low", n, "Camada mantém cache do gerenciador de pacotes")
    if not user_seen: add("DOCKER-BP-005", "high", len(text.splitlines()) or 1, "Imagem termina executando como root")
    return findings

def scan_compose(doc: str | Dict[str, Any]) -> List[Dict[str, Any]]:
    if isinstance(doc, str):
        try: data = json.loads(doc)
        except json.JSONDecodeError:
            data = _simple_yaml(doc)
    else: data = doc
    out = []
    for name, svc in data.get("services", {}).items():
        for rule, condition, message in [
            ("COMPOSE-001", svc.get("privileged") is True, "Container privilegiado"),
            ("COMPOSE-002", svc.get("network_mode") == "host", "Rede do host compartilhada"),
            ("COMPOSE-003", not svc.get("read_only", False), "Filesystem raiz gravável"),
        ]:
            if condition: out.append({"rule_id": rule, "service": name, "severity": "high", "message": message})
    return out

def scan_oci_archive(path: str | Path) -> List[Dict[str, Any]]:
    """Inspeciona cada layer de um ``docker save`` e atribui o achado à camada."""
    out = []
    with tarfile.open(path) as outer:
        manifest = json.load(outer.extractfile("manifest.json"))
        for index, layer in enumerate(manifest[0].get("Layers", [])):
            member = outer.extractfile(layer)
            with tarfile.open(fileobj=member) as archive:
                for item in archive.getmembers():
                    if re.search(r"(?:^|/)(?:\.env|id_rsa|credentials|shadow|.*\.pem)$", item.name, re.I):
                        out.append({"rule_id": "OCI-LAYER-SECRET", "severity": "critical", "layer": index, "path": item.name})
    return out

def _simple_yaml(text: str) -> Dict[str, Any]:
    result, current = {"services": {}}, None
    for raw in text.splitlines():
        s = raw.strip()
        if raw.startswith("  ") and not raw.startswith("    ") and s.endswith(":"):
            current = s[:-1]; result["services"][current] = {}
        elif current and ":" in s:
            k, v = s.split(":", 1); result["services"][current][k] = v.strip().lower() == "true" if v.strip().lower() in ("true","false") else v.strip()
    return result
