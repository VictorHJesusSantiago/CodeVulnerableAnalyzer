"""Gerador de SBOM — formato CycloneDX 1.4 JSON ou SPDX 2.3 tag-value."""
from __future__ import annotations
import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import List
from datetime import datetime, timezone


@dataclass
class Component:
    name: str
    version: str
    purl: str
    package_type: str
    license_id: str = "NOASSERTION"


def _make_purl(pkg_type: str, name: str, version: str) -> str:
    return f"pkg:{pkg_type}/{name}@{version}"


# ── Parsers de manifesto ──────────────────────────────────────────────────────

def _from_requirements(content: str) -> List[Component]:
    components: List[Component] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*==\s*([\d\.][A-Za-z0-9\.\-]*)", line)
        if m:
            name, ver = m.group(1), m.group(2)
            components.append(Component(
                name=name, version=ver,
                purl=_make_purl("pypi", name.lower().replace("-", "_"), ver),
                package_type="pypi",
            ))
    return components


def _from_package_json(content: str) -> List[Component]:
    components: List[Component] = []
    try:
        data = json.loads(content)
    except Exception:
        return components
    for section in ("dependencies", "devDependencies"):
        for name, ver_spec in data.get(section, {}).items():
            ver = re.sub(r"[^0-9.]", "", str(ver_spec)).strip(".") or "0.0.0"
            components.append(Component(
                name=name, version=ver,
                purl=_make_purl("npm", name, ver),
                package_type="npm",
            ))
    return components


def _from_pom_xml(content: str) -> List[Component]:
    components: List[Component] = []
    dep_re = re.compile(
        r"<dependency>.*?<groupId>(.*?)</groupId>.*?"
        r"<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>",
        re.DOTALL,
    )
    for m in dep_re.finditer(content):
        group   = m.group(1).strip()
        artifact = m.group(2).strip()
        ver     = m.group(3).strip()
        components.append(Component(
            name=f"{group}:{artifact}", version=ver,
            purl=_make_purl("maven", f"{group}/{artifact}", ver),
            package_type="maven",
        ))
    return components


def _from_cargo_toml(content: str) -> List[Component]:
    components: List[Component] = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if re.match(r"^\[(?:dev-|build-)?dependencies\]", stripped, re.IGNORECASE):
            in_deps = True
            continue
        if stripped.startswith("[") and "dependencies" not in stripped.lower():
            in_deps = False
            continue
        if not in_deps:
            continue
        m = re.match(r'^(\w[\w\-]+)\s*=\s*["\'][\^~>=<\s]*([0-9][0-9.]*)', stripped)
        if m:
            name, ver = m.group(1), m.group(2)
            components.append(Component(
                name=name, version=ver,
                purl=_make_purl("cargo", name, ver),
                package_type="cargo",
            ))
    return components


def _from_go_mod(content: str) -> List[Component]:
    components: List[Component] = []
    for line in content.splitlines():
        m = re.match(r"\s*(?:require\s+)?(\S+)\s+v([\d\.]+)", line)
        if m and not line.strip().startswith("//"):
            module, ver = m.group(1), m.group(2)
            components.append(Component(
                name=module, version=ver,
                purl=_make_purl("golang", module, ver),
                package_type="go",
            ))
    return components


_MANIFEST_MAP = {
    "requirements.txt":      _from_requirements,
    "requirements-dev.txt":  _from_requirements,
    "requirements-prod.txt": _from_requirements,
    "package.json":          _from_package_json,
    "pom.xml":               _from_pom_xml,
    "Cargo.toml":            _from_cargo_toml,
    "go.mod":                _from_go_mod,
}


def collect_components(directory: str) -> List[Component]:
    """Coleta todos os componentes de dependência de um diretório."""
    components: List[Component] = []
    seen: set[str] = set()
    for fname, parser in _MANIFEST_MAP.items():
        for mpath in Path(directory).rglob(fname):
            try:
                content = mpath.read_text(encoding="utf-8", errors="replace")
                for c in parser(content):
                    if c.purl not in seen:
                        seen.add(c.purl)
                        components.append(c)
            except (OSError, PermissionError):
                pass
    return components


# ── CycloneDX 1.4 JSON ────────────────────────────────────────────────────────

def export_cyclonedx(components: List[Component], output_path: str, project_name: str = "project") -> None:
    now = datetime.now(timezone.utc).isoformat()
    bom = {
        "bomFormat":    "CycloneDX",
        "specVersion":  "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version":      1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "CodeVulnerableAnalyzer", "name": "vulnscan", "version": "1.0.0"}],
            "component": {"type": "application", "name": project_name, "version": "0.0.0"},
        },
        "components": [
            {
                "type":    "library",
                "bom-ref": str(uuid.uuid4()),
                "name":    c.name,
                "version": c.version,
                "purl":    c.purl,
            }
            for c in components
        ],
    }
    Path(output_path).write_text(json.dumps(bom, indent=2, ensure_ascii=False), encoding="utf-8")


# ── SPDX 2.3 tag-value ────────────────────────────────────────────────────────

def export_spdx(components: List[Component], output_path: str, project_name: str = "project") -> None:
    now   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_ns = f"https://spdx.org/spdxdocs/{project_name}-{uuid.uuid4()}"

    lines: List[str] = [
        "SPDXVersion: SPDX-2.3",
        "DataLicense: CC0-1.0",
        "SPDXID: SPDXRef-DOCUMENT",
        f"DocumentName: {project_name}",
        f"DocumentNamespace: {doc_ns}",
        "Creator: Tool: CodeVulnerableAnalyzer-vulnscan",
        f"Created: {now}",
        "",
    ]
    for i, c in enumerate(components):
        lines += [
            f"PackageName: {c.name}",
            f"SPDXID: SPDXRef-Package-{i}",
            f"PackageVersion: {c.version}",
            "PackageDownloadLocation: NOASSERTION",
            "FilesAnalyzed: false",
            f"ExternalRef: PACKAGE-MANAGER purl {c.purl}",
            f"PackageLicenseConcluded: {c.license_id}",
            f"PackageLicenseDeclared: {c.license_id}",
            "PackageCopyrightText: NOASSERTION",
            "",
        ]
    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
