"""
Checagem de integridade de hash / pinning de dependências:
  - requirements.txt: modo --hash=sha256:... (pip hash-checking mode)
  - package-lock.json: campo "integrity" (SRI — Subresource Integrity)
  - Cargo.lock: campo "checksum"
  - Versões sem operador de igualdade (ranges como >=, ~=, ^) são reportadas
    como "não fixadas" — permitem que uma versão futura (potencialmente
    comprometida) seja instalada silenciosamente.
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class PinningFinding:
    file_path: str
    line_number: int
    package: str
    issue: str          # "sem_hash" | "versao_nao_fixada" | "sem_checksum"
    severity: str        # HIGH | MEDIUM | LOW


_REQ_PINNED_RE = re.compile(r'^([A-Za-z0-9_.\-]+)\s*==\s*[0-9][A-Za-z0-9.\-]*')
_REQ_HASH_RE = re.compile(r'--hash=sha256:[a-f0-9]{64}')
_REQ_RANGE_RE = re.compile(r'^([A-Za-z0-9_.\-]+)\s*(?:>=|<=|~=|\^|>|<|!=)')


def check_requirements_pinning(content: str) -> List[PinningFinding]:
    findings = []
    for i, line in enumerate(content.splitlines(), start=1):
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith("-"):
            continue

        range_m = _REQ_RANGE_RE.match(stripped)
        if range_m:
            findings.append(PinningFinding(
                "requirements.txt", i, range_m.group(1), "versao_nao_fixada", "MEDIUM",
            ))
            continue

        pinned_m = _REQ_PINNED_RE.match(stripped)
        if pinned_m and not _REQ_HASH_RE.search(stripped):
            findings.append(PinningFinding(
                "requirements.txt", i, pinned_m.group(1), "sem_hash", "LOW",
            ))
    return findings


def check_package_lock_integrity(content: str) -> List[PinningFinding]:
    findings = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return findings

    packages = data.get("packages", {})
    for path, info in packages.items():
        if not path:
            continue
        name = path.split("node_modules/")[-1]
        if "integrity" not in info:
            findings.append(PinningFinding("package-lock.json", 0, name, "sem_hash", "MEDIUM"))
    return findings


_CARGO_ENTRY_RE = re.compile(r'name\s*=\s*"([^"]+)"')
_CARGO_CHECKSUM_RE = re.compile(r'checksum\s*=\s*"[a-f0-9]{64}"')


def check_cargo_lock_checksums(content: str) -> List[PinningFinding]:
    findings = []
    blocks = content.split("[[package]]")
    for block in blocks[1:]:
        name_m = _CARGO_ENTRY_RE.search(block)
        if name_m and not _CARGO_CHECKSUM_RE.search(block):
            # Pacotes "path = ..." (dependências locais) legitimamente não têm checksum
            if "source" in block and not _CARGO_CHECKSUM_RE.search(block):
                findings.append(PinningFinding("Cargo.lock", 0, name_m.group(1), "sem_checksum", "LOW"))
    return findings


def scan_pinning(directory: str) -> List[PinningFinding]:
    all_findings: List[PinningFinding] = []
    for req_file in Path(directory).rglob("requirements*.txt"):
        try:
            content = req_file.read_text(encoding="utf-8", errors="replace")
            for f in check_requirements_pinning(content):
                f.file_path = str(req_file)
                all_findings.append(f)
        except (OSError, PermissionError):
            pass

    for lock_file in Path(directory).rglob("package-lock.json"):
        try:
            content = lock_file.read_text(encoding="utf-8", errors="replace")
            for f in check_package_lock_integrity(content):
                f.file_path = str(lock_file)
                all_findings.append(f)
        except (OSError, PermissionError):
            pass

    for cargo_file in Path(directory).rglob("Cargo.lock"):
        try:
            content = cargo_file.read_text(encoding="utf-8", errors="replace")
            for f in check_cargo_lock_checksums(content):
                f.file_path = str(cargo_file)
                all_findings.append(f)
        except (OSError, PermissionError):
            pass

    return all_findings
