"""Scanner de dependências vulneráveis com base CVE local embutida (zero rede)."""
from __future__ import annotations
import re
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# ── Modelo ────────────────────────────────────────────────────────────────────

@dataclass
class DepVuln:
    package: str
    installed_version: str
    cve_id: str
    description: str
    severity: str
    fixed_version: str
    manifest_file: str
    line_number: int


# ── Base CVE local embutida ───────────────────────────────────────────────────
# Formato: { nome_pacote: [(cve_id, severity, fixed_version, description), ...] }

LOCAL_CVE_DB: Dict[str, List[Tuple[str, str, str, str]]] = {
    # ── Python ────────────────────────────────────────────────────────────────
    "pillow": [
        ("CVE-2024-28219", "HIGH",     "10.3.0", "Buffer overflow in _imagingcms"),
        ("CVE-2023-50447", "HIGH",     "10.2.0", "Arbitrary code execution via putdata()"),
        ("CVE-2023-44271", "HIGH",     "10.0.1", "Uncontrolled resource consumption em ImageFont"),
        ("CVE-2022-45199", "HIGH",     "9.3.0",  "DoS via decompression bomb no parser GIF"),
    ],
    "requests": [
        ("CVE-2023-32681", "MEDIUM",   "2.31.0", "Proxy-Authorization vazado em redirect para não-HTTPS"),
    ],
    "urllib3": [
        ("CVE-2024-37891", "MEDIUM",   "2.2.2",  "Proxy-Authorization não removido em redirect cross-origin"),
        ("CVE-2023-45803", "MEDIUM",   "1.26.18","Redirect body não removido ao mudar método para GET"),
        ("CVE-2023-43804", "HIGH",     "1.26.18","Cookie não removido em redirect cross-origin"),
    ],
    "cryptography": [
        ("CVE-2024-26130", "HIGH",     "42.0.4", "NULL pointer dereference em PKCS#12"),
        ("CVE-2023-49083", "MEDIUM",   "41.0.6", "NULL pointer dereference em OCSP response"),
        ("CVE-2023-38325", "HIGH",     "41.0.3", "NULL pointer dereference em PKCS12 parsing"),
    ],
    "pyjwt": [
        ("CVE-2022-29217", "HIGH",     "2.4.0",  "Algorithm confusion attack RS/HS"),
    ],
    "django": [
        ("CVE-2024-45230", "HIGH",     "4.2.16", "DoS em urlize() e urlizetrunc()"),
        ("CVE-2024-38875", "HIGH",     "4.2.14", "DoS via multipart form data malformado"),
        ("CVE-2024-41990", "HIGH",     "4.2.15", "DoS via ultra-large email header"),
        ("CVE-2023-31047", "CRITICAL", "4.2.2",  "Bypass de validação de upload em ModelAdmin"),
    ],
    "flask": [
        ("CVE-2023-30861", "HIGH",     "2.3.2",  "Session cookie sem Secure flag no localhost"),
    ],
    "jinja2": [
        ("CVE-2024-34064", "MEDIUM",   "3.1.4",  "Sandbox escape via xmlattr filter"),
        ("CVE-2024-22195", "MEDIUM",   "3.1.3",  "XSS via funções de pluralização ngettext"),
    ],
    "aiohttp": [
        ("CVE-2024-30251", "HIGH",     "3.9.4",  "DoS via decompression bomb em request comprimido"),
        ("CVE-2024-27306", "MEDIUM",   "3.9.4",  "XSS via file upload handler"),
        ("CVE-2024-23829", "HIGH",     "3.9.2",  "CRLF injection em response headers"),
    ],
    "paramiko": [
        ("CVE-2023-48795", "MEDIUM",   "3.4.0",  "Terrapin attack: prefix truncation no SSH"),
    ],
    "pyyaml": [
        ("CVE-2022-0391",  "CRITICAL", "6.0.0",  "RCE via desserialização arbitrária de objeto Python"),
    ],
    "lxml": [
        ("CVE-2022-2309",  "HIGH",     "4.9.2",  "XXE via entity injection"),
    ],
    "celery": [
        ("CVE-2021-23727", "HIGH",     "5.2.2",  "Command injection via serialização de task"),
    ],
    "numpy": [
        ("CVE-2021-41496", "HIGH",     "1.22.0", "Buffer overflow em ndarray __length_hint__"),
    ],
    "setuptools": [
        ("CVE-2024-6345",  "HIGH",     "70.0.0", "RCE via wheel filename malformado em package_index"),
        ("CVE-2022-40897", "HIGH",     "65.5.1", "ReDoS via string de versão malformada"),
    ],
    "werkzeug": [
        ("CVE-2024-34069", "HIGH",     "3.0.3",  "Bypass do PIN do debugger via cookie malformado"),
        ("CVE-2023-46136", "HIGH",     "3.0.1",  "DoS via multipart/form-data malformado"),
    ],
    "twisted": [
        ("CVE-2024-41671", "HIGH",     "24.7.0", "HTTP request smuggling via chunk extension"),
        ("CVE-2024-41810", "MEDIUM",   "24.7.0", "XSS via header malformado em error pages"),
    ],
    "gunicorn": [
        ("CVE-2024-1135",  "HIGH",     "22.0.0", "HTTP request smuggling via chunk encoding inválido"),
    ],
    "starlette": [
        ("CVE-2024-24762", "HIGH",     "0.36.2", "DoS via payload form-data grande"),
        ("CVE-2023-29159", "MEDIUM",   "0.27.0", "Path traversal em StaticFiles"),
    ],
    "fastapi": [
        ("CVE-2024-24762", "HIGH",     "0.109.1","DoS via payload form-data grande"),
    ],
    "sqlalchemy": [
        ("CVE-2019-7164",  "HIGH",     "1.3.3",  "SQL injection via parâmetro order_by no ORM"),
    ],
    "pymysql": [
        ("CVE-2024-36039", "HIGH",     "1.1.1",  "SQL injection via % em cursor.execute()"),
    ],
    "httpx": [
        ("CVE-2023-40589", "MEDIUM",   "0.24.1", "SSRF bypass via redirect handling"),
    ],
    # ── Node.js (npm) ─────────────────────────────────────────────────────────
    "lodash": [
        ("CVE-2021-23337", "HIGH",     "4.17.21","Command injection via template tags"),
        ("CVE-2020-8203",  "HIGH",     "4.17.19","Prototype pollution via zipObjectDeep"),
    ],
    "moment": [
        ("CVE-2022-31129", "HIGH",     "2.29.4", "ReDoS em date string parsing"),
        ("CVE-2022-24785", "HIGH",     "2.29.4", "Path traversal em locale loading"),
    ],
    "express": [
        ("CVE-2024-29041", "MEDIUM",   "4.19.2", "Open redirect via URL malformada"),
        ("CVE-2022-24999", "HIGH",     "4.18.2", "Prototype pollution via qs"),
    ],
    "axios": [
        ("CVE-2024-39338", "HIGH",     "1.7.4",  "SSRF via relative URL em redirect"),
        ("CVE-2023-45857", "MEDIUM",   "1.6.0",  "CSRF via exposição de XSRF-TOKEN"),
    ],
    "jsonwebtoken": [
        ("CVE-2022-23540", "HIGH",     "9.0.0",  "jwt.verify bypass via typ:JWT header"),
        ("CVE-2022-23541", "HIGH",     "9.0.0",  "jwt.verify aceita tokens não assinados"),
        ("CVE-2022-23539", "HIGH",     "9.0.0",  "Comparação insegura na validação de assinatura"),
    ],
    "protobufjs": [
        ("CVE-2023-36665", "CRITICAL", "7.2.5",  "Prototype pollution via __proto__ em JSON"),
    ],
    "semver": [
        ("CVE-2022-25883", "HIGH",     "7.5.2",  "ReDoS via string de versão malformada"),
    ],
    "node-fetch": [
        ("CVE-2022-0235",  "HIGH",     "3.1.1",  "Exposição de informações via redirect"),
    ],
    "got": [
        ("CVE-2022-33987", "MEDIUM",   "12.1.0", "SSRF via open redirect"),
    ],
    "minimatch": [
        ("CVE-2022-3517",  "HIGH",     "3.0.5",  "ReDoS via glob pattern malformado"),
    ],
    "ws": [
        ("CVE-2024-37890", "HIGH",     "8.17.1", "DoS via HTTP header malformado"),
    ],
    "tough-cookie": [
        ("CVE-2023-26136", "CRITICAL", "4.1.3",  "Prototype pollution via cookie handling"),
    ],
    "ip": [
        ("CVE-2023-42282", "HIGH",     "2.0.1",  "SSRF bypass via validação de IP"),
    ],
    "follow-redirects": [
        ("CVE-2024-28849", "MEDIUM",   "1.15.6", "Proxy-Auth não removido em redirect cross-origin"),
    ],
    "path-to-regexp": [
        ("CVE-2024-45296", "HIGH",     "0.1.10", "ReDoS via backtracking regex de path do usuário"),
    ],
    "undici": [
        ("CVE-2024-30260", "MEDIUM",   "6.11.1", "Proxy-Auth não removido em redirect cross-origin"),
    ],
    # ── Java (Maven artifactId) ────────────────────────────────────────────────
    "log4j-core": [
        ("CVE-2021-44228", "CRITICAL", "2.15.0", "Log4Shell: RCE via JNDI lookup em log message"),
        ("CVE-2021-45046", "CRITICAL", "2.16.0", "Log4Shell bypass via thread context lookup"),
        ("CVE-2021-44832", "MEDIUM",   "2.17.1", "RCE arbitrário com acesso escrita à config log4j"),
    ],
    "spring-core": [
        ("CVE-2022-22965", "CRITICAL", "5.3.18", "Spring4Shell: RCE via data binding no JDK9+"),
        ("CVE-2022-22963", "CRITICAL", "3.2.2",  "Spring Cloud RCE via SpEL injection"),
    ],
    "spring-security-core": [
        ("CVE-2022-22978", "CRITICAL", "5.6.4",  "Bypass de autorização via RegexRequestMatcher"),
    ],
    "jackson-databind": [
        ("CVE-2022-42003", "HIGH",     "2.14.0", "DoS via deeply nested wrapper arrays"),
        ("CVE-2022-42004", "HIGH",     "2.14.0", "DoS via muitas chaves únicas em JSON"),
    ],
    "commons-text": [
        ("CVE-2022-42889", "CRITICAL", "1.10.0", "Text4Shell: RCE via StringSubstitutor interpolation"),
    ],
    "netty-all": [
        ("CVE-2023-44487", "HIGH",     "4.1.100.Final","HTTP/2 Rapid Reset DoS"),
    ],
    # ── Rust (crates.io) ──────────────────────────────────────────────────────
    "openssl": [
        ("CVE-2023-0286",  "HIGH",     "0.10.48","Confusão de tipo em GeneralName com X.400 em CRL"),
    ],
    "hyper": [
        ("CVE-2023-45405", "HIGH",     "0.14.28","HTTP/2 rapid reset vulnerability"),
    ],
    # ── .NET (NuGet) ────────────────────────────────────────────────────────────
    "newtonsoft.json": [
        ("CVE-2024-21907", "HIGH",     "13.0.1", "DoS via StackOverflow ao desserializar JSON profundamente aninhado"),
    ],
    "system.text.encodings.web": [
        ("CVE-2021-26701", "CRITICAL", "4.5.1",  "RCE via encoding malformado em System.Text.Encodings.Web"),
    ],
    "system.net.http": [
        ("CVE-2018-8292",  "HIGH",     "4.3.4",  "Vazamento de informações via tratamento de credenciais"),
    ],
    "microsoft.data.sqlclient": [
        ("CVE-2024-0056",  "HIGH",     "5.1.3",  "MITM / spoofing via validação de certificado TLS"),
    ],
    "bootstrap": [
        ("CVE-2024-6531",  "MEDIUM",   "5.3.3",  "XSS via atributos data-* em componentes carousel"),
    ],
    "jquery": [
        ("CVE-2020-11023", "MEDIUM",   "3.5.0",  "XSS via manipulação de elementos HTML com <option>"),
    ],
}


# ── Comparação de versões ─────────────────────────────────────────────────────

def _parse_ver(v: str) -> tuple:
    parts = re.sub(r"[^\d.]", "", v).split(".")
    result = []
    for p in parts[:4]:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    while len(result) < 4:
        result.append(0)
    return tuple(result)


def _ver_lt(v1: str, v2: str) -> bool:
    try:
        return _parse_ver(v1) < _parse_ver(v2)
    except Exception:
        return False


def _normalize(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def _check(name: str, version: str, manifest: str, line_no: int) -> List[DepVuln]:
    vulns: List[DepVuln] = []
    entries = LOCAL_CVE_DB.get(name) or LOCAL_CVE_DB.get(_normalize(name))
    if not entries:
        return vulns
    for cve_id, severity, fixed_ver, description in entries:
        if _ver_lt(version, fixed_ver):
            vulns.append(DepVuln(
                package=name,
                installed_version=version,
                cve_id=cve_id,
                description=description,
                severity=severity,
                fixed_version=fixed_ver,
                manifest_file=manifest,
                line_number=line_no,
            ))
    return vulns


# ── Parsers de manifesto ──────────────────────────────────────────────────────

# Casa: nome (+ extras opcionais) + operador opcional + versão concreta (limite inferior)
_REQ_RE = re.compile(
    r"^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*"
    r"(?:[=<>!~^]=?\s*v?)?\s*([0-9][A-Za-z0-9.\-]*)"
)


def _parse_requirements(content: str, filepath: str) -> List[DepVuln]:
    vulns: List[DepVuln] = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        line = line.split("#", 1)[0].split(";", 1)[0].strip()  # remove comentário e marker
        if not line or line.startswith(("-", "git+")):
            continue
        m = _REQ_RE.match(line)
        if m:
            vulns.extend(_check(m.group(1).lower(), m.group(2), filepath, line_no))
    return vulns


def _parse_package_json(content: str, filepath: str) -> List[DepVuln]:
    vulns: List[DepVuln] = []
    try:
        data = json.loads(content)
    except Exception:
        return vulns
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for pkg, ver_spec in data.get(section, {}).items():
            ver = re.sub(r"[^0-9.]", "", str(ver_spec)).strip(".")
            if ver:
                vulns.extend(_check(pkg.lower(), ver, filepath, 0))
    return vulns


def _parse_pom_xml(content: str, filepath: str) -> List[DepVuln]:
    vulns: List[DepVuln] = []
    dep_re = re.compile(
        r"<dependency>.*?<artifactId>(.*?)</artifactId>.*?<version>([\d\.]+[A-Za-z0-9\-\.]*)</version>",
        re.DOTALL,
    )
    for m in dep_re.finditer(content):
        artifact = m.group(1).strip().lower()
        version = m.group(2).strip()
        vulns.extend(_check(artifact, version, filepath, 0))
    return vulns


def _parse_cargo_toml(content: str, filepath: str) -> List[DepVuln]:
    vulns: List[DepVuln] = []
    in_deps = False
    for line_no, line in enumerate(content.splitlines(), start=1):
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
            vulns.extend(_check(m.group(1).lower(), m.group(2), filepath, line_no))
    return vulns


def _parse_go_mod(content: str, filepath: str) -> List[DepVuln]:
    vulns: List[DepVuln] = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        m = re.match(r"\s*(?:require\s+)?\S+/(\S+)\s+v([\d\.]+)", line)
        if m:
            pkg = m.group(1).lower()
            vulns.extend(_check(pkg, m.group(2), filepath, line_no))
    return vulns


def _parse_csproj(content: str, filepath: str) -> List[DepVuln]:
    """Projetos .NET: <PackageReference Include="X" Version="Y" />."""
    vulns: List[DepVuln] = []
    # Atributos podem vir em qualquer ordem; também suporta <Version> como elemento filho.
    for m in re.finditer(
        r'<PackageReference\b[^>]*?\bInclude\s*=\s*"([^"]+)"[^>]*?'
        r'(?:\bVersion\s*=\s*"([^"]+)"|/?>(?:\s*<Version>\s*([^<]+)\s*</Version>)?)',
        content, re.IGNORECASE | re.DOTALL,
    ):
        pkg = m.group(1).strip().lower()
        ver = (m.group(2) or m.group(3) or "").strip()
        ver = re.sub(r"[^\d.].*$", "", ver)  # remove sufixos ([..], -beta, etc.)
        if pkg and ver:
            vulns.extend(_check(pkg, ver, filepath, 0))
    return vulns


_PARSERS: dict[str, object] = {
    "requirements.txt":      _parse_requirements,
    "requirements-dev.txt":  _parse_requirements,
    "requirements-test.txt": _parse_requirements,
    "requirements-prod.txt": _parse_requirements,
    "package.json":          _parse_package_json,
    "pom.xml":               _parse_pom_xml,
    "Cargo.toml":            _parse_cargo_toml,
    "go.mod":                _parse_go_mod,
}


def scan_dependencies(file_path: str, content: str) -> List[DepVuln]:
    """Escaneia um arquivo de manifesto e retorna vulnerabilidades conhecidas."""
    fname = Path(file_path).name
    parser = _PARSERS.get(fname)
    if parser is None and fname.lower().endswith(".csproj"):
        parser = _parse_csproj
    if parser is None:
        return []
    return parser(content, file_path)  # type: ignore[call-arg]


def scan_manifest_dir(directory: str) -> List[DepVuln]:
    """Escaneia todos os manifestos em um diretório recursivamente."""
    all_vulns: List[DepVuln] = []
    for fname in _PARSERS:
        for mpath in Path(directory).rglob(fname):
            try:
                content = mpath.read_text(encoding="utf-8", errors="replace")
                all_vulns.extend(scan_dependencies(str(mpath), content))
            except (OSError, PermissionError):
                pass
    for mpath in Path(directory).rglob("*.csproj"):
        try:
            content = mpath.read_text(encoding="utf-8", errors="replace")
            all_vulns.extend(_parse_csproj(content, str(mpath)))
        except (OSError, PermissionError):
            pass
    return all_vulns


# ── Enriquecimento online via OSV.dev (stdlib urllib, opt-in) ──────────────────
# Mapeia o package_type do SBOM para o ecossistema esperado pela API OSV.
_OSV_ECOSYSTEM = {
    "pypi":  "PyPI",
    "npm":   "npm",
    "maven": "Maven",
    "cargo": "crates.io",
    "go":    "Go",
    "nuget": "NuGet",
}


def _cvss_v3_base(vector: str) -> Optional[float]:
    """Calcula o CVSS v3.x base score a partir de um vetor (FIRST.org spec)."""
    import math
    m = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    if "AV" not in m or "C" not in m:
        return None
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(m.get("AV"), 0.85)
    ac = {"L": 0.77, "H": 0.44}.get(m.get("AC"), 0.77)
    ui = {"N": 0.85, "R": 0.62}.get(m.get("UI"), 0.85)
    scope_changed = m.get("S") == "C"
    if scope_changed:
        pr = {"N": 0.85, "L": 0.68, "H": 0.5}.get(m.get("PR"), 0.85)
    else:
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(m.get("PR"), 0.85)
    cia = {"H": 0.56, "L": 0.22, "N": 0.0}
    c = cia.get(m.get("C"), 0.0); i = cia.get(m.get("I"), 0.0); a = cia.get(m.get("A"), 0.0)

    isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    score = min(raw, 10.0)
    return math.ceil(score * 10) / 10.0   # roundup para 1 casa decimal


def _label_from_score(f: float) -> str:
    if f >= 9.0: return "CRITICAL"
    if f >= 7.0: return "HIGH"
    if f >= 4.0: return "MEDIUM"
    if f > 0.0:  return "LOW"
    return "MEDIUM"


def _osv_severity(vuln: dict) -> str:
    """Extrai um rótulo de severidade de uma entrada OSV (CVSS ou texto)."""
    # 1) Campo de texto em database_specific (comum em GHSA)
    ds = vuln.get("database_specific") or {}
    txt = str(ds.get("severity", "")).upper()
    if txt in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"):
        return "MEDIUM" if txt == "MODERATE" else txt
    # 2) CVSS: o campo 'score' do OSV é o vetor (ex.: "CVSS:3.1/AV:N/.../A:H")
    for sv in vuln.get("severity", []) or []:
        score = str(sv.get("score", ""))
        if score.upper().startswith("CVSS:"):
            base = _cvss_v3_base(score)
            if base is not None:
                return _label_from_score(base)
        else:
            m = re.search(r"(\d+\.\d+)", score)   # alguns formatos trazem número puro
            if m:
                return _label_from_score(float(m.group(1)))
    return "MEDIUM"


def _osv_fixed_version(vuln: dict) -> str:
    """Tenta extrair a primeira versão corrigida a partir dos ranges OSV."""
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    return str(ev["fixed"])
    return "—"


def query_osv(name: str, version: str, ecosystem: str, timeout: float = 8.0) -> List[DepVuln]:
    """
    Consulta a API pública OSV.dev para um pacote/versão. Usa apenas urllib
    (stdlib). Em caso de erro de rede, retorna lista vazia (degradação graciosa).
    """
    import urllib.request

    payload = json.dumps({
        "version": version,
        "package": {"name": name, "ecosystem": ecosystem},
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return []

    results: List[DepVuln] = []
    for v in data.get("vulns", []) or []:
        aliases = v.get("aliases") or []
        cve_id  = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))
        desc    = v.get("summary") or (v.get("details", "") or "")[:160] or "Vulnerabilidade reportada no OSV"
        results.append(DepVuln(
            package=name,
            installed_version=version,
            cve_id=cve_id,
            description=desc,
            severity=_osv_severity(v),
            fixed_version=_osv_fixed_version(v),
            manifest_file="(OSV.dev)",
            line_number=0,
        ))
    return results


def scan_manifest_dir_osv(directory: str, timeout: float = 8.0) -> List[DepVuln]:
    """
    Cruza todas as dependências do diretório com a base online OSV.dev.
    Reutiliza o coletor de componentes do SBOM (que conhece o ecossistema).
    Retorna [] silenciosamente se não houver rede.
    """
    from analyzer.sbom import collect_components

    out: List[DepVuln] = []
    seen: set = set()
    for c in collect_components(directory):
        eco = _OSV_ECOSYSTEM.get(c.package_type)
        if not eco:
            continue
        for dv in query_osv(c.name, c.version, eco, timeout):
            key = (dv.package, dv.cve_id)
            if key not in seen:
                seen.add(key)
                out.append(dv)
    return out
