"""
Saúde de dependências: typosquatting/dependency-confusion, licenças e
pacotes abandonados/pouco mantidos.

  - Typosquatting: distância de edição (Levenshtein, implementação própria
    em stdlib puro) entre o nome do pacote e uma lista local dos pacotes
    mais populares de cada ecossistema — sinaliza nomes suspeitosamente
    parecidos mas não idênticos.
  - Dependency confusion: heurística de nome com cara de pacote interno
    (prefixos como "@empresa/", "internal-", "corp-") presente num
    manifesto público sem escopo/registro privado explícito.
  - Licenças: leitura do campo local de licença em manifestos (quando
    presente) + tabela local de pacotes conhecidos por licença copyleft
    forte (GPL/AGPL), para alertar sobre incompatibilidade em projeto
    proprietário. NÃO é um banco de dados completo de licenças (isso exigiria
    consulta de rede a um registry — ver query_registry_metadata, opt-in).
  - Pacotes abandonados: via consulta opcional (rede) às APIs públicas do
    PyPI/npm para data do último release.
"""
from __future__ import annotations
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# ── Top pacotes populares por ecossistema (para comparação de typosquatting) ──
# Lista curada dos pacotes mais baixados/conhecidos — não é exaustiva, mas
# cobre os alvos mais comuns de ataques de typosquatting documentados.
POPULAR_PACKAGES: Dict[str, List[str]] = {
    "pypi": [
        "requests", "numpy", "pandas", "flask", "django", "urllib3", "boto3",
        "pytest", "setuptools", "pyyaml", "click", "jinja2", "cryptography",
        "pillow", "scipy", "sqlalchemy", "matplotlib", "beautifulsoup4",
        "selenium", "scrapy", "tensorflow", "torch", "fastapi", "pydantic",
    ],
    "npm": [
        "react", "lodash", "express", "axios", "vue", "webpack", "typescript",
        "eslint", "jest", "babel", "chalk", "commander", "moment", "underscore",
        "async", "request", "debug", "colors", "yargs", "react-dom", "next",
    ],
    "cargo": [
        "serde", "tokio", "rand", "clap", "reqwest", "regex", "log", "anyhow",
        "thiserror", "futures", "hyper", "actix-web",
    ],
    "gem": [
        "rails", "rack", "rspec", "devise", "nokogiri", "puma", "sidekiq",
    ],
}

# Pacotes conhecidos por licença copyleft forte (amostra curada, não exaustiva)
_GPL_LICENSED_PACKAGES = {
    "mysql-connector-python": "GPL-2.0",
    "pyqt5": "GPL-3.0",
    "readline": "GPL-3.0",
    "gnu-libjpeg": "GPL-2.0",
}


@dataclass
class TyposquatFinding:
    package_name: str
    ecosystem: str
    similar_to: str
    edit_distance: int


@dataclass
class ConfusionFinding:
    package_name: str
    reason: str


@dataclass
class LicenseFinding:
    package_name: str
    license: str
    concern: str


@dataclass
class AbandonedFinding:
    package_name: str
    ecosystem: str
    last_release: Optional[str]
    days_since_release: Optional[int]


# ── Levenshtein (stdlib puro) ──────────────────────────────────────────────────

def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def check_typosquatting(package_name: str, ecosystem: str, max_distance: int = 2) -> Optional[TyposquatFinding]:
    popular = POPULAR_PACKAGES.get(ecosystem, [])
    name_lower = package_name.lower()
    if name_lower in popular:
        return None  # é o próprio pacote popular, não um typosquat
    best_match, best_dist = None, max_distance + 1
    for candidate in popular:
        dist = levenshtein(name_lower, candidate)
        if 0 < dist <= max_distance and dist < best_dist:
            best_match, best_dist = candidate, dist
    if best_match:
        return TyposquatFinding(package_name, ecosystem, best_match, best_dist)
    return None


_INTERNAL_NAME_MARKERS = ("internal-", "corp-", "private-", "-internal", "-private")


def check_dependency_confusion(package_name: str) -> Optional[ConfusionFinding]:
    lower = package_name.lower()
    if lower.startswith("@") and "/" not in lower:
        return None
    for marker in _INTERNAL_NAME_MARKERS:
        if marker in lower:
            return ConfusionFinding(
                package_name,
                f"Nome sugere pacote interno ('{marker}') resolvido de um registro público — "
                f"risco de dependency confusion se não houver escopo/registro privado configurado.",
            )
    return None


def check_license(package_name: str, declared_license: Optional[str] = None) -> Optional[LicenseFinding]:
    lower = package_name.lower()
    if lower in _GPL_LICENSED_PACKAGES:
        lic = _GPL_LICENSED_PACKAGES[lower]
        return LicenseFinding(package_name, lic,
                               f"Licença copyleft forte ({lic}) — pode exigir que seu projeto "
                               f"também seja distribuído sob a mesma licença se vinculado estaticamente.")
    if declared_license and re.search(r'(?i)\b(?:AGPL|GPL)\b', declared_license):
        return LicenseFinding(package_name, declared_license,
                               "Licença copyleft declarada no manifesto — revise compatibilidade com seu modelo de distribuição.")
    return None


# ── Pacotes abandonados (rede, opt-in) ────────────────────────────────────────

def query_pypi_last_release(package_name: str, timeout: float = 8.0) -> Optional[str]:
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        releases = data.get("releases", {})
        dates = []
        for files in releases.values():
            for f in files:
                if f.get("upload_time_iso_8601"):
                    dates.append(f["upload_time_iso_8601"])
        return max(dates) if dates else None
    except Exception:
        return None


def query_npm_last_release(package_name: str, timeout: float = 8.0) -> Optional[str]:
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("time", {}).get("modified")
    except Exception:
        return None


def check_abandoned(package_name: str, ecosystem: str, max_age_days: int = 730) -> Optional[AbandonedFinding]:
    """Consulta REDE (opt-in) para verificar a última publicação do pacote."""
    last_release = None
    if ecosystem == "pypi":
        last_release = query_pypi_last_release(package_name)
    elif ecosystem == "npm":
        last_release = query_npm_last_release(package_name)

    if not last_release:
        return AbandonedFinding(package_name, ecosystem, None, None)

    try:
        dt = datetime.fromisoformat(last_release.replace("Z", "+00:00"))
        days = (datetime.now(timezone.utc) - dt).days
        if days > max_age_days:
            return AbandonedFinding(package_name, ecosystem, last_release, days)
    except ValueError:
        pass
    return None
