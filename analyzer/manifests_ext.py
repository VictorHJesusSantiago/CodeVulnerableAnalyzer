"""
Parsers de manifesto de dependências para ecossistemas ainda não cobertos
por deps.py/sbom.py: Composer (PHP), RubyGems (Gemfile), NuGet
(packages.config), Dart/Flutter (pubspec.yaml), Swift PM (Package.swift/
Package.resolved), CocoaPods (Podfile), Carthage (Cartfile), Conan (C/C++),
vcpkg, Hex (Elixir mix.exs), CPAN (cpanfile), CRAN (DESCRIPTION), Conda
(environment.yml), Helm (Chart.yaml), Dockerfile (imagem base + pacotes
apt/yum/apk instalados).

Cada parser devolve List[Component] no mesmo formato de analyzer/sbom.py
para poder alimentar SBOM e o scanner de CVEs locais/OSV sem duplicar
estruturas de dado.
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import List

from analyzer.sbom import Component, _make_purl


# ── Composer (PHP) ──────────────────────────────────────────────────────────

def parse_composer_json(content: str) -> List[Component]:
    components = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return components
    for section in ("require", "require-dev"):
        for name, ver_spec in data.get(section, {}).items():
            if name == "php" or name.startswith("ext-"):
                continue
            ver = re.sub(r"[^0-9.]", "", str(ver_spec)).strip(".") or "0.0.0"
            components.append(Component(name=name, version=ver,
                                         purl=_make_purl("composer", name, ver),
                                         package_type="composer"))
    return components


def parse_composer_lock(content: str) -> List[Component]:
    components = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return components
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            name = pkg.get("name", "")
            ver = str(pkg.get("version", "")).lstrip("v")
            if name:
                components.append(Component(name=name, version=ver,
                                             purl=_make_purl("composer", name, ver),
                                             package_type="composer"))
    return components


# ── RubyGems (Gemfile / Gemfile.lock) ────────────────────────────────────────

_GEMFILE_GEM_RE = re.compile(r'''^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?''')
_GEMFILE_LOCK_ENTRY_RE = re.compile(r'^\s{4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)')


def parse_gemfile(content: str) -> List[Component]:
    components = []
    for line in content.splitlines():
        m = _GEMFILE_GEM_RE.match(line)
        if m:
            name, ver = m.groups()
            ver = re.sub(r"[^0-9.]", "", ver or "").strip(".") or "0.0.0"
            components.append(Component(name=name, version=ver,
                                         purl=_make_purl("gem", name, ver),
                                         package_type="rubygems"))
    return components


def parse_gemfile_lock(content: str) -> List[Component]:
    components = []
    in_specs = False
    for line in content.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if line and not line.startswith(" "):
            in_specs = False
        if in_specs:
            m = _GEMFILE_LOCK_ENTRY_RE.match(line)
            if m:
                name, ver = m.groups()
                components.append(Component(name=name, version=ver,
                                             purl=_make_purl("gem", name, ver),
                                             package_type="rubygems"))
    return components


# ── NuGet (packages.config) ──────────────────────────────────────────────────

_NUGET_PKG_RE = re.compile(r'<package\s+id="([^"]+)"\s+version="([^"]+)"')


def parse_packages_config(content: str) -> List[Component]:
    components = []
    for m in _NUGET_PKG_RE.finditer(content):
        name, ver = m.groups()
        components.append(Component(name=name, version=ver,
                                     purl=_make_purl("nuget", name, ver),
                                     package_type="nuget"))
    return components


# ── Dart/Flutter (pubspec.yaml) ──────────────────────────────────────────────

_PUBSPEC_DEP_RE = re.compile(r'^\s{2}([a-zA-Z0-9_]+):\s*\^?([0-9][0-9.]*)')


def parse_pubspec_yaml(content: str) -> List[Component]:
    components = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.rstrip()
        if re.match(r'^(?:dependencies|dev_dependencies):\s*$', stripped):
            in_deps = True
            continue
        if stripped and not stripped.startswith(" ") and not stripped.startswith("#"):
            in_deps = False
        if in_deps:
            m = _PUBSPEC_DEP_RE.match(line)
            if m:
                name, ver = m.groups()
                components.append(Component(name=name, version=ver,
                                             purl=_make_purl("pub", name, ver),
                                             package_type="pub"))
    return components


# ── Swift Package Manager (Package.resolved) ─────────────────────────────────

def parse_package_resolved(content: str) -> List[Component]:
    components = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return components
    pins = data.get("pins") or data.get("object", {}).get("pins", [])
    for pin in pins:
        name = pin.get("identity") or pin.get("package", "")
        state = pin.get("state", {})
        ver = state.get("version") or state.get("revision", "")[:12] or "0.0.0"
        if name:
            components.append(Component(name=name, version=ver,
                                         purl=_make_purl("swift", name, ver),
                                         package_type="swift"))
    return components


# ── CocoaPods (Podfile.lock) ──────────────────────────────────────────────────

_PODFILE_LOCK_ENTRY_RE = re.compile(r'^\s*-\s*([A-Za-z0-9_+./-]+)\s*\(([^)]+)\)')


def parse_podfile_lock(content: str) -> List[Component]:
    components = []
    in_pods = False
    for line in content.splitlines():
        if line.strip() == "PODS:":
            in_pods = True
            continue
        if line and not line.startswith(" ") and line.strip().endswith(":"):
            in_pods = (line.strip() == "PODS:")
        if in_pods:
            m = _PODFILE_LOCK_ENTRY_RE.match(line)
            if m:
                name, ver = m.groups()
                name = name.split("/")[0]  # remove subspecs (Pod/Subspec)
                components.append(Component(name=name, version=ver,
                                             purl=_make_purl("cocoapods", name, ver),
                                             package_type="cocoapods"))
    return components


# ── Carthage (Cartfile.resolved) ─────────────────────────────────────────────

_CARTFILE_RE = re.compile(r'^(?:github|git|binary)\s+"([^"]+)"\s+"([^"]+)"')


def parse_cartfile_resolved(content: str) -> List[Component]:
    components = []
    for line in content.splitlines():
        m = _CARTFILE_RE.match(line.strip())
        if m:
            name, ver = m.groups()
            name = name.split("/")[-1]
            components.append(Component(name=name, version=ver.lstrip("v"),
                                         purl=_make_purl("carthage", name, ver),
                                         package_type="carthage"))
    return components


# ── Conan (conanfile.txt) ─────────────────────────────────────────────────────

_CONAN_REQ_RE = re.compile(r'^([A-Za-z0-9_.-]+)/([0-9][A-Za-z0-9.+-]*)')


def parse_conanfile_txt(content: str) -> List[Component]:
    components = []
    in_requires = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_requires = stripped == "[requires]"
            continue
        if in_requires:
            m = _CONAN_REQ_RE.match(stripped)
            if m:
                name, ver = m.groups()
                components.append(Component(name=name, version=ver,
                                             purl=_make_purl("conan", name, ver),
                                             package_type="conan"))
    return components


# ── vcpkg.json ────────────────────────────────────────────────────────────────

def parse_vcpkg_json(content: str) -> List[Component]:
    components = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return components
    for dep in data.get("dependencies", []):
        name = dep if isinstance(dep, str) else dep.get("name", "")
        if name:
            components.append(Component(name=name, version="0.0.0",
                                         purl=_make_purl("vcpkg", name, "0.0.0"),
                                         package_type="vcpkg"))
    return components


# ── Hex (Elixir mix.exs) ──────────────────────────────────────────────────────

_MIX_DEP_RE = re.compile(r'\{:([a-z0-9_]+),\s*"~?>?=?\s*([0-9][0-9.]*)"')


def parse_mix_exs(content: str) -> List[Component]:
    components = []
    for m in _MIX_DEP_RE.finditer(content):
        name, ver = m.groups()
        components.append(Component(name=name, version=ver,
                                     purl=_make_purl("hex", name, ver),
                                     package_type="hex"))
    return components


# ── CPAN (cpanfile) ───────────────────────────────────────────────────────────

_CPANFILE_RE = re.compile(r'''^\s*requires\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?''')


def parse_cpanfile(content: str) -> List[Component]:
    components = []
    for line in content.splitlines():
        m = _CPANFILE_RE.match(line)
        if m:
            name, ver = m.groups()
            ver = re.sub(r"[^0-9.]", "", ver or "").strip(".") or "0.0.0"
            components.append(Component(name=name, version=ver,
                                         purl=_make_purl("cpan", name, ver),
                                         package_type="cpan"))
    return components


# ── CRAN (DESCRIPTION) ────────────────────────────────────────────────────────

def parse_description_cran(content: str) -> List[Component]:
    components = []
    m = re.search(r'^Imports:\s*(.+?)(?:^\S|\Z)', content, re.MULTILINE | re.DOTALL)
    if not m:
        m = re.search(r'^Depends:\s*(.+?)(?:^\S|\Z)', content, re.MULTILINE | re.DOTALL)
    if m:
        block = m.group(1)
        for item in block.split(","):
            item = item.strip()
            pm = re.match(r'([A-Za-z0-9.]+)(?:\s*\(([^)]+)\))?', item)
            if pm:
                name, ver_spec = pm.groups()
                ver = re.sub(r"[^0-9.]", "", ver_spec or "").strip(".") or "0.0.0"
                if name and name != "R":
                    components.append(Component(name=name, version=ver,
                                                 purl=_make_purl("cran", name, ver),
                                                 package_type="cran"))
    return components


# ── Conda (environment.yml) ───────────────────────────────────────────────────

_CONDA_DEP_RE = re.compile(r'^\s*-\s*([A-Za-z0-9_.-]+)(?:[=<>]+([0-9][0-9.]*))?')


def parse_conda_environment(content: str) -> List[Component]:
    components = []
    in_deps = False
    for line in content.splitlines():
        if re.match(r'^dependencies:\s*$', line):
            in_deps = True
            continue
        if in_deps:
            if line.strip().startswith("- pip:"):
                continue
            m = _CONDA_DEP_RE.match(line)
            if m:
                name, ver = m.groups()
                if name == "python":
                    continue
                components.append(Component(name=name, version=ver or "0.0.0",
                                             purl=_make_purl("conda", name, ver or "0.0.0"),
                                             package_type="conda"))
    return components


# ── Helm (Chart.yaml) ─────────────────────────────────────────────────────────

_HELM_DEP_NAME_RE = re.compile(r'^\s*-?\s*name:\s*(\S+)')
_HELM_DEP_VER_RE = re.compile(r'^\s*version:\s*"?([^"\s]+)"?')


def parse_helm_chart_yaml(content: str) -> List[Component]:
    """Extrai as 'dependencies:' de um Chart.yaml (subcharts)."""
    components = []
    in_deps = False
    pending_name = None
    for line in content.splitlines():
        if re.match(r'^dependencies:\s*$', line):
            in_deps = True
            continue
        if in_deps:
            if line and not line.startswith((" ", "-")):
                in_deps = False
                continue
            nm = _HELM_DEP_NAME_RE.match(line)
            if nm:
                pending_name = nm.group(1)
                continue
            vm = _HELM_DEP_VER_RE.match(line)
            if vm and pending_name:
                components.append(Component(name=pending_name, version=vm.group(1),
                                             purl=_make_purl("helm", pending_name, vm.group(1)),
                                             package_type="helm"))
                pending_name = None
    return components


# ── Dockerfile (imagem base + pacotes apt/yum/apk) ────────────────────────────

_DOCKER_FROM_RE = re.compile(r'^\s*FROM\s+([^\s:]+)(?::([^\s]+))?', re.MULTILINE)
_APT_INSTALL_RE = re.compile(r'apt(?:-get)?\s+install\s+(?:-y\s+)?([^\n&|]+)')
_APK_ADD_RE = re.compile(r'apk\s+add\s+(?:--no-cache\s+)?([^\n&|]+)')
_YUM_INSTALL_RE = re.compile(r'(?:yum|dnf)\s+install\s+(?:-y\s+)?([^\n&|]+)')


def parse_dockerfile(content: str) -> List[Component]:
    components = []
    for m in _DOCKER_FROM_RE.finditer(content):
        image, tag = m.groups()
        if image.lower() == "scratch":
            continue
        components.append(Component(name=image, version=tag or "latest",
                                     purl=f"pkg:docker/{image}@{tag or 'latest'}",
                                     package_type="docker-base-image"))

    for regex, pkg_type in [(_APT_INSTALL_RE, "apt"), (_APK_ADD_RE, "apk"), (_YUM_INSTALL_RE, "yum")]:
        for m in regex.finditer(content):
            pkgs = m.group(1).split()
            for pkg in pkgs:
                pkg = pkg.strip("\\").strip()
                if not pkg or pkg.startswith("-"):
                    continue
                name, _, ver = pkg.partition("=")
                components.append(Component(name=name, version=ver or "unpinned",
                                             purl=f"pkg:{pkg_type}/{name}@{ver or 'unpinned'}",
                                             package_type=pkg_type))
    return components


# ════════════════════════════════════════════════════════════════════════════
#  Orquestração
# ════════════════════════════════════════════════════════════════════════════

_MANIFEST_PARSERS = {
    "composer.json": parse_composer_json,
    "composer.lock": parse_composer_lock,
    "Gemfile": parse_gemfile,
    "Gemfile.lock": parse_gemfile_lock,
    "packages.config": parse_packages_config,
    "pubspec.yaml": parse_pubspec_yaml,
    "Package.resolved": parse_package_resolved,
    "Podfile.lock": parse_podfile_lock,
    "Cartfile.resolved": parse_cartfile_resolved,
    "conanfile.txt": parse_conanfile_txt,
    "vcpkg.json": parse_vcpkg_json,
    "mix.exs": parse_mix_exs,
    "cpanfile": parse_cpanfile,
    "DESCRIPTION": parse_description_cran,
    "environment.yml": parse_conda_environment,
    "Chart.yaml": parse_helm_chart_yaml,
    "Dockerfile": parse_dockerfile,
}


def collect_extended_components(directory: str) -> List[Component]:
    components: List[Component] = []
    seen: set = set()
    for fname, parser in _MANIFEST_PARSERS.items():
        for mpath in Path(directory).rglob(fname):
            try:
                content = mpath.read_text(encoding="utf-8", errors="replace")
                for c in parser(content):
                    key = (c.purl, str(mpath))
                    if key not in seen:
                        seen.add(key)
                        components.append(c)
            except (OSError, PermissionError):
                pass
    return components
