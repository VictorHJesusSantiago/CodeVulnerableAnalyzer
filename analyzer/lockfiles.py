"""
Parsers de lockfiles reais (formato exato de cada ferramenta) + construção
de árvore de dependências transitivas a partir da informação já resolvida
nos próprios lockfiles (eles guardam a resolução completa, então "resolver
transitivamente" aqui significa reconstruir o grafo pai→filho a partir do
que o lockfile já registrou — não reimplementamos um resolver de versões).

Formatos suportados:
  - package-lock.json (npm v1/v2/v3)
  - yarn.lock (formato próprio, parser dedicado)
  - poetry.lock (TOML)
  - Pipfile.lock (JSON)
  - Cargo.lock (TOML)
  - go.sum
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class LockedPackage:
    name: str
    version: str
    ecosystem: str
    dependencies: List[str] = field(default_factory=list)  # nomes de deps diretas (quando disponível)
    integrity: Optional[str] = None


@dataclass
class DependencyTree:
    packages: Dict[str, LockedPackage] = field(default_factory=dict)  # nome -> pacote
    edges: Dict[str, Set[str]] = field(default_factory=dict)          # pai -> filhos

    def add(self, pkg: LockedPackage) -> None:
        self.packages[pkg.name] = pkg
        for dep in pkg.dependencies:
            self.edges.setdefault(pkg.name, set()).add(dep)

    def transitive_of(self, name: str, max_depth: int = 20) -> Set[str]:
        seen: Set[str] = set()
        frontier = {name}
        depth = 0
        while frontier and depth < max_depth:
            nxt: Set[str] = set()
            for n in frontier:
                for child in self.edges.get(n, set()):
                    if child not in seen:
                        seen.add(child)
                        nxt.add(child)
            frontier = nxt
            depth += 1
        return seen

    def depth(self) -> int:
        """Profundidade máxima da árvore (aproximada via BFS a partir de raízes
        — pacotes que não são dependência de ninguém)."""
        all_children = {c for kids in self.edges.values() for c in kids}
        roots = [n for n in self.packages if n not in all_children] or list(self.packages)
        max_d = 0
        for root in roots:
            visited = {root}
            frontier = {root}
            d = 0
            while frontier:
                nxt = set()
                for n in frontier:
                    for c in self.edges.get(n, set()):
                        if c not in visited:
                            visited.add(c)
                            nxt.add(c)
                frontier = nxt
                if frontier:
                    d += 1
            max_d = max(max_d, d)
        return max_d

    def summary(self) -> dict:
        return {
            "total_packages": len(self.packages),
            "total_edges": sum(len(v) for v in self.edges.values()),
            "max_depth": self.depth(),
        }


# ════════════════════════════════════════════════════════════════════════════
#  package-lock.json (npm)
# ════════════════════════════════════════════════════════════════════════════

def parse_package_lock_json(content: str) -> DependencyTree:
    tree = DependencyTree()
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return tree

    version = data.get("lockfileVersion", 1)

    if version >= 2 and "packages" in data:
        # npm v7+: chave é o caminho ("node_modules/pkg"), valor tem version/dependencies
        for path, info in data["packages"].items():
            if not path or path == "":
                continue
            name = path.split("node_modules/")[-1]
            ver = info.get("version", "")
            deps = list(info.get("dependencies", {}).keys()) + list(info.get("devDependencies", {}).keys())
            tree.add(LockedPackage(name=name, version=ver, ecosystem="npm",
                                    dependencies=deps, integrity=info.get("integrity")))
    else:
        # npm v1: chave "dependencies" recursiva
        def walk(deps: dict) -> None:
            for name, info in deps.items():
                ver = info.get("version", "")
                sub_deps = list(info.get("requires", {}).keys())
                tree.add(LockedPackage(name=name, version=ver, ecosystem="npm",
                                        dependencies=sub_deps, integrity=info.get("integrity")))
                if "dependencies" in info:
                    walk(info["dependencies"])
        walk(data.get("dependencies", {}))

    return tree


# ════════════════════════════════════════════════════════════════════════════
#  yarn.lock (formato próprio — blocos separados por linha em branco)
# ════════════════════════════════════════════════════════════════════════════

_YARN_HEADER_RE = re.compile(r'^"?([^,"]+)@')
_YARN_VERSION_RE = re.compile(r'^\s+version\s+"([^"]+)"')
_YARN_DEP_SECTION_RE = re.compile(r'^\s+dependencies:\s*$')
_YARN_DEP_ITEM_RE = re.compile(r'^\s{4,}"?([^\s"@]+)"?\s+"[^"]+"\s*$')


def parse_yarn_lock(content: str) -> DependencyTree:
    tree = DependencyTree()
    lines = content.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("#") or not line.strip():
            i += 1
            continue
        header_match = _YARN_HEADER_RE.match(line)
        if header_match and line.endswith(":"):
            name = header_match.group(1).strip('"')
            version = ""
            deps: List[str] = []
            i += 1
            in_deps = False
            while i < len(lines) and lines[i].startswith((" ", "\t")):
                sub = lines[i]
                vm = _YARN_VERSION_RE.match(sub)
                if vm:
                    version = vm.group(1)
                if _YARN_DEP_SECTION_RE.match(sub):
                    in_deps = True
                elif in_deps:
                    dm = _YARN_DEP_ITEM_RE.match(sub)
                    if dm:
                        deps.append(dm.group(1))
                    elif sub.strip() and not sub.startswith("    "):
                        in_deps = False
                i += 1
            tree.add(LockedPackage(name=name, version=version, ecosystem="npm", dependencies=deps))
            continue
        i += 1
    return tree


# ════════════════════════════════════════════════════════════════════════════
#  poetry.lock (TOML) — parser TOML mínimo suficiente para este formato
# ════════════════════════════════════════════════════════════════════════════

def _parse_toml_simple(content: str) -> List[dict]:
    """Parser TOML simplificado para arrays de tabelas [[package]] com pares
    chave=valor de uma linha, incluindo arrays multi-linha (suficiente para
    poetry.lock/Cargo.lock)."""
    entries: List[dict] = []
    current: Optional[dict] = None
    in_target_table = False
    in_array_key: Optional[str] = None
    array_items: List[str] = []

    def _flush_array() -> None:
        nonlocal in_array_key, array_items
        if in_array_key is not None and current is not None:
            current[in_array_key] = array_items
        in_array_key = None
        array_items = []

    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        if in_array_key is not None:
            if line.startswith("]"):
                _flush_array()
                continue
            item = line.rstrip(",").strip().strip('"')
            # Formatos "nome versão" ou "nome" — mantém só o nome do pacote
            item = item.split(" ")[0].strip('"')
            if item:
                array_items.append(item)
            continue

        if line.startswith("[["):
            table_name = line.strip("[]")
            if current is not None:
                entries.append(current)
            if table_name == "package":
                current = {}
                in_target_table = True
            else:
                current = None
                in_target_table = False
            continue
        if line.startswith("["):
            if current is not None:
                entries.append(current)
            current = None
            in_target_table = False
            continue

        if in_target_table and current is not None and "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if value.startswith("[") and value.endswith("]") and value != "[]":
                items = [v.strip().strip('"').split(" ")[0] for v in value[1:-1].split(",") if v.strip()]
                current[key] = items
            elif value == "[]":
                current[key] = []
            elif value.startswith("["):
                # Array multi-linha: acumula até encontrar ']'
                in_array_key = key
                array_items = []
            else:
                current[key] = value.strip('"')
    _flush_array()
    if current is not None:
        entries.append(current)
    return entries


def parse_poetry_lock(content: str) -> DependencyTree:
    tree = DependencyTree()
    for entry in _parse_toml_simple(content):
        name = entry.get("name")
        if not name:
            continue
        version = entry.get("version", "")
        tree.add(LockedPackage(name=name, version=version, ecosystem="pypi"))
    return tree


def parse_cargo_lock(content: str) -> DependencyTree:
    tree = DependencyTree()
    for entry in _parse_toml_simple(content):
        name = entry.get("name")
        if not name:
            continue
        version = entry.get("version", "")
        deps_raw = entry.get("dependencies", [])
        deps = [d.split(" ")[0] for d in deps_raw] if isinstance(deps_raw, list) else []
        tree.add(LockedPackage(name=name, version=version, ecosystem="cargo", dependencies=deps))
    return tree


# ════════════════════════════════════════════════════════════════════════════
#  Pipfile.lock (JSON)
# ════════════════════════════════════════════════════════════════════════════

def parse_pipfile_lock(content: str) -> DependencyTree:
    tree = DependencyTree()
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return tree
    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            version = str(info.get("version", "")).lstrip("=")
            tree.add(LockedPackage(name=name, version=version, ecosystem="pypi"))
    return tree


# ════════════════════════════════════════════════════════════════════════════
#  go.sum
# ════════════════════════════════════════════════════════════════════════════

_GOSUM_LINE_RE = re.compile(r'^(\S+)\s+(v\S+?)(?:/go\.mod)?\s+(h1:\S+)$')


def parse_go_sum(content: str) -> DependencyTree:
    tree = DependencyTree()
    for line in content.splitlines():
        m = _GOSUM_LINE_RE.match(line.strip())
        if m:
            module, version, hashsum = m.groups()
            tree.add(LockedPackage(name=module, version=version.lstrip("v"),
                                    ecosystem="go", integrity=hashsum))
    return tree


# ════════════════════════════════════════════════════════════════════════════
#  Orquestração
# ════════════════════════════════════════════════════════════════════════════

_LOCKFILE_PARSERS = {
    "package-lock.json": parse_package_lock_json,
    "yarn.lock": parse_yarn_lock,
    "poetry.lock": parse_poetry_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "Cargo.lock": parse_cargo_lock,
    "go.sum": parse_go_sum,
}


def parse_lockfile(file_path: str, content: str) -> Optional[DependencyTree]:
    fname = Path(file_path).name
    parser = _LOCKFILE_PARSERS.get(fname)
    return parser(content) if parser else None


def build_dependency_tree(directory: str) -> DependencyTree:
    """Constrói (mescla) a árvore de dependências de todos os lockfiles
    suportados encontrados em um diretório."""
    merged = DependencyTree()
    for fname, parser in _LOCKFILE_PARSERS.items():
        for lockfile in Path(directory).rglob(fname):
            try:
                content = lockfile.read_text(encoding="utf-8", errors="replace")
            except (OSError, PermissionError):
                continue
            partial = parser(content)
            merged.packages.update(partial.packages)
            for parent, children in partial.edges.items():
                merged.edges.setdefault(parent, set()).update(children)
    return merged
