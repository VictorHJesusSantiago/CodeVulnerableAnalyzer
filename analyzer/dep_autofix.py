"""
"Bump plan" estilo Dependabot/Renovate — sem nenhuma operação git. Gera:
  1. O conteúdo atualizado do manifesto (requirements.txt/package.json) com
     as versões corrigidas.
  2. Um unified diff (formato padrão, aplicável com `patch`/`git apply`) entre
     o conteúdo original e o corrigido.

Isso permite ao usuário revisar e aplicar manualmente (ou integrar num fluxo
de PR próprio) sem que esta ferramenta jamais toque no repositório git.
"""
from __future__ import annotations
import difflib
import re
from dataclasses import dataclass
from typing import Dict, List

from analyzer.deps import DepVuln


@dataclass
class BumpPlanEntry:
    package: str
    from_version: str
    to_version: str
    cve_ids: List[str]


@dataclass
class BumpPlan:
    entries: List[BumpPlanEntry]
    updated_content: str
    diff: str


def _plan_from_vulns(vulns: List[DepVuln]) -> Dict[str, BumpPlanEntry]:
    """Para cada pacote, escolhe a MAIOR fixed_version entre todos os CVEs
    reportados (corrige todos de uma vez)."""
    from analyzer.deps import _ver_lt

    plan: Dict[str, BumpPlanEntry] = {}
    for v in vulns:
        if v.package not in plan:
            plan[v.package] = BumpPlanEntry(v.package, v.installed_version, v.fixed_version, [v.cve_id])
        else:
            entry = plan[v.package]
            entry.cve_ids.append(v.cve_id)
            if _ver_lt(entry.to_version, v.fixed_version):
                entry.to_version = v.fixed_version
    return plan


def _bump_requirements_txt(content: str, plan: Dict[str, BumpPlanEntry]) -> str:
    lines = content.splitlines(keepends=True)
    out = []
    for line in lines:
        stripped = line.strip()
        m = re.match(r'^([A-Za-z0-9_.\-]+)', stripped)
        if m and m.group(1).lower() in {k.lower() for k in plan}:
            pkg_key = next(k for k in plan if k.lower() == m.group(1).lower())
            newline_suffix = "\n" if line.endswith("\n") else ""
            comment = ""
            if "#" in line:
                comment = "  #" + line.split("#", 1)[1].rstrip("\n")
            out.append(f"{m.group(1)}=={plan[pkg_key].to_version}{comment}{newline_suffix}")
        else:
            out.append(line)
    return "".join(out)


def _bump_package_json(content: str, plan: Dict[str, BumpPlanEntry]) -> str:
    import json
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return content
    for section in ("dependencies", "devDependencies"):
        if section not in data:
            continue
        for pkg in list(data[section].keys()):
            match = next((k for k in plan if k.lower() == pkg.lower()), None)
            if match:
                current_spec = data[section][pkg]
                prefix = "^" if current_spec.startswith("^") else ("~" if current_spec.startswith("~") else "")
                data[section][pkg] = f"{prefix}{plan[match].to_version}"
    return json.dumps(data, indent=2) + "\n"


def build_bump_plan(manifest_path: str, manifest_content: str, vulns: List[DepVuln]) -> BumpPlan:
    plan_dict = _plan_from_vulns(vulns)
    if not plan_dict:
        return BumpPlan(entries=[], updated_content=manifest_content, diff="")

    name = manifest_path.split("/")[-1].split("\\")[-1]
    if name.startswith("requirements"):
        updated = _bump_requirements_txt(manifest_content, plan_dict)
    elif name == "package.json":
        updated = _bump_package_json(manifest_content, plan_dict)
    else:
        updated = manifest_content  # formato sem suporte de auto-edição

    diff_lines = list(difflib.unified_diff(
        manifest_content.splitlines(keepends=True),
        updated.splitlines(keepends=True),
        fromfile=f"a/{name}", tofile=f"b/{name}",
    ))
    return BumpPlan(entries=list(plan_dict.values()), updated_content=updated, diff="".join(diff_lines))
