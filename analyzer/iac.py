"""Análise estrutural de IaC, planos Terraform, drift e blast radius IAM."""
from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

WILDCARDS = {"*", "*:*"}

@dataclass
class Resource:
    id: str
    kind: str
    provider: str = "generic"
    attributes: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)

@dataclass
class Finding:
    rule_id: str
    severity: str
    resource: str
    message: str
    benchmark: str = ""
    remediation: str = ""

def parse_terraform_plan(source: str | Path | Dict[str, Any]) -> List[Resource]:
    """Normaliza o JSON produzido por ``terraform show -json``."""
    if isinstance(source, dict):
        doc = source
    else:
        raw = Path(source).read_text(encoding="utf-8") if Path(str(source)).exists() else str(source)
        doc = json.loads(raw)
    resources: List[Resource] = []
    def walk(module: Dict[str, Any]) -> None:
        for item in module.get("resources", []):
            values = item.get("values") or {}
            deps = item.get("depends_on") or []
            resources.append(Resource(item.get("address", item.get("name", "unknown")),
                                      item.get("type", "unknown"),
                                      item.get("provider_name", "terraform"),
                                      values, list(deps)))
        for child in module.get("child_modules", []):
            walk(child)
    walk(doc.get("planned_values", {}).get("root_module", {}))
    return resources

def terraform_changes(source: str | Dict[str, Any]) -> Dict[str, List[str]]:
    doc = source if isinstance(source, dict) else json.loads(source)
    out = {"create": [], "update": [], "delete": [], "replace": [], "no-op": []}
    for change in doc.get("resource_changes", []):
        actions = change.get("change", {}).get("actions", [])
        key = "replace" if set(actions) == {"delete", "create"} else (actions[0] if len(actions) == 1 else "update")
        out.setdefault(key, []).append(change.get("address", "unknown"))
    return out

class ResourceGraph:
    def __init__(self, resources: Iterable[Resource]):
        self.resources = {r.id: r for r in resources}
        self.edges = {r.id: set(r.dependencies) for r in resources}

    def dependents(self, resource_id: str, transitive: bool = True) -> Set[str]:
        found, frontier = set(), {resource_id}
        while frontier:
            current = frontier.pop()
            direct = {node for node, deps in self.edges.items() if current in deps}
            new = direct - found
            found |= new
            if transitive:
                frontier |= new
        return found

    def blast_radius(self, resource_id: str) -> Dict[str, Any]:
        affected = self.dependents(resource_id)
        return {"resource": resource_id, "affected": sorted(affected), "score": len(affected)}

    def to_dict(self) -> Dict[str, Any]:
        return {"nodes": [asdict(r) for r in self.resources.values()],
                "edges": [{"from": dep, "to": node} for node, deps in self.edges.items() for dep in deps]}

def detect_drift(desired: Iterable[Resource], actual: Iterable[Resource]) -> Dict[str, Any]:
    want, have = ({r.id: r for r in group} for group in (desired, actual))
    missing = sorted(set(want) - set(have))
    unmanaged = sorted(set(have) - set(want))
    changed = []
    for rid in set(want) & set(have):
        keys = set(want[rid].attributes) | set(have[rid].attributes)
        delta = {k: {"desired": want[rid].attributes.get(k), "actual": have[rid].attributes.get(k)}
                 for k in keys if want[rid].attributes.get(k) != have[rid].attributes.get(k)}
        if delta:
            changed.append({"resource": rid, "attributes": delta})
    return {"missing": missing, "unmanaged": unmanaged, "changed": changed,
            "drifted": bool(missing or unmanaged or changed)}

def iam_blast_radius(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Estima privilégio e alcance de uma policy AWS/Azure/GCP normalizada."""
    statements = policy.get("Statement", policy.get("statements", []))
    if isinstance(statements, dict):
        statements = [statements]
    actions, resources, risks = set(), set(), []
    for stmt in statements:
        if str(stmt.get("Effect", "Allow")).lower() != "allow":
            continue
        a, r = stmt.get("Action", []), stmt.get("Resource", [])
        a = [a] if isinstance(a, str) else a
        r = [r] if isinstance(r, str) else r
        actions.update(a); resources.update(r)
        if "*" in a: risks.append("administrador global")
        if "*" in r: risks.append("recursos irrestritos")
        if any(x.lower().startswith(("iam:", "sts:assumerole", "organizations:")) for x in a):
            risks.append("escalada ou movimento lateral")
    score = min(100, len(actions) * 2 + len(resources) + 50 * ("*" in actions) + 30 * ("*" in resources))
    return {"score": score, "level": "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 20 else "low",
            "actions": sorted(actions), "resources": sorted(resources), "risks": sorted(set(risks))}

def cis_evaluate(resources: Iterable[Resource]) -> List[Finding]:
    findings = []
    for r in resources:
        a, kind = r.attributes, r.kind.lower()
        if "security_group" in kind and any(x in ("0.0.0.0/0", "::/0") for x in _flatten(a)):
            findings.append(Finding("CIS-AWS-5.2", "high", r.id, "Security group expõe serviço para toda a Internet", "CIS AWS"))
        if ("bucket" in kind or "storage" in kind) and str(a.get("public_access", a.get("acl", ""))).lower() in ("true", "public-read"):
            findings.append(Finding("CIS-CLOUD-STORAGE-1", "critical", r.id, "Armazenamento público", "CIS AWS/Azure/GCP"))
        if "pod" in kind or "deployment" in kind:
            sec = a.get("securityContext", a.get("security_context", {})) or {}
            if sec.get("runAsNonRoot") is not True:
                findings.append(Finding("CIS-K8S-5.2.6", "high", r.id, "Workload não exige usuário não-root", "CIS Kubernetes"))
    return findings

def _flatten(value: Any) -> List[str]:
    if isinstance(value, dict): return sum((_flatten(v) for v in value.values()), [])
    if isinstance(value, list): return sum((_flatten(v) for v in value), [])
    return [str(value)]
