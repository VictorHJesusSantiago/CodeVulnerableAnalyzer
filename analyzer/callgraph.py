"""
Call graph cross-arquivo para Python (via `ast`, stdlib), com:
  - Impact analysis: dado o nome de uma função, quem a chama (direto e
    transitivamente) em todo o diretório.
  - Taint interprocedural: propaga taint de argumentos de chamada para
    parâmetros do calee, e do valor de retorno do calee de volta para o
    call-site no caller, por ponto fixo sobre o grafo de chamadas.

Escopo declarado honestamente: a resolução de chamada é por NOME de função
(heurística padrão em ferramentas estáticas sem inferência de tipos completa
— mesma limitação de tools como pylint/vulture). Não resolve overloads,
dynamic dispatch complexo ou funções de mesmo nome em classes diferentes
como entidades distintas (elas são tratadas como o mesmo nó do grafo).
"""
from __future__ import annotations
import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from analyzer.models import (
    Language, Severity, Vulnerability, VulnCategory, Confidence
)

# Reaproveita os padrões de taint já usados no engine principal
_TAINT_SOURCE_RE = re.compile(
    r'\b(\w+)\s*=\s*(?:'
    r'request\.(?:args|form|json|data|values|get|params|cookies|headers)\b|'
    r'sys\.argv\[|input\s*\(|os\.environ\b|os\.getenv\s*\('
    r')'
)
_SINK_FUNCS = {"eval", "exec", "os.system", "subprocess.run", "subprocess.call",
               "subprocess.Popen", "cursor.execute", "engine.execute", "__import__"}


@dataclass
class FuncNode:
    name: str
    qualname: str
    file_path: str
    lineno: int
    node: ast.AST
    params: List[str]
    calls: List[Tuple[str, ast.Call]] = field(default_factory=list)   # (callee_name, call_node)
    tainted_params: Set[str] = field(default_factory=set)
    returns_tainted: bool = False


class CallGraph:
    def __init__(self):
        # nome -> lista de FuncNode (pode haver múltiplas defs com mesmo nome)
        self.functions: Dict[str, List[FuncNode]] = {}
        # edges: nome_chamador -> set(nome_chamado)
        self.edges: Dict[str, Set[str]] = {}
        self.reverse_edges: Dict[str, Set[str]] = {}

    # ── Construção ──────────────────────────────────────────────────────────
    def add_file(self, file_path: str, content: str) -> None:
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = [a.arg for a in node.args.args]
            fn = FuncNode(
                name=node.name, qualname=f"{Path(file_path).stem}.{node.name}",
                file_path=file_path, lineno=node.lineno, node=node, params=params,
            )
            for call in ast.walk(node):
                if isinstance(call, ast.Call):
                    callee = self._callee_name(call)
                    if callee:
                        fn.calls.append((callee, call))
            self.functions.setdefault(node.name, []).append(fn)

        for fname, defs in self.functions.items():
            for fn in defs:
                for callee, _ in fn.calls:
                    self.edges.setdefault(fname, set()).add(callee)
                    self.reverse_edges.setdefault(callee, set()).add(fname)

    @staticmethod
    def _callee_name(call: ast.Call) -> Optional[str]:
        f = call.func
        if isinstance(f, ast.Name):
            return f.id
        if isinstance(f, ast.Attribute):
            return f.attr
        return None

    # ── Impact analysis ─────────────────────────────────────────────────────
    def callers(self, func_name: str) -> Set[str]:
        return set(self.reverse_edges.get(func_name, set()))

    def callers_transitive(self, func_name: str, max_depth: int = 10) -> Set[str]:
        seen: Set[str] = set()
        frontier = {func_name}
        depth = 0
        while frontier and depth < max_depth:
            next_frontier: Set[str] = set()
            for f in frontier:
                for caller in self.reverse_edges.get(f, set()):
                    if caller not in seen:
                        seen.add(caller)
                        next_frontier.add(caller)
            frontier = next_frontier
            depth += 1
        return seen

    def callees_transitive(self, func_name: str, max_depth: int = 10) -> Set[str]:
        seen: Set[str] = set()
        frontier = {func_name}
        depth = 0
        while frontier and depth < max_depth:
            next_frontier: Set[str] = set()
            for f in frontier:
                for callee in self.edges.get(f, set()):
                    if callee not in seen:
                        seen.add(callee)
                        next_frontier.add(callee)
            frontier = next_frontier
            depth += 1
        return seen

    def impact_report(self, func_name: str) -> dict:
        direct = self.callers(func_name)
        transitive = self.callers_transitive(func_name)
        return {
            "function": func_name,
            "defined_in": [fn.file_path for fn in self.functions.get(func_name, [])],
            "direct_callers": sorted(direct),
            "transitive_callers": sorted(transitive),
            "total_impact": len(transitive),
        }

    def summary(self) -> dict:
        return {
            "total_functions": sum(len(v) for v in self.functions.values()),
            "unique_names": len(self.functions),
            "total_edges": sum(len(v) for v in self.edges.values()),
        }

    # ── Taint interprocedural (ponto fixo sobre o grafo) ────────────────────
    def _intraproc_tainted_vars(self, fn: FuncNode) -> Set[str]:
        """Variáveis contaminadas dentro do corpo de fn, considerando também
        os parâmetros já marcados como tainted (por chamadas anteriores)."""
        tainted: Set[str] = set(fn.tainted_params)
        for node in ast.walk(fn.node):
            if isinstance(node, ast.Assign):
                src = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
                rhs_names = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
                if rhs_names & tainted or _TAINT_SOURCE_RE.search(_line_of(fn, node.lineno)):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            tainted.add(t.id)
        return tainted

    def analyze_taint(self, max_iterations: int = 5) -> List[Vulnerability]:
        """Fixed-point: propaga taint de argumentos->parâmetros e de
        retorno->call-site, então reporta quando um parâmetro tainted
        alcança um sink dentro do calee."""
        findings: List[Vulnerability] = []

        for _ in range(max_iterations):
            changed = False

            for fname, defs in self.functions.items():
                for fn in defs:
                    tainted_vars = self._intraproc_tainted_vars(fn)

                    # Retorno contaminado?
                    for node in ast.walk(fn.node):
                        if isinstance(node, ast.Return) and node.value is not None:
                            ret_names = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
                            if ret_names & tainted_vars and not fn.returns_tainted:
                                fn.returns_tainted = True
                                changed = True

                    # Propaga para os calees: argumento tainted -> parâmetro do calee
                    for callee_name, call_node in fn.calls:
                        callee_defs = self.functions.get(callee_name, [])
                        if not callee_defs:
                            continue
                        for i, arg in enumerate(call_node.args):
                            arg_names = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
                            is_tainted_arg = bool(arg_names & tainted_vars)
                            if not is_tainted_arg:
                                continue
                            for callee_fn in callee_defs:
                                if i < len(callee_fn.params):
                                    pname = callee_fn.params[i]
                                    if pname not in callee_fn.tainted_params:
                                        callee_fn.tainted_params.add(pname)
                                        changed = True

            if not changed:
                break

        # ── Geração dos achados: parâmetro tainted alcançando sink no calee ──
        seen_keys: Set[tuple] = set()
        for fname, defs in self.functions.items():
            for fn in defs:
                if not fn.tainted_params:
                    continue
                tainted_vars = self._intraproc_tainted_vars(fn)
                for node in ast.walk(fn.node):
                    if isinstance(node, ast.Call):
                        sink_name = self._sink_dotted_name(node)
                        if sink_name in _SINK_FUNCS or (isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec")):
                            used = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} & tainted_vars
                            if used:
                                key = (fn.file_path, node.lineno, sink_name)
                                if key in seen_keys:
                                    continue
                                seen_keys.add(key)
                                findings.append(Vulnerability(
                                    rule_id="INTERPROC-TAINT-001",
                                    name=f"Taint Interprocedural até Sink ({sink_name or 'call'})",
                                    description=(
                                        f"A função '{fn.name}' recebe um parâmetro contaminado "
                                        f"({', '.join(sorted(used))}) — propagado a partir de um "
                                        f"call-site em outra função/arquivo através do call graph "
                                        f"— e o utiliza em '{sink_name}' na linha {node.lineno}, "
                                        f"sem sanitização aparente."
                                    ),
                                    severity=Severity.HIGH, category=VulnCategory.CODE_INJECTION,
                                    language=Language.PYTHON, file_path=fn.file_path,
                                    line_number=node.lineno,
                                    line_content=_line_of(fn, node.lineno),
                                    remediation="Sanitize o parâmetro no início da função ou no call-site antes de repassá-lo; use APIs parametrizadas no sink.",
                                    cwe="CWE-20", owasp="A03:2021 - Injection", confidence=Confidence.MEDIUM,
                                ))
        return findings

    @staticmethod
    def _sink_dotted_name(call: ast.Call) -> str:
        f = call.func
        if isinstance(f, ast.Name):
            return f.id
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            return f"{f.value.id}.{f.attr}"
        if isinstance(f, ast.Attribute):
            return f.attr
        return ""


def _line_of(fn: FuncNode, lineno: int) -> str:
    try:
        return Path(fn.file_path).read_text(encoding="utf-8", errors="replace").splitlines()[lineno - 1].strip()
    except Exception:
        return ""


def build_call_graph(directory: str) -> CallGraph:
    """Constrói o call graph para todos os arquivos .py de um diretório."""
    cg = CallGraph()
    for py_file in Path(directory).rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            continue
        cg.add_file(str(py_file), content)
    return cg
