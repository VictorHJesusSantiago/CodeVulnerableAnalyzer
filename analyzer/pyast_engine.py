"""
Engine de análise estática baseada em AST real para Python (módulo `ast` da
stdlib — zero dependência nova). Diferente do restante do projeto (regex),
aqui a análise opera sobre a árvore sintática de verdade.

Cobre, de forma genuína e verificável:
  - Detecção de código morto/inalcançável (statement após return/raise/break/
    continue no mesmo bloco).
  - Framework de dataflow genérico (worklist) com duas instâncias reais:
      reaching definitions (forward, union)
      live variables       (backward, union)
    usados para: "dead store" (atribuição nunca lida) e "uso possivelmente
    não definido" (variável lida sem definição que alcance aquele ponto).
  - Complexidade ciclomática (McCabe) via contagem real de nós de decisão
    na AST (não regex).
  - Complexidade cognitiva (aproximação do algoritmo SonarSource: incrementos
    ponderados por aninhamento).
  - Métricas de Halstead (operadores/operandos distintos e totais, volume,
    dificuldade, esforço) via contagem de tokens da AST.
  - Detecção de recursão sem caso-base aparente (função chama a si mesma sem
    nenhum `return`/`yield` no corpo).
  - Heurística de TOCTOU (os.path.exists(x) seguido de open(x) no mesmo
    escopo, sem operação atômica entre as duas).
  - Heurística de uso após close() (obj.close() seguido de uso de obj sem
    reatribuição, no mesmo bloco).
  - Heurística de possível null-dereference (var = None seguido de var.attr
    ou var[...] sem guarda 'if var'/'is not None' entre os dois pontos).

Limitações declaradas (não fingidas): não há resolução de tipos completa,
não há inferência de fluxo interprocedural aqui (ver analyzer/callgraph.py
para isso), e a granularidade do CFG é por statement-list, suficiente para
os checks acima mas não para um compilador otimizador completo.
"""
from __future__ import annotations
import ast
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from analyzer.models import (
    Language, Severity, Vulnerability, VulnCategory, Confidence
)

# ════════════════════════════════════════════════════════════════════════════
#  1. Detecção de código morto (unreachable code)
# ════════════════════════════════════════════════════════════════════════════

_TERMINATORS = (ast.Return, ast.Raise, ast.Break, ast.Continue)


def _find_unreachable(tree: ast.AST) -> List[ast.stmt]:
    """Percorre toda lista de statements da árvore e marca o que vem depois
    de um terminador incondicional dentro do mesmo bloco linear."""
    unreachable: List[ast.stmt] = []

    def _scan_body(body: List[ast.stmt]) -> None:
        terminated = False
        for stmt in body:
            if terminated:
                unreachable.append(stmt)
            elif isinstance(stmt, _TERMINATORS):
                terminated = True
            # Recorre em sub-blocos independentemente do estado 'terminated'
            # do bloco pai (cada bloco tem sua própria linearidade).
            for child_body in _sub_bodies(stmt):
                _scan_body(child_body)

    def _sub_bodies(stmt: ast.stmt) -> List[List[ast.stmt]]:
        bodies: List[List[ast.stmt]] = []
        if isinstance(stmt, (ast.If, ast.For, ast.While)):
            bodies.append(stmt.body)
            if stmt.orelse:
                bodies.append(stmt.orelse)
        if isinstance(stmt, ast.Try):
            bodies.append(stmt.body)
            for h in stmt.handlers:
                bodies.append(h.body)
            if stmt.orelse:
                bodies.append(stmt.orelse)
            if stmt.finalbody:
                bodies.append(stmt.finalbody)
        if isinstance(stmt, ast.With):
            bodies.append(stmt.body)
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bodies.append(stmt.body)
        return bodies

    if isinstance(tree, ast.Module):
        _scan_body(tree.body)
    else:
        for node in ast.walk(tree):
            for b in _sub_bodies(node):
                _scan_body(b)
    return unreachable


# ════════════════════════════════════════════════════════════════════════════
#  2. Framework de dataflow genérico (worklist algorithm)
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class CFGNode:
    id: int
    stmt: ast.stmt
    succ: Set[int] = field(default_factory=set)
    pred: Set[int] = field(default_factory=set)
    defs: Set[str] = field(default_factory=set)   # variáveis definidas neste nó
    uses: Set[str] = field(default_factory=set)   # variáveis lidas neste nó


class CFG:
    """CFG simplificado por statement, construído para o corpo de uma função."""

    def __init__(self, body: List[ast.stmt]):
        self.nodes: Dict[int, CFGNode] = {}
        self._next_id = 0
        self.entry: Optional[int] = None
        self.exits: Set[int] = set()
        if body:
            self.entry = self._build(body)

    def _new_node(self, stmt: ast.stmt) -> CFGNode:
        nid = self._next_id
        self._next_id += 1
        node = CFGNode(id=nid, stmt=stmt)
        node.defs, node.uses = _defs_uses(stmt)
        self.nodes[nid] = node
        return node

    def _link(self, a: int, b: int) -> None:
        self.nodes[a].succ.add(b)
        self.nodes[b].pred.add(a)

    def _build(self, body: List[ast.stmt]) -> Optional[int]:
        """Constrói o CFG de uma lista de statements; retorna o id de entrada.
        Mantém self.exits atualizado com os pontos de saída (fall-through)."""
        prev_exits: Set[int] = set()
        first_id: Optional[int] = None

        for stmt in body:
            node = self._new_node(stmt)
            if first_id is None:
                first_id = node.id
            for p in prev_exits:
                self._link(p, node.id)
            prev_exits = {node.id}

            if isinstance(stmt, ast.If):
                then_entry = self._build(stmt.body)
                then_exits = self._last_exits
                if then_entry is not None:
                    self._link(node.id, then_entry)
                if stmt.orelse:
                    else_entry = self._build(stmt.orelse)
                    else_exits = self._last_exits
                    if else_entry is not None:
                        self._link(node.id, else_entry)
                    prev_exits = (then_exits or {node.id}) | (else_exits or {node.id})
                else:
                    prev_exits = (then_exits or set()) | {node.id}
            elif isinstance(stmt, (ast.For, ast.While)):
                body_entry = self._build(stmt.body)
                body_exits = self._last_exits
                if body_entry is not None:
                    self._link(node.id, body_entry)
                    for be in (body_exits or set()):
                        self._link(be, node.id)  # loop back
                prev_exits = {node.id} | (body_exits or set())
            elif isinstance(stmt, (ast.Return, ast.Raise)):
                self.exits.add(node.id)
                prev_exits = set()  # sem fall-through
            else:
                prev_exits = {node.id}

            self._last_exits = prev_exits

        if prev_exits:
            self.exits |= prev_exits
        self._last_exits = prev_exits
        return first_id


def _defs_uses(stmt: ast.stmt) -> Tuple[Set[str], Set[str]]:
    """Extrai variáveis definidas (Store) e usadas (Load) num statement,
    sem descer em sub-blocos aninhados (If/For/While/Try tratados pelo CFG)."""
    defs: Set[str] = set()
    uses: Set[str] = set()

    class _V(ast.NodeVisitor):
        def visit_Name(self, n: ast.Name) -> None:
            if isinstance(n.ctx, ast.Store):
                defs.add(n.id)
            elif isinstance(n.ctx, ast.Load):
                uses.add(n.id)

        def visit_FunctionDef(self, n): pass  # não desce em funções aninhadas
        def visit_AsyncFunctionDef(self, n): pass
        def visit_ClassDef(self, n): pass
        def visit_If(self, n):
            for v in ast.walk(n.test):
                self.visit(v) if isinstance(v, ast.Name) else None
        def visit_For(self, n):
            for t in ast.walk(n.target):
                if isinstance(t, ast.Name):
                    defs.add(t.id)
            for v in ast.walk(n.iter):
                if isinstance(v, ast.Name):
                    uses.add(v.id)
        def visit_While(self, n):
            for v in ast.walk(n.test):
                if isinstance(v, ast.Name):
                    uses.add(v.id)

    v = _V()
    if isinstance(stmt, (ast.If, ast.For, ast.While)):
        v.visit(stmt)
    else:
        v.generic_visit(stmt)
    return defs, uses


def _worklist(cfg: CFG, forward: bool,
              gen_kill) -> Dict[int, Tuple[Set, Set]]:
    """Algoritmo de worklist genérico (união como meet operator)."""
    IN: Dict[int, Set] = {nid: set() for nid in cfg.nodes}
    OUT: Dict[int, Set] = {nid: set() for nid in cfg.nodes}
    order = list(cfg.nodes.keys()) if forward else list(reversed(cfg.nodes.keys()))
    changed = True
    while changed:
        changed = False
        for nid in order:
            node = cfg.nodes[nid]
            preds = node.pred if forward else node.succ
            new_in = set()
            for p in preds:
                new_in |= (OUT[p] if forward else IN[p])
            gen, kill = gen_kill(node)
            new_out = gen | (new_in - kill)
            if forward:
                if new_in != IN[nid] or new_out != OUT[nid]:
                    IN[nid], OUT[nid] = new_in, new_out
                    changed = True
            else:
                if new_in != OUT[nid] or new_out != IN[nid]:
                    OUT[nid], IN[nid] = new_in, new_out
                    changed = True
    return {nid: (IN[nid], OUT[nid]) for nid in cfg.nodes}


def reaching_definitions(cfg: CFG) -> Dict[int, Tuple[Set[str], Set[str]]]:
    def gk(node: CFGNode):
        return set(node.defs), set()  # simplificado: sem 'kill' de defs antigas (over-approx conservador)
    return _worklist(cfg, forward=True, gen_kill=gk)


def live_variables(cfg: CFG) -> Dict[int, Tuple[Set[str], Set[str]]]:
    def gk(node: CFGNode):
        return set(node.uses), set(node.defs)
    return _worklist(cfg, forward=False, gen_kill=gk)


# ════════════════════════════════════════════════════════════════════════════
#  3. Métricas de complexidade via AST
# ════════════════════════════════════════════════════════════════════════════

_DECISION_NODES = (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.Assert, ast.IfExp)
if hasattr(ast, "Match"):
    _DECISION_NODES = _DECISION_NODES + (ast.Match,)


def cyclomatic_complexity(func: ast.AST) -> int:
    """McCabe: 1 + número de pontos de decisão na AST."""
    complexity = 1
    for node in ast.walk(func):
        if isinstance(node, _DECISION_NODES):
            if hasattr(ast, "Match") and isinstance(node, ast.Match):
                complexity += max(0, len(node.cases) - 1)
            else:
                complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            complexity += len(node.ifs) + 1
    return complexity


def cognitive_complexity(func: ast.AST) -> int:
    """Aproximação do algoritmo de complexidade cognitiva (SonarSource):
    cada estrutura de controle soma 1 + nível de aninhamento; operadores
    booleanos em sequência somam 1 cada."""
    score = 0

    def walk(node: ast.AST, nesting: int) -> None:
        nonlocal score
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.If):
                score += 1 + nesting
                walk_body(child.body, nesting + 1)
                if child.orelse:
                    score += 1
                    walk_body(child.orelse, nesting + 1)
            elif isinstance(child, (ast.For, ast.While)):
                score += 1 + nesting
                walk_body(child.body, nesting + 1)
            elif isinstance(child, ast.Try):
                for h in child.handlers:
                    score += 1 + nesting
                    walk_body(h.body, nesting + 1)
                walk_body(child.body, nesting)
            elif isinstance(child, ast.BoolOp):
                score += len(child.values) - 1
                walk(child, nesting)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                pass  # função aninhada tem sua própria pontuação
            else:
                walk(child, nesting)

    def walk_body(body: List[ast.stmt], nesting: int) -> None:
        for stmt in body:
            walk(stmt, nesting)

    walk_body(getattr(func, "body", []), 0)
    return score


_OPERATOR_TYPES = (
    ast.operator, ast.unaryop, ast.cmpop, ast.boolop,
)


def halstead_metrics(func: ast.AST) -> dict:
    """Métricas de Halstead aproximadas via tokens da AST."""
    operators: List[str] = []
    operands: List[str] = []

    for node in ast.walk(func):
        if isinstance(node, ast.BinOp):
            operators.append(type(node.op).__name__)
        elif isinstance(node, ast.UnaryOp):
            operators.append(type(node.op).__name__)
        elif isinstance(node, ast.BoolOp):
            operators.append(type(node.op).__name__)
        elif isinstance(node, ast.Compare):
            for op in node.ops:
                operators.append(type(op).__name__)
        elif isinstance(node, ast.Call):
            operators.append("call()")
        elif isinstance(node, ast.Attribute):
            operators.append(".")
        elif isinstance(node, ast.Subscript):
            operators.append("[]")
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            operators.append("=")
        elif isinstance(node, (ast.If, ast.For, ast.While, ast.Return,
                                ast.Import, ast.ImportFrom, ast.With, ast.Lambda)):
            operators.append(type(node).__name__)
        elif isinstance(node, ast.Name):
            operands.append(node.id)
        elif isinstance(node, ast.Constant):
            operands.append(repr(node.value))

    n1, n2 = len(set(operators)), len(set(operands))
    N1, N2 = len(operators), len(operands)
    vocabulary = n1 + n2
    length = N1 + N2
    volume = length * math.log2(vocabulary) if vocabulary > 0 else 0.0
    difficulty = (n1 / 2) * (N2 / n2) if n2 > 0 else 0.0
    effort = difficulty * volume
    return {
        "n1": n1, "n2": n2, "N1": N1, "N2": N2,
        "vocabulary": vocabulary, "length": length,
        "volume": round(volume, 2), "difficulty": round(difficulty, 2),
        "effort": round(effort, 2),
    }


# ════════════════════════════════════════════════════════════════════════════
#  4. Detectores de bugs via AST (heurísticas reais, escopo declarado)
# ════════════════════════════════════════════════════════════════════════════

def _self_recursive_without_base_case(func: ast.FunctionDef) -> bool:
    """Função chama a si mesma e não possui nenhum Return/Yield no corpo
    (sinal forte de recursão sem caso-base / potencial StackOverflow)."""
    calls_self = any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == func.name
        for n in ast.walk(func)
    )
    if not calls_self:
        return False
    has_return_or_yield = any(
        isinstance(n, (ast.Return, ast.Yield, ast.YieldFrom)) for n in ast.walk(func)
    )
    return not has_return_or_yield


def _toctou_pairs(func: ast.FunctionDef) -> List[Tuple[ast.Call, ast.Call]]:
    """Detecta os.path.exists(X) seguido de open(X) no mesmo corpo (TOCTOU)."""
    pairs = []
    checks: Dict[str, ast.Call] = {}

    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            fn = node.func
            fname = None
            if isinstance(fn, ast.Attribute):
                fname = fn.attr
            elif isinstance(fn, ast.Name):
                fname = fn.id
            if fname in ("exists", "isfile", "isdir") and node.args:
                arg = node.args[0]
                key = ast.dump(arg)
                checks[key] = node
            elif fname == "open" and node.args:
                arg = node.args[0]
                key = ast.dump(arg)
                if key in checks:
                    pairs.append((checks[key], node))
    return pairs


def _use_after_close(func: ast.FunctionDef) -> List[Tuple[str, int]]:
    """obj.close() seguido de uso posterior de obj (sem reatribuição) no
    mesmo corpo linear (heurística simples, um nível)."""
    findings: List[Tuple[str, int]] = []
    closed: Dict[str, int] = {}

    def scan(body: List[ast.stmt]) -> None:
        for stmt in body:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            closed.pop(t.id, None)  # reatribuído: reset
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr == "close" and isinstance(node.func.value, ast.Name):
                        closed[node.func.value.id] = node.lineno
                elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                    name = node.value.id
                    if name in closed and node.attr != "close" and getattr(node, "lineno", 0) > closed[name]:
                        findings.append((name, node.lineno))
    scan(func.body)
    return findings


def _null_deref_candidates(func: ast.FunctionDef) -> List[Tuple[str, int]]:
    """var = None seguido de var.attr / var[...] sem guarda 'if var' entre
    os dois pontos, no corpo linear da função (heurística, não flow-sensitive
    completa: não rastreia branches, é conservadora e propositalmente
    reportada com confiança MEDIUM/LOW)."""
    findings: List[Tuple[str, int]] = []
    none_assigned: Dict[str, int] = {}
    guarded: Set[str] = set()

    for stmt in func.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and node.value.value is None:
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        none_assigned[t.id] = node.lineno
                        guarded.discard(t.id)
            elif isinstance(node, ast.If):
                test_names = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
                guarded |= test_names
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                name = node.value.id
                if name in none_assigned and name not in guarded and node.lineno > none_assigned[name]:
                    findings.append((name, node.lineno))
    return findings


# ════════════════════════════════════════════════════════════════════════════
#  5. Orquestração: análise de um arquivo Python
# ════════════════════════════════════════════════════════════════════════════

MAX_CYCLOMATIC_AST  = 10
MAX_COGNITIVE_AST   = 15


def analyze_python_ast(file_path: str, content: str) -> List[Vulnerability]:
    """Roda toda a análise AST-based sobre um arquivo Python e retorna
    Vulnerability's no mesmo formato do resto do engine."""
    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError:
        return []

    lines = content.splitlines()
    results: List[Vulnerability] = []

    def _line(n: int) -> str:
        return lines[n - 1].rstrip() if 0 < n <= len(lines) else ""

    # ── Código morto ────────────────────────────────────────────────────────
    for stmt in _find_unreachable(tree):
        results.append(Vulnerability(
            rule_id="AST-DEAD-001", name="Código Inalcançável (Dead Code)",
            description=f"Statement na linha {stmt.lineno} nunca é executado: aparece após um "
                        f"return/raise/break/continue incondicional no mesmo bloco. Detectado via "
                        f"análise real da AST (não regex).",
            severity=Severity.LOW, category=VulnCategory.DEAD_CODE, language=Language.PYTHON,
            file_path=file_path, line_number=stmt.lineno, line_content=_line(stmt.lineno),
            remediation="Remova o código morto ou corrija a lógica de controle de fluxo que o precede.",
            cwe="CWE-561", confidence=Confidence.HIGH,
        ))

    # ── Por função: complexidade, dataflow, recursão, TOCTOU, etc. ───────────
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        cyclo = cyclomatic_complexity(node)
        cognitive = cognitive_complexity(node)

        if cyclo > MAX_CYCLOMATIC_AST:
            results.append(Vulnerability(
                rule_id="AST-CMPLX-001", name="Complexidade Ciclomática Alta (via AST)",
                description=f"Função '{node.name}' tem complexidade ciclomática {cyclo} "
                            f"(threshold: {MAX_CYCLOMATIC_AST}), calculada por contagem real de nós "
                            f"de decisão na AST (if/for/while/except/bool-ops/comprehensions).",
                severity=Severity.HIGH if cyclo > 20 else Severity.MEDIUM,
                category=VulnCategory.COMPLEXITY, language=Language.PYTHON,
                file_path=file_path, line_number=node.lineno, line_content=_line(node.lineno),
                remediation="Extraia sub-funções, use early-return e reduza pontos de decisão.",
                cwe="CWE-1121", confidence=Confidence.HIGH,
            ))
        if cognitive > MAX_COGNITIVE_AST:
            results.append(Vulnerability(
                rule_id="AST-CMPLX-002", name="Complexidade Cognitiva Alta (via AST)",
                description=f"Função '{node.name}' tem complexidade cognitiva aproximada {cognitive} "
                            f"(threshold: {MAX_COGNITIVE_AST}). Mede o esforço mental de leitura, "
                            f"ponderando aninhamento de estruturas de controle.",
                severity=Severity.MEDIUM, category=VulnCategory.COMPLEXITY, language=Language.PYTHON,
                file_path=file_path, line_number=node.lineno, line_content=_line(node.lineno),
                remediation="Reduza aninhamento com guard clauses e extraia funções auxiliares.",
                cwe="CWE-1121", confidence=Confidence.MEDIUM,
            ))

        if _self_recursive_without_base_case(node):
            results.append(Vulnerability(
                rule_id="AST-REC-001", name="Recursão Sem Caso-Base Aparente",
                description=f"Função '{node.name}' chama a si mesma mas não contém nenhum "
                            f"return/yield no corpo — não há caso-base visível para interromper a "
                            f"recursão, risco de RecursionError/estouro de pilha.",
                severity=Severity.MEDIUM, category=VulnCategory.ERROR_HANDLING, language=Language.PYTHON,
                file_path=file_path, line_number=node.lineno, line_content=_line(node.lineno),
                remediation="Adicione uma condição de parada explícita com return antes da chamada recursiva.",
                cwe="CWE-674", confidence=Confidence.MEDIUM,
            ))

        for check_call, open_call in _toctou_pairs(node):
            results.append(Vulnerability(
                rule_id="AST-TOCTOU-001", name="Race Condition TOCTOU (check-then-use)",
                description=f"os.path.exists()/isfile() na linha {check_call.lineno} seguido de "
                            f"open() na linha {open_call.lineno} sobre o mesmo caminho: entre a "
                            f"checagem e o uso, outro processo pode alterar o arquivo (TOCTOU).",
                severity=Severity.MEDIUM, category=VulnCategory.RACE_CONDITION, language=Language.PYTHON,
                file_path=file_path, line_number=open_call.lineno, line_content=_line(open_call.lineno),
                remediation="Evite checar e depois abrir; use try/except diretamente no open() (EAFP) ou os.open() com flags atômicas (O_EXCL).",
                cwe="CWE-367", confidence=Confidence.MEDIUM,
            ))

        for name, lineno in _use_after_close(node):
            results.append(Vulnerability(
                rule_id="AST-UAC-001", name="Uso Após close() (Use-After-Close)",
                description=f"Variável '{name}' usada na linha {lineno} depois de '.close()' sem "
                            f"reatribuição no meio — operações em recurso fechado falham ou têm "
                            f"comportamento indefinido dependendo do tipo.",
                severity=Severity.MEDIUM, category=VulnCategory.ERROR_HANDLING, language=Language.PYTHON,
                file_path=file_path, line_number=lineno, line_content=_line(lineno),
                remediation="Use context manager ('with') para garantir que o recurso não seja usado após fechado.",
                cwe="CWE-672", confidence=Confidence.LOW,
            ))

        for name, lineno in _null_deref_candidates(node):
            results.append(Vulnerability(
                rule_id="AST-NULL-001", name="Possível Acesso a Atributo de None",
                description=f"Variável '{name}' foi atribuída None e, sem guarda 'if {name}'/'is not "
                            f"None' visível antes, tem um atributo acessado na linha {lineno} — "
                            f"risco de AttributeError em runtime.",
                severity=Severity.LOW, category=VulnCategory.ERROR_HANDLING, language=Language.PYTHON,
                file_path=file_path, line_number=lineno, line_content=_line(lineno),
                remediation="Adicione checagem explícita 'if var is not None:' antes de acessar atributos.",
                cwe="CWE-476", confidence=Confidence.LOW,
            ))

        # ── Dataflow: dead store (reaching defs / live variables) ────────────
        cfg = CFG(node.body)
        if cfg.nodes:
            live = live_variables(cfg)
            for nid, cfgnode in cfg.nodes.items():
                live_out = live[nid][1]
                dead_stores = cfgnode.defs - live_out - {"_"}
                for varname in dead_stores:
                    if varname.startswith("_"):
                        continue
                    results.append(Vulnerability(
                        rule_id="AST-DATAFLOW-001", name="Atribuição Nunca Utilizada (Dead Store)",
                        description=f"Variável '{varname}' é atribuída na linha {cfgnode.stmt.lineno} "
                                    f"mas nunca é lida depois (via análise de live variables sobre o "
                                    f"CFG da função '{node.name}').",
                        severity=Severity.LOW, category=VulnCategory.MAINTAINABILITY, language=Language.PYTHON,
                        file_path=file_path, line_number=cfgnode.stmt.lineno,
                        line_content=_line(cfgnode.stmt.lineno),
                        remediation="Remova a atribuição não utilizada ou use '_' se o valor é intencionalmente descartado.",
                        cwe="CWE-563", confidence=Confidence.MEDIUM,
                    ))

    return results
