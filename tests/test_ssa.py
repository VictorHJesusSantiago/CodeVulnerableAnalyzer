"""
Testes da construção real de SSA (dominadores, fronteira de dominância,
φ-nodes) e da análise de definite assignment em analyzer/ssa.py, além da
integração no pyast_engine (regra AST-SSA-001).
"""
from __future__ import annotations
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.pyast_engine import CFG
from analyzer.ssa import compute_dominators, compute_dominance_frontier, place_phi_nodes, build_ssa, definite_assignment


def _cfg_from(code: str) -> CFG:
    tree = ast.parse(code)
    return CFG(tree.body[0].body)


def test_diamond_cfg_requires_phi_node():
    code = "def f(cond):\n    if cond:\n        x = 1\n    else:\n        x = 2\n    return x\n"
    cfg = _cfg_from(code)
    idom, df, phi = build_ssa(cfg)
    assert "x" in phi.phi_sites
    join_node = max(cfg.nodes.keys())  # nó do 'return x'
    assert join_node in phi.phi_sites["x"]


def test_linear_cfg_no_phi_needed():
    code = "def f():\n    x = 1\n    y = 2\n    return x + y\n"
    cfg = _cfg_from(code)
    _, _, phi = build_ssa(cfg)
    assert phi.phi_sites == {}


def test_dominators_entry_dominates_itself():
    code = "def f(cond):\n    if cond:\n        x = 1\n    return x\n"
    cfg = _cfg_from(code)
    idom = compute_dominators(cfg)
    assert idom[cfg.entry] == cfg.entry


def test_definite_assignment_missing_else_flags_uncertain():
    code = "def f(cond):\n    if cond:\n        x = 1\n    return x\n"
    cfg = _cfg_from(code)
    result = definite_assignment(cfg, params=set())
    last_id = max(result.keys())
    assert "x" not in result[last_id]


def test_definite_assignment_with_else_is_certain():
    code = "def f(cond):\n    if cond:\n        x = 1\n    else:\n        x = 2\n    return x\n"
    cfg = _cfg_from(code)
    result = definite_assignment(cfg, params=set())
    last_id = max(result.keys())
    assert "x" in result[last_id]


def test_definite_assignment_params_are_certain_from_entry():
    code = "def f(a, b):\n    return a + b\n"
    cfg = _cfg_from(code)
    result = definite_assignment(cfg, params={"a", "b"})
    assert {"a", "b"}.issubset(result[cfg.entry])


# ── Integração com pyast_engine (regra AST-SSA-001) ─────────────────────────

def test_ast_ssa_rule_flags_real_bug():
    from analyzer.pyast_engine import analyze_python_ast
    code = "def f(cond):\n    if cond:\n        x = 1\n    return x\n"
    vulns = analyze_python_ast("t.py", code)
    assert any(v.rule_id == "AST-SSA-001" for v in vulns)


def test_ast_ssa_rule_no_false_positive_with_else():
    from analyzer.pyast_engine import analyze_python_ast
    code = "def f(cond):\n    if cond:\n        x = 1\n    else:\n        x = 2\n    return x\n"
    vulns = analyze_python_ast("t.py", code)
    assert not any(v.rule_id == "AST-SSA-001" for v in vulns)


def test_ast_ssa_rule_no_false_positive_on_import():
    from analyzer.pyast_engine import analyze_python_ast
    code = "import os\ndef f():\n    return os.getcwd()\n"
    vulns = analyze_python_ast("t.py", code)
    assert not any(v.rule_id == "AST-SSA-001" for v in vulns)
