"""
Testes do motor de análise avançada: AST engine (Python), call graph
interprocedural, pré-processador de macros C/C++ e cache incremental.
"""
from __future__ import annotations
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ════════════════════════════════════════════════════════════════════════════
#  pyast_engine
# ════════════════════════════════════════════════════════════════════════════

def test_dead_code_detection():
    from analyzer.pyast_engine import analyze_python_ast
    code = "def f(x):\n    return x\n    print('never')\n"
    vulns = analyze_python_ast("t.py", code)
    dead = [v for v in vulns if v.rule_id == "AST-DEAD-001"]
    assert len(dead) == 1
    assert dead[0].line_number == 3


def test_cyclomatic_complexity_ast_high():
    from analyzer.pyast_engine import analyze_python_ast
    params = ",".join(f"a{i}" for i in range(11))
    lines = [f"def f({params}):"]
    for i in range(11):
        lines.append("    " * (i + 1) + f"if a{i}:")
    lines.append("    " * 12 + "return 1")
    lines.append("    return 0")
    code = "\n".join(lines) + "\n"
    vulns = analyze_python_ast("t.py", code)
    assert any(v.rule_id == "AST-CMPLX-001" for v in vulns)


def test_recursion_without_base_case():
    from analyzer.pyast_engine import analyze_python_ast
    code = "def f(n):\n    f(n)\n"
    vulns = analyze_python_ast("t.py", code)
    assert any(v.rule_id == "AST-REC-001" for v in vulns)


def test_recursion_with_return_not_flagged():
    from analyzer.pyast_engine import analyze_python_ast
    code = "def f(n):\n    if n <= 0:\n        return 0\n    return f(n-1)\n"
    vulns = analyze_python_ast("t.py", code)
    assert not any(v.rule_id == "AST-REC-001" for v in vulns)


def test_toctou_detection():
    from analyzer.pyast_engine import analyze_python_ast
    code = (
        "import os\n"
        "def f(path):\n"
        "    if os.path.exists(path):\n"
        "        f = open(path)\n"
        "        return f.read()\n"
    )
    vulns = analyze_python_ast("t.py", code)
    assert any(v.rule_id == "AST-TOCTOU-001" for v in vulns)


def test_use_after_close():
    from analyzer.pyast_engine import analyze_python_ast
    code = "def f():\n    fh = open('x')\n    fh.close()\n    return fh.read()\n"
    vulns = analyze_python_ast("t.py", code)
    assert any(v.rule_id == "AST-UAC-001" for v in vulns)


def test_null_deref_candidate():
    from analyzer.pyast_engine import analyze_python_ast
    code = "def f():\n    result = None\n    return result.value\n"
    vulns = analyze_python_ast("t.py", code)
    assert any(v.rule_id == "AST-NULL-001" for v in vulns)


def test_null_deref_guarded_not_flagged():
    from analyzer.pyast_engine import analyze_python_ast
    code = "def f():\n    result = None\n    if result:\n        return result.value\n    return None\n"
    vulns = analyze_python_ast("t.py", code)
    assert not any(v.rule_id == "AST-NULL-001" for v in vulns)


def test_dead_store_via_dataflow():
    from analyzer.pyast_engine import analyze_python_ast
    code = "def f():\n    unused = 42\n    return 1\n"
    vulns = analyze_python_ast("t.py", code)
    assert any(v.rule_id == "AST-DATAFLOW-001" for v in vulns)


def test_dead_store_not_flagged_when_used():
    from analyzer.pyast_engine import analyze_python_ast
    code = "def f():\n    x = 42\n    return x\n"
    vulns = analyze_python_ast("t.py", code)
    assert not any(v.rule_id == "AST-DATAFLOW-001" for v in vulns)


def test_syntax_error_returns_empty():
    from analyzer.pyast_engine import analyze_python_ast
    assert analyze_python_ast("t.py", "def f(:\n") == []


def test_halstead_and_cyclomatic_are_real_numbers():
    import ast
    from analyzer.pyast_engine import cyclomatic_complexity, halstead_metrics
    tree = ast.parse("def f(a, b):\n    if a > b:\n        return a\n    return b\n")
    func = tree.body[0]
    assert cyclomatic_complexity(func) == 2  # 1 base + 1 if
    h = halstead_metrics(func)
    assert h["N1"] > 0 and h["N2"] > 0
    assert h["volume"] > 0


# ════════════════════════════════════════════════════════════════════════════
#  callgraph
# ════════════════════════════════════════════════════════════════════════════

def test_callgraph_cross_file_taint(tmp_path):
    from analyzer.callgraph import build_call_graph

    (tmp_path / "mod_a.py").write_text(
        "def handler():\n"
        "    user_cmd = request.args.get('cmd')\n"
        "    run_it(user_cmd)\n",
        encoding="utf-8",
    )
    (tmp_path / "mod_b.py").write_text(
        "def run_it(cmd):\n"
        "    helper(cmd)\n"
        "\n"
        "def helper(x):\n"
        "    os.system(x)\n",
        encoding="utf-8",
    )
    cg = build_call_graph(str(tmp_path))
    findings = cg.analyze_taint()
    assert len(findings) == 1
    assert findings[0].rule_id == "INTERPROC-TAINT-001"
    assert "mod_b.py" in findings[0].file_path


def test_callgraph_impact_analysis(tmp_path):
    from analyzer.callgraph import build_call_graph

    (tmp_path / "m.py").write_text(
        "def target():\n    return 1\n\n"
        "def caller1():\n    return target()\n\n"
        "def caller2():\n    return caller1()\n",
        encoding="utf-8",
    )
    cg = build_call_graph(str(tmp_path))
    report = cg.impact_report("target")
    assert "caller1" in report["direct_callers"]
    assert "caller2" in report["transitive_callers"]
    assert report["total_impact"] >= 2


def test_callgraph_no_taint_when_sanitized_is_absent(tmp_path):
    from analyzer.callgraph import build_call_graph
    (tmp_path / "clean.py").write_text(
        "def f():\n    x = 'constante'\n    g(x)\n\n"
        "def g(y):\n    os.system(y)\n",
        encoding="utf-8",
    )
    cg = build_call_graph(str(tmp_path))
    findings = cg.analyze_taint()
    assert findings == []


# ════════════════════════════════════════════════════════════════════════════
#  cpreprocess
# ════════════════════════════════════════════════════════════════════════════

def test_macro_object_expansion():
    from analyzer.cpreprocess import expand_macros
    src = "#define MAX 256\nint x = MAX;\n"
    out = expand_macros(src)
    assert "int x = 256;" in out


def test_macro_function_expansion():
    from analyzer.cpreprocess import expand_macros
    src = "#define ADD(a,b) ((a)+(b))\nint r = ADD(1,2);\n"
    out = expand_macros(src)
    assert "((1)+(2))" in out


def test_macro_reveals_hidden_dangerous_call():
    from analyzer.cpreprocess import expand_macros
    from analyzer.engine import ScanEngine
    from analyzer.models import Severity, Language

    src = "#define S system\nint main(char *x) {\n    S(x);\n    return 0;\n}\n"
    eng = ScanEngine(min_severity=Severity.INFO)
    before = eng._scan_content("t.c", src, Language.C)
    assert not any(v.rule_id == "C-007" for v in before)

    expanded = expand_macros(src)
    after = eng._scan_content("t.c", expanded, Language.C)
    assert any(v.rule_id == "C-007" for v in after)


def test_ifdef_not_defined_removes_block():
    from analyzer.cpreprocess import expand_macros
    src = "#ifdef DEBUG\nvoid debug_fn() {}\n#else\nvoid release_fn() {}\n#endif\n"
    out = expand_macros(src)
    assert "debug_fn" not in out
    assert "release_fn" in out


def test_line_count_preserved():
    from analyzer.cpreprocess import expand_macros
    src = "#define X 1\n#ifdef Y\nfoo();\n#endif\nbar();\n"
    out = expand_macros(src)
    assert len(out.splitlines()) == len(src.splitlines())


# ════════════════════════════════════════════════════════════════════════════
#  incremental cache
# ════════════════════════════════════════════════════════════════════════════

def test_incremental_cache_hit_miss(tmp_path):
    from analyzer.incremental import IncrementalCache
    from analyzer.models import Vulnerability, Severity, VulnCategory, Language, Confidence

    cache = IncrementalCache(str(tmp_path / "inc.db"))
    content = "eval(x)\n"
    assert cache.get("t.py", content) is None

    v = Vulnerability(
        rule_id="PY-001", name="eval", description="d", severity=Severity.CRITICAL,
        category=VulnCategory.CODE_INJECTION, language=Language.PYTHON,
        file_path="t.py", line_number=1, line_content="eval(x)", remediation="r",
    )
    cache.put("t.py", content, [v], 1, 0.01)

    hit = cache.get("t.py", content)
    assert hit is not None
    assert hit[0][0].rule_id == "PY-001"

    assert cache.get("t.py", content + "x=1\n") is None
    assert cache.stats()["hits"] == 1
    assert cache.stats()["misses"] == 2


def test_incremental_integration_via_engine(tmp_path):
    from analyzer.engine import ScanEngine
    from analyzer.incremental import IncrementalCache
    from analyzer.models import Severity

    f = tmp_path / "v.py"
    f.write_text('eval(request.form["x"])\n', encoding="utf-8")

    cache = IncrementalCache(str(tmp_path / "inc.db"))
    eng = ScanEngine(min_severity=Severity.INFO, incremental_cache=cache)

    r1 = eng.scan_file(str(f))
    assert len(r1.vulnerabilities) > 0
    assert cache.stats()["misses"] == 1

    r2 = eng.scan_file(str(f))
    assert len(r2.vulnerabilities) == len(r1.vulnerabilities)
    assert cache.stats()["hits"] == 1


# ════════════════════════════════════════════════════════════════════════════
#  Integração com o engine principal (flags novas não quebram o fluxo)
# ════════════════════════════════════════════════════════════════════════════

def test_engine_with_ast_analysis_flag(tmp_path):
    from analyzer.engine import ScanEngine
    from analyzer.models import Severity

    f = tmp_path / "v.py"
    f.write_text("def f(x):\n    return x\n    print('dead')\n", encoding="utf-8")

    eng = ScanEngine(min_severity=Severity.INFO, ast_analysis=True)
    result = eng.scan_file(str(f))
    assert any(v.rule_id == "AST-DEAD-001" for v in result.vulnerabilities)


def test_engine_without_ast_analysis_flag_skips_it(tmp_path):
    from analyzer.engine import ScanEngine
    from analyzer.models import Severity

    f = tmp_path / "v.py"
    f.write_text("def f(x):\n    return x\n    print('dead')\n", encoding="utf-8")

    eng = ScanEngine(min_severity=Severity.INFO, ast_analysis=False)
    result = eng.scan_file(str(f))
    assert not any(v.rule_id == "AST-DEAD-001" for v in result.vulnerabilities)


def test_engine_with_cpp_macros_flag(tmp_path):
    from analyzer.engine import ScanEngine
    from analyzer.models import Severity

    f = tmp_path / "v.c"
    f.write_text("#define S system\nint main(char *x) {\n    S(x);\n    return 0;\n}\n", encoding="utf-8")

    eng = ScanEngine(min_severity=Severity.INFO, cpp_macros=True)
    result = eng.scan_file(str(f))
    assert any(v.rule_id == "C-007" for v in result.vulnerabilities)
