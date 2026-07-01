"""
Testes dos codemods expandidos em analyzer/remediation.py — cada um valida
uma transformação mecânica segura contra um caso real e, quando aplicável,
um caso que NÃO deveria ser alterado (evitar falso positivo de autofix).
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.remediation import default_engine


def test_registered_rule_ids_are_real_not_phantom():
    """PY-EVAL e PY-YAML-001 eram IDs fantasmas que nunca correspondiam a
    um achado real do engine — devem ter sido substituídos pelos IDs reais."""
    engine = default_engine()
    assert "PY-EVAL" not in engine.codemods
    assert "PY-YAML-001" not in engine.codemods
    assert "PY-001" in engine.codemods       # eval() real
    assert "PY-012" in engine.codemods       # yaml.load real


def test_weak_hash_md5_to_sha256():
    engine = default_engine()
    src = "h = hashlib.md5(data).hexdigest()\n"
    patch = engine.plan("t.py", src, [{"rule_id": "PY-009", "line_number": 1}])
    assert "hashlib.sha256(data)" in patch.diff


def test_ssl_verify_false_removed():
    engine = default_engine()
    src = "r = requests.get(url, timeout=5, verify=False)\n"
    patch = engine.plan("t.py", src, [{"rule_id": "PY-016", "line_number": 1}])
    assert patch.edits and "verify=False" not in patch.edits[0].replacement
    assert "timeout=5" in patch.edits[0].replacement


def test_flask_debug_disabled():
    engine = default_engine()
    src = 'app.run(host="0.0.0.0", debug=True)\n'
    patch = engine.plan("t.py", src, [{"rule_id": "PY-021", "line_number": 1}])
    assert patch.edits[0].replacement == 'app.run(host="0.0.0.0", debug=False)'


def test_insecure_random_for_token_uses_secrets():
    engine = default_engine()
    src = "session_token = random.random()\n"
    patch = engine.plan("t.py", src, [{"rule_id": "PY-011", "line_number": 1}])
    assert "secrets.token_hex" in patch.edits[0].replacement


def test_insecure_random_not_touched_for_unrelated_variable():
    """random.randint em variável sem relação com segurança não deve ser
    tocado (evita autofix incorreto em uso legítimo, ex.: dado de jogo)."""
    engine = default_engine()
    src = "dice_roll = random.randint(1, 6)\n"
    patch = engine.plan("t.py", src, [{"rule_id": "PY-011", "line_number": 1}])
    assert patch.edits == []


def test_dangerously_set_innerhtml_gets_warning_comment():
    engine = default_engine()
    src = "  return <div dangerouslySetInnerHTML={{__html: data}} />;\n"
    patch = engine.plan("t.jsx", src, [{"rule_id": "JS-006", "line_number": 1}])
    assert "vulnscan: revisar XSS" in patch.diff


def test_innerhtml_registered_under_real_js003_id():
    engine = default_engine()
    src = "el.innerHTML = userInput;\n"
    patch = engine.plan("t.js", src, [{"rule_id": "JS-003", "line_number": 1}])
    assert "el.textContent = userInput;" in patch.diff
