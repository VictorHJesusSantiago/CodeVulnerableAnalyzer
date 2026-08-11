"""
Fuzzing do próprio engine/parsers usando apenas `random` da stdlib
(sem dependências externas como atheris/hypothesis). Gera entradas
malformadas/aleatórias e garante que o scanner nunca lança exceção
não tratada — robustez é uma propriedade de segurança tão importante
quanto a detecção em si (um scanner que trava em CI bloqueia pipelines).

Determinístico: seed fixa para reprodutibilidade em CI.

Rodar: python -m pytest tests/test_fuzz.py -q
Rodar com mais iterações: VULNSCAN_FUZZ_ITER=500 python -m pytest tests/test_fuzz.py -q
"""

from __future__ import annotations

import os
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.engine import ScanEngine
from analyzer.models import Severity

ITERATIONS = int(os.environ.get("VULNSCAN_FUZZ_ITER", "80"))
SEED = 1337

EXTENSIONS = [".py", ".js", ".java", ".c", ".php", ".rb", ".go", ".rs", ".sas", ".sql", ".sh"]

_TOKENS = [
    "def",
    "function",
    "class",
    "if",
    "else",
    "for",
    "while",
    "{",
    "}",
    "(",
    ")",
    "[",
    "]",
    '"',
    "'",
    "\\",
    "#",
    "//",
    "/*",
    "*/",
    "=",
    "==",
    "!=",
    "&&",
    "||",
    "eval(",
    "system(",
    "password",
    "SELECT * FROM",
    "%s",
    "\n",
    "\t",
    "\x00",
    "'; DROP TABLE users; --",
    "🔥",
    "日本語",
    "﻿",
    "à" * 200,
]


def _random_snippet(rng: random.Random, max_len: int = 2000) -> str:
    parts = []
    total = 0
    while total < max_len:
        tok = rng.choice(_TOKENS)
        parts.append(tok)
        total += len(tok)
    return "".join(parts)


def _random_bytes_snippet(rng: random.Random, length: int = 500) -> bytes:
    return bytes(rng.randrange(0, 256) for _ in range(length))


@pytest.mark.parametrize("i", range(ITERATIONS))
def test_fuzz_random_text_does_not_crash(tmp_path: Path, i: int):
    rng = random.Random(SEED + i)
    ext = rng.choice(EXTENSIONS)
    content = _random_snippet(rng)

    f = tmp_path / f"fuzz_{i}{ext}"
    f.write_text(content, encoding="utf-8", errors="replace")

    engine = ScanEngine(min_severity=Severity.INFO)
    try:
        result = engine.scan_file(str(f))
    except Exception as exc:  # pragma: no cover - só falha se achar bug real
        pytest.fail(f"Engine lançou exceção não tratada para input aleatório (seed={SEED + i}, ext={ext}): {exc!r}")

    assert result is not None


@pytest.mark.parametrize("i", range(max(1, ITERATIONS // 4)))
def test_fuzz_random_bytes_does_not_crash(tmp_path: Path, i: int):
    """Bytes verdadeiramente aleatórios (não necessariamente UTF-8 válido)."""
    rng = random.Random(SEED + 9000 + i)
    ext = rng.choice(EXTENSIONS)
    raw = _random_bytes_snippet(rng)

    f = tmp_path / f"fuzzbytes_{i}{ext}"
    f.write_bytes(raw)

    engine = ScanEngine(min_severity=Severity.INFO)
    try:
        result = engine.scan_file(str(f))
    except Exception as exc:  # pragma: no cover
        pytest.fail(
            f"Engine lançou exceção não tratada para bytes aleatórios (seed={SEED + 9000 + i}, ext={ext}): {exc!r}"
        )

    assert result is not None


def test_fuzz_deeply_nested_brackets_does_not_crash(tmp_path: Path):
    """Aninhamento extremo pode estourar recursão em analisadores ingênuos."""
    depth = 3000
    content = "def f():\n" + "    " * 1 + "(" * depth + ")" * depth + "\n"
    f = tmp_path / "deep_nest.py"
    f.write_text(content, encoding="utf-8")

    engine = ScanEngine(min_severity=Severity.INFO)
    result = engine.scan_file(str(f))
    assert result is not None


def test_fuzz_ast_analysis_on_syntax_errors_does_not_crash(tmp_path: Path):
    """--ast-analysis roda ast.parse() real; código Python inválido não pode derrubar o scan."""
    rng = random.Random(SEED)
    for i in range(20):
        content = _random_snippet(rng, max_len=300)
        f = tmp_path / f"badsyntax_{i}.py"
        f.write_text(content, encoding="utf-8", errors="replace")

        engine = ScanEngine(min_severity=Severity.INFO, ast_analysis=True)
        try:
            result = engine.scan_file(str(f))
        except Exception as exc:  # pragma: no cover
            pytest.fail(f"ast_analysis lançou exceção não tratada em código Python malformado (i={i}): {exc!r}")
        assert result is not None


def test_fuzz_extremely_long_single_line_does_not_crash(tmp_path: Path):
    content = "x = 1  # " + ("A" * 500_000)
    f = tmp_path / "longline.py"
    f.write_text(content, encoding="utf-8")

    engine = ScanEngine(min_severity=Severity.INFO)
    result = engine.scan_file(str(f))
    assert result is not None
