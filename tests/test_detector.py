"""Testes do detector de linguagem (analyzer.detector)."""

from __future__ import annotations

import pytest

from analyzer.detector import (
    detect_language,
    get_comment_prefix,
    is_scannable,
)
from analyzer.models import Language


@pytest.mark.parametrize(
    "path,expected",
    [
        ("Dockerfile", Language.DOCKERFILE),
        ("Containerfile", Language.DOCKERFILE),
        ("Makefile", Language.MAKEFILE),
        ("build.mk", Language.MAKEFILE),
        ("CMakeLists.txt", Language.CMAKE),
        ("WORKSPACE", Language.BAZEL),
        ("app.gradle", Language.GRADLE),
        ("Jenkinsfile", Language.GROOVY),
        (".bashrc", Language.BASH),
        ("Gemfile", Language.RUBY),
        ("pyproject.toml", Language.PYTHON),
        ("Cargo.toml", Language.RUST),
        ("package.json", Language.JSON),
        ("go.mod", Language.GO),
        (".env.local", Language.INI),
    ],
)
def test_detect_language_by_special_name(path, expected):
    assert detect_language(path) == expected


@pytest.mark.parametrize(
    "path,expected",
    [
        ("app.py", Language.PYTHON),
        ("index.js", Language.JAVASCRIPT),
        ("Main.java", Language.JAVA),
        ("main.go", Language.GO),
        ("lib.rs", Language.RUST),
        ("script.fish", Language.FISH),
        ("infra.pp", Language.PUPPET),
    ],
)
def test_detect_language_by_extension(path, expected):
    assert detect_language(path) == expected


def test_detect_language_binary_is_unknown():
    assert detect_language("photo.jpg") == Language.UNKNOWN


def test_detect_language_by_content_signature():
    lang = detect_language("mystery", "#!/usr/bin/env python3\nimport os\n")
    assert lang != Language.UNKNOWN


def test_detect_language_unknown_fallback():
    assert detect_language("data.unknownext", "") == Language.UNKNOWN


def test_is_scannable():
    assert is_scannable("src/app.py") is True
    assert is_scannable("photo.png") is False
    assert is_scannable("node_modules/pkg/index.js") is False


def test_get_comment_prefix_shapes():
    single, block_start, block_end = get_comment_prefix(Language.PYTHON)
    assert single == "#"
    c_single, c_start, c_end = get_comment_prefix(Language.JAVA)
    assert c_single == "//" and c_start == "/*" and c_end == "*/"
