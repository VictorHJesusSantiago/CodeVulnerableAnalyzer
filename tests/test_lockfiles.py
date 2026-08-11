"""Testes dos parsers de lockfile e da árvore de dependências (analyzer.lockfiles)."""

from __future__ import annotations

import json

from analyzer.lockfiles import (
    DependencyTree,
    LockedPackage,
    build_dependency_tree,
    parse_cargo_lock,
    parse_go_sum,
    parse_lockfile,
    parse_package_lock_json,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_yarn_lock,
)


def test_dependency_tree_transitive_depth_summary():
    tree = DependencyTree()
    tree.add(LockedPackage("a", "1.0", "npm", dependencies=["b"]))
    tree.add(LockedPackage("b", "1.0", "npm", dependencies=["c"]))
    tree.add(LockedPackage("c", "1.0", "npm"))
    assert tree.transitive_of("a") == {"b", "c"}
    assert tree.depth() == 2
    s = tree.summary()
    assert s == {"total_packages": 3, "total_edges": 2, "max_depth": 2}


def test_parse_package_lock_v2():
    content = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root"},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2.0.0"}, "integrity": "sha512-x"},
                "node_modules/b": {"version": "2.0.0"},
            },
        }
    )
    tree = parse_package_lock_json(content)
    assert set(tree.packages) == {"a", "b"}
    assert tree.packages["a"].integrity == "sha512-x"
    assert tree.transitive_of("a") == {"b"}


def test_parse_package_lock_v1_recursive():
    content = json.dumps(
        {
            "lockfileVersion": 1,
            "dependencies": {
                "a": {"version": "1.0.0", "requires": {"b": "2.0.0"}, "dependencies": {"b": {"version": "2.0.0"}}},
            },
        }
    )
    tree = parse_package_lock_json(content)
    assert "a" in tree.packages and "b" in tree.packages
    assert "b" in tree.edges["a"]


def test_parse_package_lock_invalid():
    assert parse_package_lock_json("{bad").packages == {}


def test_parse_yarn_lock():
    content = (
        "# yarn lockfile v1\n\n"
        '"a@^1.0.0":\n  version "1.2.3"\n  dependencies:\n    b "^2.0.0"\n\n'
        'b@^2.0.0:\n  version "2.3.4"\n'
    )
    tree = parse_yarn_lock(content)
    assert tree.packages["a"].version == "1.2.3"
    assert tree.packages["b"].version == "2.3.4"
    assert "b" in tree.edges["a"]


def test_parse_poetry_lock():
    content = (
        '[[package]]\nname = "requests"\nversion = "2.28.0"\n\n[[package]]\nname = "urllib3"\nversion = "1.26.0"\n'
    )
    tree = parse_poetry_lock(content)
    assert tree.packages["requests"].version == "2.28.0"
    assert tree.packages["urllib3"].version == "1.26.0"


def test_parse_cargo_lock_with_deps():
    content = (
        '[[package]]\nname = "serde"\nversion = "1.0.130"\n'
        'dependencies = [\n "serde_derive 1.0.130",\n]\n\n'
        '[[package]]\nname = "serde_derive"\nversion = "1.0.130"\n'
    )
    tree = parse_cargo_lock(content)
    assert tree.packages["serde"].version == "1.0.130"
    assert "serde_derive" in tree.edges["serde"]


def test_parse_pipfile_lock():
    content = json.dumps(
        {
            "default": {"requests": {"version": "==2.28.0"}},
            "develop": {"pytest": {"version": "==7.0.0"}},
        }
    )
    tree = parse_pipfile_lock(content)
    assert tree.packages["requests"].version == "2.28.0"
    assert tree.packages["pytest"].version == "7.0.0"


def test_parse_go_sum():
    content = "github.com/pkg/errors v0.9.1 h1:abc=\ngithub.com/pkg/errors v0.9.1/go.mod h1:def=\n"
    tree = parse_go_sum(content)
    assert tree.packages["github.com/pkg/errors"].version == "0.9.1"
    assert tree.packages["github.com/pkg/errors"].integrity.startswith("h1:")


def test_parse_lockfile_dispatch_and_unknown():
    assert parse_lockfile("x/unknown.txt", "") is None
    tree = parse_lockfile("proj/go.sum", "example.com/m v1.2.3 h1:zzz=\n")
    assert tree is not None and "example.com/m" in tree.packages


def test_build_dependency_tree(tmp_path):
    (tmp_path / "go.sum").write_text("example.com/m v1.0.0 h1:aaa=\n", encoding="utf-8")
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "flask"\nversion = "2.0.0"\n', encoding="utf-8")
    merged = build_dependency_tree(str(tmp_path))
    assert "example.com/m" in merged.packages
    assert "flask" in merged.packages
