"""Testes dos parsers de manifesto estendidos (analyzer.manifests_ext)."""

from __future__ import annotations

import json

from analyzer.manifests_ext import (
    collect_extended_components,
    parse_cartfile_resolved,
    parse_composer_json,
    parse_composer_lock,
    parse_conanfile_txt,
    parse_conda_environment,
    parse_cpanfile,
    parse_description_cran,
    parse_dockerfile,
    parse_gemfile,
    parse_gemfile_lock,
    parse_helm_chart_yaml,
    parse_mix_exs,
    parse_package_resolved,
    parse_packages_config,
    parse_podfile_lock,
    parse_pubspec_yaml,
    parse_vcpkg_json,
)


def _by_name(components):
    return {c.name: c for c in components}


def test_composer_json_skips_php_and_ext():
    content = json.dumps({"require": {"monolog/monolog": "^2.3.5", "php": ">=7.4", "ext-json": "*"}})
    comps = _by_name(parse_composer_json(content))
    assert set(comps) == {"monolog/monolog"}
    assert comps["monolog/monolog"].version == "2.3.5"
    assert comps["monolog/monolog"].purl == "pkg:composer/monolog/monolog@2.3.5"


def test_composer_json_invalid():
    assert parse_composer_json("{bad") == []


def test_composer_lock():
    content = json.dumps({"packages": [{"name": "guzzlehttp/guzzle", "version": "v7.4.1"}]})
    comps = parse_composer_lock(content)
    assert comps[0].name == "guzzlehttp/guzzle"
    assert comps[0].version == "7.4.1"


def test_gemfile_and_lock():
    gems = _by_name(parse_gemfile('gem "rails", "6.1.4"\ngem \'puma\'\n'))
    assert gems["rails"].version == "6.1.4"
    assert gems["puma"].version == "0.0.0"

    lock = "GEM\n  specs:\n    rails (6.1.4)\n    puma (5.3.2)\n\nPLATFORMS\n"
    locked = _by_name(parse_gemfile_lock(lock))
    assert locked["rails"].version == "6.1.4"
    assert locked["puma"].version == "5.3.2"


def test_packages_config():
    content = '<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>'
    comps = parse_packages_config(content)
    assert comps[0].name == "Newtonsoft.Json" and comps[0].version == "13.0.1"


def test_pubspec_yaml():
    content = "dependencies:\n  http: ^0.13.4\n  provider: 6.0.1\n\nflutter:\n  x: y\n"
    comps = _by_name(parse_pubspec_yaml(content))
    assert comps["http"].version == "0.13.4"
    assert comps["provider"].version == "6.0.1"


def test_package_resolved():
    content = json.dumps({"pins": [{"identity": "alamofire", "state": {"version": "5.4.4"}}]})
    comps = parse_package_resolved(content)
    assert comps[0].name == "alamofire" and comps[0].version == "5.4.4"


def test_podfile_lock_strips_subspec():
    content = "PODS:\n  - Alamofire (5.4.4)\n  - AFNetworking/Core (4.0.1)\n"
    comps = _by_name(parse_podfile_lock(content))
    assert "Alamofire" in comps
    assert "AFNetworking" in comps


def test_cartfile_resolved():
    content = 'github "Alamofire/Alamofire" "5.4.4"\n'
    comps = parse_cartfile_resolved(content)
    assert comps[0].name == "Alamofire" and comps[0].version == "5.4.4"


def test_conanfile_txt():
    content = "[requires]\nzlib/1.2.11\nopenssl/1.1.1k\n\n[generators]\ncmake\n"
    comps = _by_name(parse_conanfile_txt(content))
    assert comps["zlib"].version == "1.2.11"
    assert "openssl" in comps
    assert "cmake" not in comps


def test_vcpkg_json_string_and_object():
    content = json.dumps({"dependencies": ["fmt", {"name": "boost"}]})
    comps = _by_name(parse_vcpkg_json(content))
    assert {"fmt", "boost"} <= set(comps)


def test_mix_exs():
    content = 'defp deps do\n  [{:phoenix, "~> 1.6.0"}, {:ecto, "3.7.1"}]\nend\n'
    comps = _by_name(parse_mix_exs(content))
    assert comps["phoenix"].version == "1.6.0"
    assert comps["ecto"].version == "3.7.1"


def test_cpanfile():
    content = "requires 'Moose', '2.2015';\nrequires 'DBI';\n"
    comps = _by_name(parse_cpanfile(content))
    assert comps["Moose"].version == "2.2015"
    assert comps["DBI"].version == "0.0.0"


def test_description_cran():
    content = "Package: mine\nImports: dplyr (>= 1.0.0), ggplot2\nLicense: MIT\n"
    comps = _by_name(parse_description_cran(content))
    assert "dplyr" in comps and comps["dplyr"].version == "1.0.0"
    assert "ggplot2" in comps
    assert "R" not in comps


def test_conda_environment():
    content = "dependencies:\n  - numpy=1.21.0\n  - pandas\n  - python=3.9\n"
    comps = _by_name(parse_conda_environment(content))
    assert comps["numpy"].version == "1.21.0"
    assert comps["pandas"].version == "0.0.0"
    assert "python" not in comps


def test_helm_chart_yaml():
    content = 'dependencies:\n  - name: redis\n    version: "17.0.0"\n'
    comps = parse_helm_chart_yaml(content)
    assert comps[0].name == "redis" and comps[0].version == "17.0.0"


def test_dockerfile_base_image_and_packages():
    content = "FROM python:3.11\nRUN apt-get install -y curl wget\n"
    comps = _by_name(parse_dockerfile(content))
    assert comps["python"].version == "3.11"
    assert "curl" in comps and "wget" in comps


def test_dockerfile_scratch_skipped():
    assert parse_dockerfile("FROM scratch\n") == []


def test_collect_extended_components(tmp_path):
    (tmp_path / "composer.json").write_text(json.dumps({"require": {"monolog/monolog": "2.3.5"}}), encoding="utf-8")
    (tmp_path / "Gemfile").write_text('gem "rails", "6.1.4"\n', encoding="utf-8")
    comps = _by_name(collect_extended_components(str(tmp_path)))
    assert "monolog/monolog" in comps
    assert "rails" in comps
