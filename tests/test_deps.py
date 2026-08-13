"""Testes do scanner de dependências vulneráveis (analyzer.deps)."""

from __future__ import annotations

import json

import analyzer.deps as deps
from analyzer.deps import (
    DepVuln,
    _check,
    _cvss_v3_base,
    _label_from_score,
    _osv_fixed_version,
    _osv_severity,
    _parse_cargo_toml,
    _parse_csproj,
    _parse_go_mod,
    _parse_package_json,
    _parse_pom_xml,
    _parse_requirements,
    _parse_ver,
    _ver_lt,
    query_osv,
    scan_dependencies,
    scan_manifest_dir,
    scan_manifest_dir_osv,
)



def test_parse_ver_and_lt():
    assert _parse_ver("1.2.3") == (1, 2, 3, 0)
    assert _parse_ver("2.0") == (2, 0, 0, 0)
    assert _ver_lt("1.0.0", "2.0.0") is True
    assert _ver_lt("2.31.0", "2.31.0") is False


def test_check_matches_known_cve():
    vulns = _check("requests", "2.30.0", "requirements.txt", 1)
    assert any(v.cve_id == "CVE-2023-32681" for v in vulns)
    assert _check("requests", "2.31.0", "requirements.txt", 1) == []
    assert _check("pacote-inexistente-xyz", "1.0", "x", 1) == []




def test_parse_requirements():
    vulns = _parse_requirements("requests==2.30.0\n# c\nflask==2.0.0\n", "requirements.txt")
    pkgs = {v.package for v in vulns}
    assert "requests" in pkgs and "flask" in pkgs


def test_parse_package_json():
    content = json.dumps({"dependencies": {"lodash": "4.17.20"}})
    vulns = _parse_package_json(content, "package.json")
    assert any(v.package == "lodash" for v in vulns)


def test_parse_pom_xml():
    content = (
        "<dependency><groupId>org.apache.logging.log4j</groupId>"
        "<artifactId>log4j-core</artifactId><version>2.14.0</version></dependency>"
    )
    vulns = _parse_pom_xml(content, "pom.xml")
    assert any(v.cve_id == "CVE-2021-44228" for v in vulns)


def test_parse_cargo_toml():
    content = '[dependencies]\nopenssl = "0.10.40"\n'
    vulns = _parse_cargo_toml(content, "Cargo.toml")
    assert any(v.package == "openssl" for v in vulns)


def test_parse_go_mod():
    content = "require github.com/hyperium/hyper v0.14.0\n"
    vulns = _parse_go_mod(content, "go.mod")
    assert any(v.package == "hyper" for v in vulns)


def test_parse_csproj():
    content = '<PackageReference Include="Newtonsoft.Json" Version="12.0.0" />'
    vulns = _parse_csproj(content, "app.csproj")
    assert any(v.package == "newtonsoft.json" for v in vulns)


def test_scan_dependencies_dispatch_and_unknown():
    assert scan_dependencies("proj/unknown.foo", "x") == []
    vulns = scan_dependencies("proj/requirements.txt", "requests==2.30.0\n")
    assert vulns and vulns[0].package == "requests"
    csproj = scan_dependencies("proj/app.csproj", '<PackageReference Include="Newtonsoft.Json" Version="12.0.0" />')
    assert csproj


def test_scan_manifest_dir(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.30.0\n", encoding="utf-8")
    vulns = scan_manifest_dir(str(tmp_path))
    assert any(v.package == "requests" for v in vulns)




def test_cvss_v3_base_critical():
    score = _cvss_v3_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8
    assert _label_from_score(score) == "CRITICAL"


def test_cvss_v3_scope_changed_in_range():
    score = _cvss_v3_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H")
    assert score is not None and 0.0 < score <= 10.0


def test_cvss_v3_missing_metrics_returns_none():
    assert _cvss_v3_base("CVSS:3.1/AC:L") is None


def test_label_from_score_bands():
    assert _label_from_score(9.5) == "CRITICAL"
    assert _label_from_score(7.5) == "HIGH"
    assert _label_from_score(5.0) == "MEDIUM"
    assert _label_from_score(1.0) == "LOW"
    assert _label_from_score(0.0) == "MEDIUM"




def test_osv_severity_text_and_cvss():
    assert _osv_severity({"database_specific": {"severity": "HIGH"}}) == "HIGH"
    assert _osv_severity({"database_specific": {"severity": "MODERATE"}}) == "MEDIUM"
    cvss = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert _osv_severity(cvss) == "CRITICAL"
    assert _osv_severity({}) == "MEDIUM"


def test_osv_fixed_version():
    vuln = {"affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}]}
    assert _osv_fixed_version(vuln) == "1.2.3"
    assert _osv_fixed_version({}) == "—"




class _FakeResp:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


def test_query_osv_success(monkeypatch):
    body = json.dumps(
        {
            "vulns": [
                {
                    "id": "GHSA-xxxx",
                    "aliases": ["CVE-2021-1234"],
                    "summary": "bug ruim",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [{"ranges": [{"events": [{"fixed": "1.2.3"}]}]}],
                }
            ]
        }
    ).encode("utf-8")
    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: _FakeResp(body))
    results = query_osv("requests", "2.0.0", "PyPI")
    assert len(results) == 1
    assert results[0].cve_id == "CVE-2021-1234"
    assert results[0].severity == "HIGH"
    assert results[0].fixed_version == "1.2.3"


def test_query_osv_network_error(monkeypatch):
    import urllib.request

    def boom(req, timeout=None):
        raise OSError("no network")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert query_osv("requests", "2.0.0", "PyPI") == []


def test_scan_manifest_dir_osv(monkeypatch, tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
    monkeypatch.setattr(
        deps,
        "query_osv",
        lambda name, ver, eco, timeout=8.0: [
            DepVuln(name, ver, "CVE-2020-0001", "d", "HIGH", "9.9", "(OSV.dev)", 0),
        ],
    )
    out = scan_manifest_dir_osv(str(tmp_path))
    assert any(v.cve_id == "CVE-2020-0001" for v in out)
