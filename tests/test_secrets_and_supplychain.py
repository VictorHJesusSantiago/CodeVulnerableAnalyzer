"""
Testes da expansão de detecção de segredos e supply chain (dependências).
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ════════════════════════════════════════════════════════════════════════════
#  secrets_providers
# ════════════════════════════════════════════════════════════════════════════

def test_provider_signatures_compile():
    import re
    from analyzer.secrets_providers import PROVIDER_SIGNATURES
    for sig in PROVIDER_SIGNATURES:
        re.compile(sig.pattern.pattern)  # não deve lançar


def test_classify_secret_finds_aws_and_stripe():
    # As strings são concatenadas em partes para que o texto-fonte bruto deste
    # arquivo nunca contenha a sequência contígua no formato de segredo real
    # (evita falso-positivo do secret scanning / push protection do GitHub).
    from analyzer.secrets_providers import classify_secret
    fake_aws = "AKIA" + "ABCDEFGHIJKLMNOP"
    fake_stripe = "sk_live_" + "abcdefghijklmnopqrstuvwx"
    text = f"{fake_aws} and {fake_stripe}"
    results = classify_secret(text)
    providers = {r[0] for r in results}
    assert "AWS" in providers
    assert "Stripe" in providers


def test_provider_count_substantial():
    from analyzer.secrets_providers import provider_count, signature_count
    assert provider_count() >= 100
    assert signature_count() >= 120


# ════════════════════════════════════════════════════════════════════════════
#  key_material
# ════════════════════════════════════════════════════════════════════════════

def test_pkcs8_pem_detected():
    from analyzer.key_material import scan_key_material
    # PEM sintético (base64 válido, não precisa ser uma chave criptograficamente
    # correta para o teste de detecção de bloco + tentativa de parse DER)
    import base64
    fake_der = b"\x30\x03\x02\x01\x00"  # SEQUENCE { INTEGER 0 }
    b64 = base64.encodebytes(fake_der).decode()
    pem = f"-----BEGIN PRIVATE KEY-----\n{b64}-----END PRIVATE KEY-----\n"
    findings = scan_key_material("t.pem", pem)
    assert len(findings) == 1
    assert findings[0].valid_der is True


def test_encrypted_key_flagged():
    from analyzer.key_material import scan_key_material
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-128-CBC,ABCDEF\n\n"
        "c29tZWJhc2U2NGRhdGE=\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    findings = scan_key_material("t.pem", pem)
    assert len(findings) == 1
    assert findings[0].is_encrypted is True


def test_der_analysis_rejects_garbage():
    from analyzer.key_material import analyze_der_structure
    valid, bits = analyze_der_structure(b"\xff\xff\xff\xff")
    assert valid is False


# ════════════════════════════════════════════════════════════════════════════
#  jwt_scan
# ════════════════════════════════════════════════════════════════════════════

def _build_jwt(header: dict, payload: dict) -> str:
    import base64
    def b64u(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64u(header)}.{b64u(payload)}.fakesig"


def test_jwt_alg_none_flagged():
    from analyzer.jwt_scan import scan_jwt
    token = _build_jwt({"alg": "none"}, {"sub": "1"})
    code = f'const t = "{token}";\n'
    findings = scan_jwt("t.js", code)
    assert len(findings) == 1
    assert any("alg=none" in issue for issue in findings[0].issues)


def test_jwt_missing_exp_flagged():
    from analyzer.jwt_scan import scan_jwt
    token = _build_jwt({"alg": "HS256"}, {"sub": "1"})
    findings = scan_jwt("t.js", f'"{token}"')
    assert any("exp" in issue for issue in findings[0].issues)


def test_jwt_valid_with_exp_no_issues():
    from analyzer.jwt_scan import scan_jwt
    token = _build_jwt({"alg": "HS256"}, {"sub": "1", "exp": 9999999999})
    findings = scan_jwt("t.js", f'"{token}"')
    assert findings[0].issues == []


# ════════════════════════════════════════════════════════════════════════════
#  binary_scan
# ════════════════════════════════════════════════════════════════════════════

def test_extract_strings_from_binary():
    from analyzer.binary_scan import extract_strings
    data = b"\x00\x01ghp_" + b"a" * 36 + b"\x00\xffhello world"
    strs = extract_strings(data)
    assert any(s.startswith("ghp_") for s in strs)
    assert "hello world" in strs


def test_env_scan_detects_secret():
    from analyzer.binary_scan import scan_env_for_secrets
    content = "DB_PASSWORD=supersecretpassword123\nAPP_NAME=test\n"
    findings = scan_env_for_secrets(".env", content)
    assert any("DB_PASSWORD" in f["secret_type"] for f in findings)


def test_pdf_text_extraction_with_flate():
    import zlib
    from analyzer.binary_scan import extract_pdf_text
    compressed = zlib.compress(b"(secret content here)")
    pdf = b"stream\n" + compressed + b"\nendstream\n"
    text = extract_pdf_text(pdf)
    assert "secret content here" in text


# ════════════════════════════════════════════════════════════════════════════
#  secrets_baseline
# ════════════════════════════════════════════════════════════════════════════

def test_baseline_roundtrip(tmp_path):
    from analyzer.secrets_baseline import save_secrets_baseline, filter_new_secrets
    fake_aws = "AKIA" + "ABCDEFGHIJKLMNOP"
    findings = [{"file_path": "a.py", "line_number": 1, "provider": "AWS",
                 "secret_type": "Access Key ID", "matched": fake_aws}]
    path = str(tmp_path / "baseline.json")
    save_secrets_baseline(path, findings)
    diff = filter_new_secrets(findings, path)
    assert diff.new_secrets == []
    assert diff.unchanged_count == 1


def test_baseline_detects_new_secret(tmp_path):
    from analyzer.secrets_baseline import save_secrets_baseline, filter_new_secrets
    path = str(tmp_path / "baseline.json")
    save_secrets_baseline(path, [])
    new_findings = [{"file_path": "b.py", "line_number": 1, "provider": "GitHub",
                      "secret_type": "PAT", "matched": "ghp_x"}]
    diff = filter_new_secrets(new_findings, path)
    assert len(diff.new_secrets) == 1


# ════════════════════════════════════════════════════════════════════════════
#  credential_validators (SigV4 — sem chamadas de rede no teste)
# ════════════════════════════════════════════════════════════════════════════

def test_sigv4_signature_deterministic_and_key_sensitive():
    import re
    from analyzer.credential_validators import build_sigv4_headers
    h1 = build_sigv4_headers("AKIAFAKE", "secret1")
    h2 = build_sigv4_headers("AKIAFAKE", "secret2")
    sig1 = re.search(r"Signature=([a-f0-9]+)", h1["Authorization"]).group(1)
    sig2 = re.search(r"Signature=([a-f0-9]+)", h2["Authorization"]).group(1)
    assert sig1 != sig2
    assert "Credential=AKIAFAKE" in h1["Authorization"]


# ════════════════════════════════════════════════════════════════════════════
#  lockfiles
# ════════════════════════════════════════════════════════════════════════════

def test_package_lock_json_v3():
    from analyzer.lockfiles import parse_package_lock_json
    content = json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {}, "node_modules/lodash": {"version": "4.17.15"}},
    })
    tree = parse_package_lock_json(content)
    assert tree.packages["lodash"].version == "4.17.15"


def test_yarn_lock_dependencies():
    from analyzer.lockfiles import parse_yarn_lock
    content = (
        'express@^4.18.0:\n'
        '  version "4.18.2"\n'
        '  dependencies:\n'
        '    debug "2.6.9"\n'
    )
    tree = parse_yarn_lock(content)
    assert tree.packages["express"].version == "4.18.2"
    assert "debug" in tree.packages["express"].dependencies


def test_cargo_lock_multiline_array():
    from analyzer.lockfiles import parse_cargo_lock
    content = (
        '[[package]]\n'
        'name = "serde"\n'
        'version = "1.0.130"\n'
        'dependencies = [\n'
        ' "serde_derive",\n'
        ']\n'
    )
    tree = parse_cargo_lock(content)
    assert "serde_derive" in tree.packages["serde"].dependencies


def test_dependency_tree_transitive():
    from analyzer.lockfiles import DependencyTree, LockedPackage
    tree = DependencyTree()
    tree.add(LockedPackage("a", "1.0", "npm", dependencies=["b"]))
    tree.add(LockedPackage("b", "1.0", "npm", dependencies=["c"]))
    tree.add(LockedPackage("c", "1.0", "npm"))
    assert tree.transitive_of("a") == {"b", "c"}


# ════════════════════════════════════════════════════════════════════════════
#  manifests_ext
# ════════════════════════════════════════════════════════════════════════════

def test_composer_json_parser():
    from analyzer.manifests_ext import parse_composer_json
    comps = parse_composer_json('{"require":{"php":">=7.4","monolog/monolog":"^2.0"}}')
    assert len(comps) == 1
    assert comps[0].name == "monolog/monolog"


def test_gemfile_lock_parser():
    from analyzer.manifests_ext import parse_gemfile_lock
    content = "GEM\n  specs:\n    rails (7.0.4)\n    puma (5.6.5)\n"
    comps = parse_gemfile_lock(content)
    names = {c.name: c.version for c in comps}
    assert names["rails"] == "7.0.4"


def test_dockerfile_parser_extracts_base_and_packages():
    from analyzer.manifests_ext import parse_dockerfile
    content = "FROM python:3.11-slim\nRUN apt-get install -y curl=7.68.0 git\n"
    comps = parse_dockerfile(content)
    names = {c.name: c.version for c in comps}
    assert names["python"] == "3.11-slim"
    assert names["curl"] == "7.68.0"


# ════════════════════════════════════════════════════════════════════════════
#  vex
# ════════════════════════════════════════════════════════════════════════════

def test_vex_roundtrip_and_suppression(tmp_path):
    from analyzer.vex import VexDocument, VexStatement, suppress_by_vex

    class FakeDepVuln:
        def __init__(self, cve_id, package):
            self.cve_id, self.package = cve_id, package

    path = str(tmp_path / "vex.json")
    doc = VexDocument()
    doc.add_statement(VexStatement("CVE-2024-1", "pkgA", "not_affected"))
    doc.save(path)

    doc2 = VexDocument.load(path)
    kept, suppressed = suppress_by_vex(
        [FakeDepVuln("CVE-2024-1", "pkgA"), FakeDepVuln("CVE-2024-2", "pkgB")], doc2
    )
    assert len(kept) == 1 and kept[0].cve_id == "CVE-2024-2"
    assert len(suppressed) == 1


def test_vex_invalid_status_raises():
    from analyzer.vex import VexStatement
    with pytest.raises(ValueError):
        VexStatement("CVE-1", "pkg", "invalid_status")


# ════════════════════════════════════════════════════════════════════════════
#  dep_health
# ════════════════════════════════════════════════════════════════════════════

def test_levenshtein_basic():
    from analyzer.dep_health import levenshtein
    assert levenshtein("requests", "requests") == 0
    assert levenshtein("reqeusts", "requests") == 2


def test_typosquat_detection():
    from analyzer.dep_health import check_typosquatting
    r = check_typosquatting("reqeusts", "pypi")
    assert r is not None
    assert r.similar_to == "requests"


def test_typosquat_no_false_positive_on_real_package():
    from analyzer.dep_health import check_typosquatting
    assert check_typosquatting("pandas", "pypi") is None


def test_dependency_confusion_heuristic():
    from analyzer.dep_health import check_dependency_confusion
    assert check_dependency_confusion("internal-auth-lib") is not None
    assert check_dependency_confusion("requests") is None


def test_license_check_known_gpl_package():
    from analyzer.dep_health import check_license
    r = check_license("pyqt5")
    assert r is not None
    assert "GPL" in r.license


# ════════════════════════════════════════════════════════════════════════════
#  sbom_ext
# ════════════════════════════════════════════════════════════════════════════

def test_cyclonedx_xml_export(tmp_path):
    from analyzer.sbom import Component
    from analyzer.sbom_ext import export_cyclonedx_xml
    import xml.etree.ElementTree as ET

    comps = [Component(name="requests", version="2.31.0", purl="pkg:pypi/requests@2.31.0", package_type="pypi")]
    out = tmp_path / "sbom.xml"
    export_cyclonedx_xml(comps, str(out), "proj")
    tree = ET.parse(str(out))
    assert tree.getroot().tag.endswith("bom")


def test_spdx_json_export(tmp_path):
    from analyzer.sbom import Component
    from analyzer.sbom_ext import export_spdx_json

    comps = [Component(name="requests", version="2.31.0", purl="pkg:pypi/requests@2.31.0", package_type="pypi")]
    out = tmp_path / "sbom.spdx.json"
    export_spdx_json(comps, str(out), "proj")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["spdxVersion"] == "SPDX-2.3"
    assert data["packages"][0]["name"] == "requests"


def test_local_attestation_verify(tmp_path):
    from analyzer.sbom_ext import create_local_attestation, verify_local_attestation
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text('{"components": []}', encoding="utf-8")
    key = b"a" * 32
    att = create_local_attestation(str(sbom_path), key)
    assert verify_local_attestation(att, key) is True
    assert verify_local_attestation(att, b"b" * 32) is False


# ════════════════════════════════════════════════════════════════════════════
#  dep_autofix
# ════════════════════════════════════════════════════════════════════════════

def test_bump_plan_requirements_txt():
    from analyzer.deps import DepVuln
    from analyzer.dep_autofix import build_bump_plan

    vulns = [DepVuln(package="django", installed_version="3.0.0", cve_id="CVE-1",
                      description="d", severity="CRITICAL", fixed_version="4.2.2",
                      manifest_file="requirements.txt", line_number=1)]
    content = "django==3.0.0  # web\n"
    plan = build_bump_plan("requirements.txt", content, vulns)
    assert "django==4.2.2" in plan.updated_content
    assert "# web" in plan.updated_content
    assert "-django==3.0.0" in plan.diff


def test_bump_plan_picks_highest_fixed_version():
    from analyzer.deps import DepVuln
    from analyzer.dep_autofix import build_bump_plan

    vulns = [
        DepVuln(package="django", installed_version="3.0.0", cve_id="CVE-1",
                description="d", severity="HIGH", fixed_version="4.2.2",
                manifest_file="requirements.txt", line_number=1),
        DepVuln(package="django", installed_version="3.0.0", cve_id="CVE-2",
                description="d2", severity="CRITICAL", fixed_version="4.2.16",
                manifest_file="requirements.txt", line_number=1),
    ]
    plan = build_bump_plan("requirements.txt", "django==3.0.0\n", vulns)
    assert plan.entries[0].to_version == "4.2.16"


# ════════════════════════════════════════════════════════════════════════════
#  hash_pinning
# ════════════════════════════════════════════════════════════════════════════

def test_pinning_detects_unpinned_and_no_hash():
    from analyzer.hash_pinning import check_requirements_pinning
    content = "django>=3.0\nrequests==2.31.0\n"
    findings = check_requirements_pinning(content)
    issues = {f.package: f.issue for f in findings}
    assert issues["django"] == "versao_nao_fixada"
    assert issues["requests"] == "sem_hash"


def test_pinning_package_lock_missing_integrity():
    from analyzer.hash_pinning import check_package_lock_integrity
    content = json.dumps({"packages": {
        "": {},
        "node_modules/lodash": {"version": "4.17.15", "integrity": "sha512-x"},
        "node_modules/leftpad": {"version": "1.0.0"},
    }})
    findings = check_package_lock_integrity(content)
    assert len(findings) == 1
    assert findings[0].package == "leftpad"
