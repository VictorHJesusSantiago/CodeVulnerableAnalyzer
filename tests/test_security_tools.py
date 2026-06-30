"""
Testes do cofre de segredos (AES/vault), parser .csproj e integração OSV.
Rodar: python -m pytest tests/ -q
"""
from __future__ import annotations
import os
import sys
import json
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ════════════════════════════════════════════════════════════════════════════
#  Vault — AES e SecretVault
# ════════════════════════════════════════════════════════════════════════════

def test_aes256_fips197_vector():
    from analyzer.vault import AES
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    pt  = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct  = AES(key).encrypt_block(pt)
    assert ct.hex() == "8ea2b7ca516745bfeafc49904b496089"
    assert AES(key).decrypt_block(ct) == pt


def test_aes128_fips197_vector():
    from analyzer.vault import AES
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt  = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert AES(key).encrypt_block(pt).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_cbc_roundtrip_arbitrary_length():
    from analyzer.vault import aes_cbc_encrypt, aes_cbc_decrypt
    key = os.urandom(32)
    iv  = os.urandom(16)
    for msg in [b"", b"a", b"exatamente16byte", b"mensagem de comprimento irregular !@#$"]:
        assert aes_cbc_decrypt(key, iv, aes_cbc_encrypt(key, iv, msg)) == msg


def test_vault_create_set_get(tmp_path):
    from analyzer.vault import SecretVault
    path = str(tmp_path / "c.vault")
    v = SecretVault.create(path, "mestre123")
    v.set_secret("db", "p@ss")
    v.save()
    v2 = SecretVault.open(path, "mestre123")
    assert v2.get_secret("db") == "p@ss"
    assert v2.list_secrets() == ["db"]


def test_vault_wrong_password(tmp_path):
    from analyzer.vault import SecretVault, VaultError
    path = str(tmp_path / "c.vault")
    SecretVault.create(path, "certa")
    with pytest.raises(VaultError):
        SecretVault.open(path, "errada")


def test_vault_tamper_detection(tmp_path):
    from analyzer.vault import SecretVault, VaultError
    path = str(tmp_path / "c.vault")
    v = SecretVault.create(path, "mestre")
    v.set_secret("k", "v")
    v.save()
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    doc["secrets"]["k"]["ct"] = "00" * 32          # corrompe ciphertext
    Path(path).write_text(json.dumps(doc), encoding="utf-8")
    v2 = SecretVault.open(path, "mestre")
    with pytest.raises(VaultError):
        v2.get_secret("k")


def test_vault_change_password(tmp_path):
    from analyzer.vault import SecretVault, VaultError
    path = str(tmp_path / "c.vault")
    v = SecretVault.create(path, "antiga")
    v.set_secret("k", "segredo")
    v.change_password("nova")
    v.save()
    with pytest.raises(VaultError):
        SecretVault.open(path, "antiga")
    assert SecretVault.open(path, "nova").get_secret("k") == "segredo"


# ════════════════════════════════════════════════════════════════════════════
#  Parser .csproj (NuGet)
# ════════════════════════════════════════════════════════════════════════════

_CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>"""


def test_csproj_deps_detects_known_cve():
    from analyzer.deps import _parse_csproj
    vulns = _parse_csproj(_CSPROJ, "App.csproj")
    assert any(v.package == "newtonsoft.json" for v in vulns)


def test_csproj_sbom_components():
    from analyzer.sbom import _from_csproj
    comps = {c.name: c for c in _from_csproj(_CSPROJ)}
    assert "Serilog" in comps
    assert comps["Serilog"].purl == "pkg:nuget/Serilog@3.1.1"


def test_csproj_routed_by_suffix(tmp_path):
    from analyzer.deps import scan_manifest_dir
    (tmp_path / "MyApp.csproj").write_text(_CSPROJ, encoding="utf-8")
    vulns = scan_manifest_dir(str(tmp_path))
    assert any(v.package == "newtonsoft.json" for v in vulns)


# ════════════════════════════════════════════════════════════════════════════
#  OSV — parsing offline + consulta online (resiliente a falta de rede)
# ════════════════════════════════════════════════════════════════════════════

def test_osv_severity_from_cvss():
    from analyzer.deps import _osv_severity, _cvss_v3_base
    # Vetor real "crítico" (9.8) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    crit = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert abs(_cvss_v3_base(crit) - 9.8) < 0.01
    assert _osv_severity({"severity": [{"type": "CVSS_V3", "score": crit}]}) == "CRITICAL"
    assert _osv_severity({"database_specific": {"severity": "MODERATE"}}) == "MEDIUM"
    assert _osv_severity({}) == "MEDIUM"


def test_osv_fixed_version_extraction():
    from analyzer.deps import _osv_fixed_version
    vuln = {"affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}]}
    assert _osv_fixed_version(vuln) == "2.10.1"


@pytest.mark.network
def test_osv_live_query_jinja2():
    """Consulta real à OSV.dev; pulada automaticamente se não houver rede."""
    from analyzer.deps import query_osv
    try:
        results = query_osv("jinja2", "2.10", "PyPI", timeout=10)
    except Exception:
        pytest.skip("sem rede")
    if not results:
        pytest.skip("OSV indisponível ou sem achados")
    assert any(r.cve_id.startswith("CVE-") for r in results)
