import json,zipfile
from analyzer.vault_advanced import *
from analyzer.identity import *
from analyzer.reporting_ext import *
from analyzer.integrations import *
from analyzer.ux import *

def test_chacha_aead_and_tamper():
    key=bytes(range(32));nonce=bytes(range(12));cipher,tag=chacha20poly1305_encrypt(key,nonce,b"segredo",b"ctx")
    assert chacha20poly1305_decrypt(key,nonce,cipher,tag,b"ctx")==b"segredo"
    try:chacha20poly1305_decrypt(key,nonce,cipher,bytes([tag[0]^1])+tag[1:],b"ctx")
    except VaultSecurityError:pass
    else:assert False

def test_shamir_and_vault_features():
    secret=b"master-key-32-bytes"
    shares=shamir_split(secret,5,3)
    assert shamir_combine([shares[0],shares[2],shares[4]])==secret
    vault=AdvancedVault("forte")
    vault.grant("alice","admin")
    assert vault.put("api","token-1","alice")==1
    assert vault.rotate("api",lambda:"token-2","alice")==2
    assert vault.get("api","alice",1)=="token-1"
    assert vault.get("api","alice")=="token-2"
    assert vault.leaked(["x","token-2"],"alice")==["api"]
    assert vault.verify_audit()
    blob=vault.export_encrypted()
    restored=AdvancedVault.restore_with_salt(blob,"forte",vault.salt)
    assert restored.get("api","alice")=="token-2"
    agent=MemorySecretAgent(restored);assert agent.get("api","alice")=="token-2";agent.lock();assert not agent.cache

def test_identity_graph_and_detection():
    g=IdentityGraph()
    for p in [Principal("u","user","ad"),Principal("g","group","ad"),Principal("d","domain","ad",{"tier0":True})]:g.add_principal(p)
    g.add_edge(PrivilegeEdge("u","g","AddMember",{"write"}));g.add_edge(PrivilegeEdge("g","d","DCSync",{"replicate"}))
    assert g.escalation_paths()[0]["source"]=="u"
    assert g.simulate_removal("g","d","DCSync")["paths_removed"]>0
    assert g.least_privilege({"u":set(),"g":set()})
    risks=detect_identity_risks({"users":[{"id":"u","mfa":False}],"service_principals":[{"id":"sp","secrets":["x"]}]})
    assert {"IAM-MFA-001","AAD-SP-SECRET-001"}<={x["rule_id"] for x in risks}

def test_reports_formats_and_diff(tmp_path):
    old={"findings":[]};new={"findings":[{"rule_id":"X","severity":"high","file_path":"a.py","line_number":3,"description":"erro","fix":"safe()","code_flow":[{"file":"a.py","line":1}]}]}
    assert len(scan_diff(old,new)["new"])==1
    assert advanced_sarif(new)["runs"][0]["results"][0]["fixes"]
    assert gitlab_sast(new)["vulnerabilities"][0]["severity"]=="High"
    assert heatmap(new)[0]["risk"]==5
    assert "DATA=" in interactive_html(new)
    for fn,export in [("r.docx",export_docx),("r.xlsx",export_xlsx),("r.pdf",export_pdf)]:
        path=tmp_path/fn;export(new,str(path));assert path.stat().st_size>100
    with zipfile.ZipFile(tmp_path/"r.docx") as z:assert "word/document.xml" in z.namelist()
    with zipfile.ZipFile(tmp_path/"r.xlsx") as z:assert "xl/worksheets/sheet1.xml" in z.namelist()
    assert sign_report(b"x",b"k")["sha256"]
    assert jira_issues(new,"SEC")[0]["fields"]["project"]["key"]=="SEC"

def test_integrations_quality_gate_queue_and_ux():
    body=b'{"x":1}';secret="s"
    import hashlib,hmac
    sig="sha256="+hmac.new(secret.encode(),body,hashlib.sha256).hexdigest()
    assert verify_webhook(body,sig,secret)
    gate=QualityGate(max_high=0).evaluate([{"severity":"high"}])
    assert not gate["passed"] and scm_check("github","abc",gate)["conclusion"]=="failure"
    q=MemoryQueue();seen=[];q.publish("scan",{"id":1});q.consume("scan",seen.append);assert seen
    ux=UXState();ux.suppress("X","a","aceito");assert ux.undo_suppression()
    assert regex_playground(r"a+","baaa")[0]["match"]=="aaa"
    assert ast_playground("def f(): pass")["functions"]==["f"]
