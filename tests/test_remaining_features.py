import json,zipfile
from analyzer.iac_render import *
from analyzer.mobile_archive import *
from analyzer.api_extended import *
from analyzer.secret_history import *
from analyzer.semantic_ir import *

def test_helm_and_kustomize():
    rendered=render_helm("image: {{ .Values.image | quote }}\nname: {{ .Release.Name }}",{"image":"app:1"},"prod")
    assert '"app:1"' in rendered and "prod" in rendered
    base={"apiVersion":"v1","kind":"Pod","metadata":{"name":"web"},"spec":{"containers":[{"name":"app","image":"old"},{"name":"sidecar","image":"s"}]}}
    patch={"kind":"Pod","metadata":{"name":"web"},"spec":{"containers":[{"name":"app","image":"new"}]}}
    out=kustomize([base],[patch],"pre-","ns")[0]
    assert out["metadata"]=={"name":"pre-web","namespace":"ns"}
    assert out["spec"]["containers"][0]["image"]=="new" and len(out["spec"]["containers"])==2

def test_extended_iac_rules():
    assert scan_extended_iac('default allow = true',"rego")[0]["rule_id"]=="REGO-001"
    assert scan_extended_iac("ssh_pwauth: true","cloud-init")[0]["severity"]=="high"
    assert scan_extended_iac("validationFailureAction: Audit","kyverno")

def test_mobile_archive(tmp_path):
    apk=tmp_path/"app.apk"
    with zipfile.ZipFile(apk,"w") as z:
        z.writestr("AndroidManifest.xml",'<manifest><application android:debuggable="true"/></manifest>')
        z.writestr("assets/config.js",'api_key="abcdefghijklmnop123"')
        z.writestr("META-INF/CERT.RSA",b"certificate")
    result=scan_mobile_archive(apk)
    ids={x["rule_id"] for x in result["findings"]}
    assert "MOBILE-ANDROID-001" in ids and "MOBILE-SECRET-001" in ids
    assert result["certificates"]

def test_api_protocols_and_bfla():
    assert any(x["rule_id"]=="ASYNCAPI-002" for x in scan_asyncapi({"asyncapi":"3.0","servers":{"x":{"url":"ws://x"}}}))
    wsdl='<definitions xmlns:soap="urn:x"><soap:address location="http://x"/></definitions>'
    assert {x["rule_id"] for x in scan_wsdl(wsdl)}=={"SOAP-002","SOAP-003"}
    assert scan_graphql_schema("type Query { users: [User] }")
    spec={"paths":{"/admin":{"delete":{"operationId":"deleteAll"}}}}
    assert bfla_matrix(spec,{})[0]["rule_id"]=="API-BFLA-001"

def test_secret_patch_history():
    patch="""commit abc123
+++ b/config.py
@@ -0,0 +1,1 @@
+token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
"""
    findings=scan_patch_history(patch)
    assert findings and findings[0]["commit"]=="abc123" and len(findings[0]["fingerprint"])==64

def test_cfg_ssa_dataflow_intervals_and_symbolic():
    cfg=cfg_from_python("x=1\nif x:\n y=x+1\nelse:\n y=0\nz=y\n")
    assert cfg.exit in cfg.reachable() and len(symbolic_paths(cfg))==2
    assert reaching_definitions(cfg) and live_variables(cfg)
    ssa=to_ssa(cfg);targets=[i.target for b in ssa.blocks.values() for i in b.instructions if i.target]
    assert "x_1" in targets
    env=interpret_intervals([Instruction("assign","x",("1",)),Instruction("assign","y",("x + 2",))])
    assert env["y"]==Interval(3,3)

def test_memory_lifetime_findings():
    ins=[Instruction("alloc","p",line=1),Instruction("free",args=("p",),line=2),Instruction("read",args=("p",),line=3),Instruction("free",args=("p",),line=4)]
    ids={x["rule_id"] for x in memory_lifetime_findings(ins)}
    assert ids=={"IR-USE-AFTER-FREE","IR-DOUBLE-FREE"}
