"""Analisadores semânticos de Mobile, Web, API, Banco, Blockchain e AI/ML."""
from __future__ import annotations
import json, re
from typing import Any, Dict, List

def _hit(rule: str, severity: str, message: str, **context: Any) -> Dict[str, Any]:
    return {"rule_id": rule, "severity": severity, "message": message, **context}

def scan_android_manifest(xml: str) -> List[Dict[str, Any]]:
    out = []
    checks = [
      ("MOBILE-ANDROID-001", r'android:debuggable\s*=\s*"true"', "critical", "Aplicativo depurável em produção"),
      ("MOBILE-ANDROID-002", r'android:usesCleartextTraffic\s*=\s*"true"', "high", "Tráfego HTTP permitido"),
      ("MOBILE-ANDROID-003", r'android:allowBackup\s*=\s*"true"', "medium", "Backup de dados habilitado"),
      ("MOBILE-ANDROID-004", r'<(?:activity|service|receiver|provider)[^>]*android:exported\s*=\s*"true"[^>]*(?!android:permission)', "high", "Componente exportado sem permissão"),
      ("MOBILE-ANDROID-005", r'<data[^>]*android:scheme\s*=\s*"https?"[^>]*(?!android:host)', "medium", "Deep link sem host restrito"),
    ]
    for rid, pattern, sev, msg in checks:
        if re.search(pattern, xml, re.I | re.S): out.append(_hit(rid, sev, msg))
    return out

def scan_mobile_code(text: str) -> List[Dict[str, Any]]:
    out=[]
    for rid, pattern, sev, msg in [
      ("MOBILE-PIN-001", r'(?:TrustAll|allowInvalidCertificates|proceed\(\)|HostnameVerifier\s*\{[^}]*true)', "critical", "Certificate pinning/validação TLS desabilitada"),
      ("MOBILE-WEBVIEW-001", r'setJavaScriptEnabled\s*\(\s*true\s*\)', "medium", "JavaScript habilitado em WebView"),
      ("MOBILE-WEBVIEW-002", r'addJavascriptInterface\s*\(', "high", "Bridge JavaScript nativa exposta"),
      ("MOBILE-IOS-ATS-001", r'NSAllowsArbitraryLoads.{0,80}(?:true|YES)', "high", "App Transport Security desabilitado"),
    ]:
        if re.search(pattern,text,re.I|re.S): out.append(_hit(rid,sev,msg))
    return out

def analyze_http_security(headers: Dict[str, str], status: int = 200) -> List[Dict[str, Any]]:
    h={k.lower():v for k,v in headers.items()}; out=[]
    required={"content-security-policy":"WEB-CSP-001","x-content-type-options":"WEB-HEADER-001",
              "strict-transport-security":"WEB-HEADER-002","referrer-policy":"WEB-HEADER-003"}
    for name,rid in required.items():
        if name not in h: out.append(_hit(rid,"medium",f"Header ausente: {name}"))
    csp=h.get("content-security-policy","")
    if re.search(r"'unsafe-(?:inline|eval)'|\*",csp): out.append(_hit("WEB-CSP-002","high","CSP contém fonte insegura"))
    origin=h.get("access-control-allow-origin","")
    if origin=="*" and h.get("access-control-allow-credentials","").lower()=="true":
        out.append(_hit("WEB-CORS-001","critical","CORS permite credenciais com origem curinga"))
    cookies=h.get("set-cookie","")
    if cookies and ("secure" not in cookies.lower() or "httponly" not in cookies.lower() or "samesite" not in cookies.lower()):
        out.append(_hit("WEB-COOKIE-001","high","Cookie sem Secure, HttpOnly ou SameSite"))
    return out

def scan_web_code(text: str) -> List[Dict[str, Any]]:
    patterns=[
      ("WEB-SSRF-001",r'(?:requests\.get|fetch|axios\.get)\s*\(\s*(?:req|request|url|input)',"high","URL controlada alcança cliente HTTP"),
      ("WEB-SSTI-001",r'(?:render_template_string|Template)\s*\(\s*(?:req|request|input)',"critical","Template compilado a partir de entrada"),
      ("WEB-XXE-001",r'(?:resolve_entities\s*=\s*True|DocumentBuilderFactory)(?![\s\S]{0,150}disallow-doctype)', "high","Parser XML aceita entidades externas"),
      ("WEB-PROTO-001",r'(?:__proto__|constructor\.prototype)\s*=', "high","Prototype pollution"),
      ("WEB-DOMXSS-001",r'(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML)\s*(?:=|\()', "high","Entrada em sink DOM XSS"),
    ]
    return [_hit(r,s,m) for r,p,s,m in patterns if re.search(p,text,re.I)]

def analyze_api_contract(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    out=[]; paths=spec.get("paths",{})
    if not spec.get("openapi") and not spec.get("asyncapi"): out.append(_hit("API-SPEC-001","low","Versão do contrato ausente"))
    for path,item in paths.items():
        for method,op in item.items():
            if method.lower() not in {"get","post","put","patch","delete"} or not isinstance(op,dict): continue
            if not op.get("security") and not spec.get("security"):
                out.append(_hit("API-AUTH-001","high","Operação sem segurança declarada",path=path,method=method))
            if re.search(r"\{(?:id|userId|accountId)\}",path,re.I) and not any("403"==str(x) for x in op.get("responses",{})):
                out.append(_hit("API-BOLA-001","high","Recurso por ID sem resposta de autorização 403",path=path,method=method))
            if not op.get("responses"): out.append(_hit("API-CONTRACT-001","medium","Operação sem respostas",path=path,method=method))
    return out

def generate_contract_cases(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    cases=[]
    for path,item in spec.get("paths",{}).items():
      for method,op in item.items():
       if method in {"get","post","put","patch","delete"}:
        cases.extend({"path":path,"method":method.upper(),"mutation":m} for m in ("missing-required","wrong-type","boundary","unexpected-field"))
    return cases

def scan_database(text: str) -> List[Dict[str, Any]]:
    rules=[
      ("DB-INJECTION-001",r'(?:execute|raw|query)\s*\([^)]*(?:\+|f["\']|\$\{)',"critical","SQL construído por concatenação"),
      ("DB-NPLUS1-001",r'for\s+.+:\s*[\s\S]{0,160}(?:\.query|\.find|SELECT)',"medium","Consulta dentro de loop sugere N+1"),
      ("DB-RLS-001",r'CREATE\s+TABLE(?![\s\S]{0,300}ENABLE\s+ROW\s+LEVEL\s+SECURITY)',"medium","Tabela sem RLS"),
      ("DB-PII-001",r'(?:email|cpf|ssn|credit_card)\s+(?:varchar|text)(?![\s\S]{0,80}(?:encrypt|mask))',"high","Coluna PII sem mascaramento/criptografia aparente"),
      ("DB-PROC-001",r'EXECUTE\s+(?:IMMEDIATE|format)\s*\([^)]*(?:\|\||\+)',"critical","SQL dinâmico em stored procedure"),
    ]
    return [_hit(r,s,m) for r,p,s,m in rules if re.search(p,text,re.I)]

def scan_blockchain(text: str) -> List[Dict[str, Any]]:
    rules=[
      ("CHAIN-REENTRANCY-001",r'\.call\{value:[^}]+\}\([^)]*\)[\s\S]{0,240}(?:balances|balanceOf)\s*\[.*\]\s*[-=]',"critical","Estado atualizado após chamada externa"),
      ("CHAIN-ORACLE-001",r'(?:latestAnswer|latestRoundData)\s*\([^)]*\)(?![\s\S]{0,180}(?:updatedAt|stale))',"high","Oracle sem validação de freshness"),
      ("CHAIN-MEV-001",r'(?:amountOutMin|deadline)\s*[:=]\s*0',"high","Swap sem proteção de slippage/deadline"),
      ("CHAIN-PROXY-001",r'(?:delegatecall|upgradeTo)\s*\((?![\s\S]{0,120}(?:onlyOwner|onlyRole))',"critical","Upgrade/delegatecall sem controle visível"),
      ("CHAIN-GAS-001",r'for\s*\([^;]*;[^;]*<\s*\w+\.length',"low","Loop sobre storage dinâmico pode esgotar gas"),
    ]
    return [_hit(r,s,m) for r,p,s,m in rules if re.search(p,text,re.I)]

def scan_ml(text: str) -> List[Dict[str, Any]]:
    rules=[
      ("ML-DESERIALIZE-001",r'(?:pickle\.load|torch\.load|joblib\.load)\s*\(',"critical","Modelo/objeto desserializado com formato executável"),
      ("ML-PROMPT-001",r'(?:system_prompt|messages)\s*(?:\+|\.append)\s*\(?\s*(?:user|request|input)',"high","Entrada incorporada ao prompt privilegiado"),
      ("ML-POISON-001",r'(?:fit|train)\s*\(\s*(?:uploaded|external|untrusted)',"high","Treino usa dataset não confiável"),
      ("ML-PII-001",r'(?:email|phone|cpf|ssn).*(?:dataset|training|features)',"high","Possível PII em dataset"),
      ("ML-LEAK-001",r'(?:print|log)\s*\([^)]*(?:prediction|embedding|prompt)',"medium","Artefato de modelo pode vazar em logs"),
    ]
    return [_hit(r,s,m) for r,p,s,m in rules if re.search(p,text,re.I)]

def generate_mlbom(models: List[Dict[str, Any]], datasets: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"bomFormat":"CycloneDX","specVersion":"1.6","type":"ML-BOM",
            "models":[{"name":m["name"],"version":m.get("version","unknown"),"hashes":m.get("hashes",[]),
                       "modelCard":m.get("modelCard")} for m in models],
            "datasets":[{"name":d["name"],"license":d.get("license"),"containsPII":bool(d.get("containsPII"))} for d in datasets]}
