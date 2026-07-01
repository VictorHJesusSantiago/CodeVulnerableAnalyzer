"""Análise de AsyncAPI, SOAP/WSDL, GraphQL e autorização BOLA/BFLA."""
from __future__ import annotations
import re,xml.etree.ElementTree as ET
from typing import Any,Dict,List

def scan_asyncapi(spec:Dict[str,Any])->List[Dict[str,Any]]:
    out=[]
    if not spec.get("asyncapi"):out.append({"rule_id":"ASYNCAPI-001","severity":"low","message":"Versão AsyncAPI ausente"})
    servers=spec.get("servers",{})
    for name,server in servers.items():
        if str(server.get("url","")).startswith(("ws://","mqtt://","http://")):out.append({"rule_id":"ASYNCAPI-002","severity":"high","server":name,"message":"Transporte sem TLS"})
        if not server.get("security"):out.append({"rule_id":"ASYNCAPI-003","severity":"high","server":name,"message":"Servidor sem autenticação declarada"})
    for channel,item in spec.get("channels",{}).items():
        for op in ("publish","subscribe","send","receive"):
            if op in item and not item[op].get("security") and not servers:out.append({"rule_id":"ASYNCAPI-004","severity":"medium","channel":channel,"message":"Operação sem segurança"})
    return out

def scan_wsdl(xml:str)->List[Dict[str,Any]]:
    out=[]
    try:root=ET.fromstring(xml)
    except ET.ParseError:return [{"rule_id":"SOAP-001","severity":"medium","message":"WSDL/XML inválido"}]
    text=ET.tostring(root,encoding="unicode")
    if re.search(r'(?:soap:address|address)\s+location="http://',text,re.I):out.append({"rule_id":"SOAP-002","severity":"high","message":"Endpoint SOAP sem TLS"})
    if not re.search(r'(?:Policy|Security|UsernameToken|TransportBinding)',text,re.I):out.append({"rule_id":"SOAP-003","severity":"high","message":"WS-Security não declarado"})
    if re.search(r'<!DOCTYPE|<!ENTITY',xml,re.I):out.append({"rule_id":"SOAP-XXE-001","severity":"critical","message":"DTD/entidade externa no WSDL"})
    return out

def scan_graphql_schema(schema:str)->List[Dict[str,Any]]:
    out=[]
    if re.search(r'\btype\s+Query\s*\{[\s\S]*?(?:users|accounts|orders)\s*(?:\([^)]*\))?\s*:',schema,re.I) and not re.search(r'@(?:auth|requires|authenticated)',schema,re.I):
        out.append({"rule_id":"GRAPHQL-BFLA-001","severity":"high","message":"Query sensível sem diretiva de autorização"})
    if re.search(r'\b(?:user|account|order)\s*\(\s*id\s*:\s*ID',schema,re.I) and not re.search(r'@(?:owner|auth|requires)',schema,re.I):
        out.append({"rule_id":"GRAPHQL-BOLA-001","severity":"high","message":"Objeto por ID sem autorização em nível de objeto"})
    if "__schema" in schema or "__type" in schema:out.append({"rule_id":"GRAPHQL-INTROSPECTION-001","severity":"low","message":"Referência explícita a introspecção"})
    return out

def bfla_matrix(spec:Dict[str,Any],roles:Dict[str,List[str]])->List[Dict[str,Any]]:
    gaps=[]
    for path,item in spec.get("paths",{}).items():
        for method,op in item.items():
            if method.lower() not in {"get","post","put","patch","delete"}:continue
            operation=op.get("operationId",f"{method}:{path}");allowed={r for r,ops in roles.items() if operation in ops}
            if not allowed:gaps.append({"rule_id":"API-BFLA-001","severity":"high","operation":operation,"message":"Nenhum papel autorizado"})
            if method.lower() in {"delete","put","patch"} and "anonymous" in allowed:gaps.append({"rule_id":"API-BFLA-002","severity":"critical","operation":operation,"message":"Operação mutável permite anonymous"})
    return gaps
