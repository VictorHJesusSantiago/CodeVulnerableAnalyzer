"""Telemetria opt-in, atualização assinada, versão de regras, i18n e catálogo."""
from __future__ import annotations
import hashlib,hmac,json,locale,urllib.request
from pathlib import Path
from typing import Any,Dict,Iterable,List

MESSAGES={
 "pt-BR":{"scan.complete":"Análise concluída","finding.count":"{count} achados","education.why":"Por que isso importa"},
 "en":{"scan.complete":"Scan complete","finding.count":"{count} findings","education.why":"Why this matters"},
 "es":{"scan.complete":"Análisis concluido","finding.count":"{count} hallazgos","education.why":"Por qué importa"},
}
def translate(key:str,lang:str="pt-BR",**values:Any)->str:return MESSAGES.get(lang,MESSAGES["en"]).get(key,key).format(**values)

class Telemetry:
    def __init__(self,enabled:bool=False,endpoint:str=""):self.enabled,self.endpoint=enabled,endpoint;self.events=[]
    def record(self,name:str,properties:Dict[str,Any])->None:
        if not self.enabled:return
        safe={k:v for k,v in properties.items() if k in {"duration_ms","file_count","finding_count","version","platform"}}
        self.events.append({"name":name,"properties":safe})
    def flush(self)->int:
        if not self.enabled or not self.endpoint:return 0
        body=json.dumps({"events":self.events}).encode();req=urllib.request.Request(self.endpoint,body,{"Content-Type":"application/json"})
        with urllib.request.urlopen(req,timeout=5) as r:count=len(self.events);self.events.clear();return count if r.status<300 else 0

def verify_update(data:bytes,signature:str,key:bytes)->bool:return hmac.compare_digest(hmac.new(key,data,hashlib.sha256).hexdigest(),signature)
def install_rule_pack(data:bytes,signature:str,key:bytes,target:str|Path)->Path:
    if not verify_update(data,signature,key):raise ValueError("Assinatura do pacote de regras inválida")
    doc=json.loads(data);version=doc.get("version")
    if not version or not isinstance(doc.get("rules"),list):raise ValueError("Pacote de regras inválido")
    path=Path(target)/f"rules-{version}.json";path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);return path
def rule_catalog(rules:Iterable[Any])->List[Dict[str,Any]]:
    return [{"id":getattr(r,"id",""),"name":getattr(r,"name",""),"language":getattr(getattr(r,"language",None),"value",""),
             "severity":getattr(getattr(r,"severity",None),"name",""),"category":getattr(getattr(r,"category",None),"value",""),
             "cwe":getattr(r,"cwe",None),"description":getattr(r,"description",""),"remediation":getattr(r,"remediation","")} for r in rules]
def search_catalog(catalog:Iterable[Dict[str,Any]],query:str)->List[Dict[str,Any]]:
    words=query.lower().split();return [r for r in catalog if all(w in json.dumps(r,ensure_ascii=False).lower() for w in words)]
