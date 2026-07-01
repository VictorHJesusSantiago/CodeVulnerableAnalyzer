"""Clientes e normalizadores para fontes adicionais de advisories."""
from __future__ import annotations
import base64,json,urllib.parse,urllib.request
from dataclasses import dataclass,asdict
from typing import Any,Dict,List,Optional
@dataclass
class Advisory:
    id:str;package:str;ecosystem:str;severity:str;summary:str;fixed_versions:List[str];source:str
def _get_json(url:str,headers:Optional[Dict[str,str]]=None,timeout:int=10)->Any:
    req=urllib.request.Request(url,headers={"Accept":"application/json",**(headers or {})})
    with urllib.request.urlopen(req,timeout=timeout) as r:return json.load(r)
def query_deps_dev(system:str,package:str,version:str)->List[Advisory]:
    key=urllib.parse.quote(package,safe="");doc=_get_json(f"https://api.deps.dev/v3/systems/{system}/packages/{key}/versions/{version}")
    return [Advisory(a.get("advisoryKey",{}).get("id","unknown"),package,system,"UNKNOWN","",[], "deps.dev") for a in doc.get("advisoryKeys",[])]
def query_nvd(cpe:str,api_key:str="")->List[Advisory]:
    headers={"apiKey":api_key} if api_key else {};doc=_get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName="+urllib.parse.quote(cpe,safe=":/"),headers)
    out=[]
    for item in doc.get("vulnerabilities",[]):
        cve=item.get("cve",{});desc=next((x["value"] for x in cve.get("descriptions",[]) if x.get("lang")=="en"),"")
        metrics=cve.get("metrics",{});sev="UNKNOWN"
        for name in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            if metrics.get(name):sev=metrics[name][0].get("cvssData",{}).get("baseSeverity",metrics[name][0].get("baseSeverity","UNKNOWN"));break
        out.append(Advisory(cve.get("id","unknown"),cpe,"cpe",sev,desc,[],"NVD"))
    return out
def query_github_advisories(ecosystem:str,package:str,token:str)->List[Advisory]:
    params=urllib.parse.urlencode({"ecosystem":ecosystem,"affects":package,"per_page":100})
    doc=_get_json("https://api.github.com/advisories?"+params,{"Authorization":"Bearer "+token,"X-GitHub-Api-Version":"2022-11-28"})
    return [Advisory(x.get("ghsa_id",""),package,ecosystem,x.get("severity","UNKNOWN").upper(),x.get("summary",""),[], "GHSA") for x in doc]
def query_oss_index(coordinates:List[str],username:str,token:str)->List[Advisory]:
    body=json.dumps({"coordinates":coordinates}).encode();auth=base64.b64encode(f"{username}:{token}".encode()).decode()
    req=urllib.request.Request("https://ossindex.sonatype.org/api/v3/component-report",body,{"Content-Type":"application/json","Authorization":"Basic "+auth})
    with urllib.request.urlopen(req,timeout=15) as r:doc=json.load(r)
    out=[]
    for component in doc:
        for v in component.get("vulnerabilities",[]):out.append(Advisory(v.get("id",""),component.get("coordinates",""),"purl",str(v.get("cvssScore","")),v.get("title",""),[], "OSS Index"))
    return out
