"""Renderizadores e scanners estruturais para Helm, Kustomize e IaC estendido."""
from __future__ import annotations
import copy,json,re,subprocess,tempfile
from pathlib import Path
from typing import Any,Dict,Iterable,List,Optional

class RenderError(ValueError):pass

def _lookup(values:Dict[str,Any],path:str)->Any:
    current:Any=values
    for part in path.strip(".").split("."):
        if not part:continue
        if not isinstance(current,dict) or part not in current:raise RenderError(f"Valor ausente: {path}")
        current=current[part]
    return current

def render_helm(template:str,values:Dict[str,Any],release_name:str="release",namespace:str="default")->str:
    """Render seguro do subconjunto determinístico mais comum de templates Helm."""
    context={"Values":values,"Release":{"Name":release_name,"Namespace":namespace}}
    def replace(match:re.Match)->str:
        expr=match.group(1).strip().lstrip("-").rstrip("-").strip()
        if expr.startswith(("if ","range ","with ","end","include ","tpl ")):
            raise RenderError("Blocos/funções dinâmicas requerem o binário Helm oficial")
        parts=[x.strip() for x in expr.split("|")]
        value=_lookup(context,parts[0])
        for fn in parts[1:]:
            if fn=="quote":value=json.dumps(str(value))
            elif fn=="lower":value=str(value).lower()
            elif fn=="upper":value=str(value).upper()
            elif fn.startswith("default "):
                default=fn[8:].strip().strip("\"'");value=value if value not in (None,"") else default
            else:raise RenderError(f"Função Helm não suportada: {fn}")
        if isinstance(value,bool):return str(value).lower()
        if isinstance(value,(dict,list)):return json.dumps(value,separators=(",",":"))
        return str(value)
    return re.sub(r"\{\{\s*(.*?)\s*\}\}",replace,template)

def render_helm_chart(chart:str|Path,values_file:Optional[str|Path]=None,release_name:str="vulnscan",
                      namespace:str="default",helm_binary:str="helm",timeout:int=30)->str:
    """Render completo delegando ao Helm oficial, sem shell interpolation."""
    command=[helm_binary,"template",release_name,str(chart),"--namespace",namespace]
    if values_file:command+=["--values",str(values_file)]
    try:
        result=subprocess.run(command,capture_output=True,text=True,timeout=timeout,check=False)
    except FileNotFoundError as exc:raise RenderError("Binário Helm não encontrado") from exc
    except subprocess.TimeoutExpired as exc:raise RenderError("Render Helm excedeu o timeout") from exc
    if result.returncode:raise RenderError(result.stderr.strip() or "Falha no Helm")
    return result.stdout

def build_kustomize_dir(directory:str|Path,kustomize_binary:str="kustomize",timeout:int=30)->str:
    """Build completo por binário Kustomize oficial."""
    try:
        result=subprocess.run([kustomize_binary,"build",str(directory)],capture_output=True,text=True,timeout=timeout,check=False)
    except FileNotFoundError as exc:raise RenderError("Binário Kustomize não encontrado") from exc
    except subprocess.TimeoutExpired as exc:raise RenderError("Kustomize excedeu o timeout") from exc
    if result.returncode:raise RenderError(result.stderr.strip() or "Falha no Kustomize")
    return result.stdout

def strategic_merge(base:Any,patch:Any)->Any:
    if isinstance(base,dict) and isinstance(patch,dict):
        out=copy.deepcopy(base)
        for key,value in patch.items():
            if value is None:out.pop(key,None)
            else:out[key]=strategic_merge(out.get(key),value) if key in out else copy.deepcopy(value)
        return out
    if isinstance(base,list) and isinstance(patch,list) and all(isinstance(x,dict) and "name" in x for x in base+patch):
        out=copy.deepcopy(base);positions={x["name"]:i for i,x in enumerate(out)}
        for item in patch:
            if item["name"] in positions:out[positions[item["name"]]]=strategic_merge(out[positions[item["name"]]],item)
            else:out.append(copy.deepcopy(item))
        return out
    return copy.deepcopy(patch)

def kustomize(resources:Iterable[Dict[str,Any]],patches:Iterable[Dict[str,Any]]=(),name_prefix:str="",namespace:str="")->List[Dict[str,Any]]:
    docs=[copy.deepcopy(x) for x in resources]
    for patch in patches:
        meta=patch.get("metadata",{})
        for i,doc in enumerate(docs):
            if doc.get("kind")==patch.get("kind") and doc.get("metadata",{}).get("name")==meta.get("name"):
                docs[i]=strategic_merge(doc,patch);break
    for doc in docs:
        meta=doc.setdefault("metadata",{});meta["name"]=name_prefix+meta.get("name","")
        if namespace and doc.get("kind") not in {"Namespace","ClusterRole","ClusterRoleBinding"}:meta["namespace"]=namespace
    return docs

def scan_extended_iac(text:str,kind:str)->List[Dict[str,Any]]:
    kind=kind.lower();out=[]
    rules={
      "vagrant":[("VAGRANT-001",r'config\.ssh\.password\s*=',"high","Senha SSH configurada"),("VAGRANT-002",r'synced_folder.*mount_options.*(?:777|dmode=777)',"high","Diretório compartilhado world-writable")],
      "packer":[("PACKER-001",r'"ssh_password"\s*:',"high","Senha SSH no template"),("PACKER-002",r'"skip_create_ami"\s*:\s*false(?![\s\S]{0,200}encrypt_boot)',"medium","Imagem sem criptografia explícita")],
      "rego":[("REGO-001",r'default\s+allow\s*:?=\s*true',"critical","Política permite por padrão"),("REGO-002",r'allow\s*\{[^}]*input\.[^}]*\}',"low","Regra allow sem deny explícito")],
      "falco":[("FALCO-001",r'condition:\s*always_true',"critical","Regra Falco sempre verdadeira"),("FALCO-002",r'priority:\s*(?:debug|informational)',"low","Prioridade baixa para regra de runtime")],
      "cloud-init":[("CLOUDINIT-001",r'(?:passwd|password):\s*[^\s*$]','critical',"Senha em claro"),("CLOUDINIT-002",r'ssh_pwauth:\s*true',"high","Autenticação SSH por senha habilitada")],
      "crossplane":[("CROSSPLANE-001",r'providerConfigRef:\s*\{\s*\}',"medium","ProviderConfig não fixado"),("CROSSPLANE-002",r'deletionPolicy:\s*Delete',"medium","Exclusão propaga para recurso cloud")],
      "kyverno":[("KYVERNO-001",r'validationFailureAction:\s*Audit',"medium","Política apenas audita"),("KYVERNO-002",r'background:\s*false',"low","Verificação de recursos existentes desativada")],
    }
    for rid,pattern,severity,message in rules.get(kind,[]):
        for m in re.finditer(pattern,text,re.I|re.S):out.append({"rule_id":rid,"severity":severity,"message":message,"offset":m.start(),"kind":kind})
    return out
