"""Remediação segura: codemods, patches aplicáveis, quick fixes e provedores de PR/LLM."""
from __future__ import annotations
import ast, difflib, hashlib, json, re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Tuple

@dataclass
class TextEdit:
    start_line:int;end_line:int;replacement:str
@dataclass
class Patch:
    file_path:str;before_sha256:str;edits:List[TextEdit];diff:str="";description:str=""

class Codemod(Protocol):
    def __call__(self,source:str,finding:Dict[str,Any])->List[TextEdit]:...

class RemediationEngine:
    def __init__(self):self.codemods:Dict[str,Codemod]={}
    def register(self,rule_id:str,codemod:Codemod)->None:self.codemods[rule_id]=codemod
    def plan(self,file_path:str,source:str,findings:Iterable[Dict[str,Any]])->Patch:
        edits=[]
        for f in findings:
            transform=self.codemods.get(f.get("rule_id",""))
            if transform:edits.extend(transform(source,f))
        self._validate_edits(edits,len(source.splitlines()))
        updated=apply_edits(source,edits)
        diff="".join(difflib.unified_diff(source.splitlines(True),updated.splitlines(True),f"a/{file_path}",f"b/{file_path}"))
        return Patch(file_path,hashlib.sha256(source.encode()).hexdigest(),edits,diff,f"{len(edits)} correções determinísticas")
    def apply(self,patch:Patch,root:str|Path=".",dry_run:bool=False)->str:
        path=(Path(root)/patch.file_path).resolve();base=Path(root).resolve()
        if base not in path.parents and path!=base:raise ValueError("Patch tenta sair da raiz")
        source=path.read_text(encoding="utf-8")
        if hashlib.sha256(source.encode()).hexdigest()!=patch.before_sha256:raise RuntimeError("Arquivo mudou desde a geração do patch")
        updated=apply_edits(source,patch.edits)
        if not dry_run:path.write_text(updated,encoding="utf-8")
        return updated
    @staticmethod
    def _validate_edits(edits:List[TextEdit],lines:int)->None:
        ordered=sorted(edits,key=lambda e:(e.start_line,e.end_line))
        for i,e in enumerate(ordered):
            if e.start_line<1 or e.end_line<e.start_line or e.end_line>max(1,lines):raise ValueError("Intervalo de edição inválido")
            if i and ordered[i-1].end_line>=e.start_line:raise ValueError("Edições sobrepostas")

def apply_edits(source:str,edits:Iterable[TextEdit])->str:
    lines=source.splitlines(keepends=True)
    for e in sorted(edits,key=lambda x:x.start_line,reverse=True):
        newline="\n" if lines[e.start_line-1:e.end_line] and lines[e.start_line-1:e.end_line][-1].endswith("\n") and not e.replacement.endswith("\n") else ""
        lines[e.start_line-1:e.end_line]=[e.replacement+newline]
    return "".join(lines)

def python_eval_codemod(source:str,finding:Dict[str,Any])->List[TextEdit]:
    n=int(finding["line_number"]);line=source.splitlines()[n-1]
    replacement=re.sub(r"\beval\s*\(", "ast.literal_eval(",line,count=1)
    return [TextEdit(n,n,replacement)] if replacement!=line else []
def python_yaml_load_codemod(source:str,finding:Dict[str,Any])->List[TextEdit]:
    n=int(finding["line_number"]);line=source.splitlines()[n-1]
    replacement=re.sub(r"\byaml\.load\s*\(([^,\n]+)\)",r"yaml.safe_load(\1)",line)
    return [TextEdit(n,n,replacement)] if replacement!=line else []
def javascript_innerhtml_codemod(source:str,finding:Dict[str,Any])->List[TextEdit]:
    n=int(finding["line_number"]);line=source.splitlines()[n-1]
    replacement=line.replace(".innerHTML =",".textContent =")
    return [TextEdit(n,n,replacement)] if replacement!=line else []

def default_engine()->RemediationEngine:
    e=RemediationEngine()
    for rid in ("PY-001","PY-EVAL","TAINT-001"):e.register(rid,python_eval_codemod)
    e.register("PY-YAML-001",python_yaml_load_codemod);e.register("WEB-DOMXSS-001",javascript_innerhtml_codemod)
    return e

class LLMProvider(Protocol):
    def complete(self,prompt:str)->str:...
class AssistedRemediator:
    def __init__(self,provider:LLMProvider):self.provider=provider
    def suggest(self,finding:Dict[str,Any],code:str)->Dict[str,str]:
        prompt=("Você é um remediador de segurança. Não altere comportamento além do necessário. "
                "Retorne JSON com explanation e replacement.\nACHADO="+json.dumps(finding,ensure_ascii=False)+"\nCÓDIGO:\n"+code)
        raw=self.provider.complete(prompt)
        try:data=json.loads(raw)
        except json.JSONDecodeError:return {"explanation":raw,"replacement":""}
        return {"explanation":str(data.get("explanation","")),"replacement":str(data.get("replacement",""))}

def lsp_code_actions(uri:str,source:str,findings:Iterable[Dict[str,Any]],engine:Optional[RemediationEngine]=None)->List[Dict[str,Any]]:
    engine=engine or default_engine();actions=[]
    for f in findings:
        mod=engine.codemods.get(f.get("rule_id",""))
        if not mod:continue
        for edit in mod(source,f):
            actions.append({"title":f"VulnScan: corrigir {f['rule_id']}","kind":"quickfix",
             "diagnostics":[{"code":f["rule_id"]}],"edit":{"changes":{uri:[{"range":{"start":{"line":edit.start_line-1,"character":0},"end":{"line":edit.end_line,"character":0}},"newText":edit.replacement+"\n"}]}}})
    return actions

class PullRequestProvider(Protocol):
    def create(self,title:str,body:str,changes:Dict[str,str])->Dict[str,Any]:...
def create_remediation_pr(provider:PullRequestProvider,patches:Iterable[Patch],contents:Dict[str,str])->Dict[str,Any]:
    patches=list(patches);changes={p.file_path:apply_edits(contents[p.file_path],p.edits) for p in patches}
    body="Correções automáticas revisáveis:\n\n"+"\n".join(f"- {p.file_path}: {p.description}" for p in patches)
    return provider.create("fix(security): remediações automáticas",body,changes)
