"""Triagem aprendida, explicações, síntese de regras, anomalias e priorização contextual."""
from __future__ import annotations
import hashlib,math,re
from collections import Counter
from dataclasses import dataclass,field
from typing import Any,Dict,Iterable,List,Sequence,Tuple

FEATURES=("confidence","severity","reachable","test_file","in_comment","sanitized","exploitability","epss","business")
def feature_vector(f:Dict[str,Any])->List[float]:
    sev={"critical":1,"high":.8,"medium":.5,"low":.2,"info":.05}.get(str(f.get("severity","")).lower(),.3)
    conf={"high":1,"medium":.6,"low":.25}.get(str(f.get("confidence","")).lower(),.5)
    return [conf,sev,float(bool(f.get("reachable"))),float(bool(f.get("test_file"))),float(bool(f.get("in_comment"))),
            float(bool(f.get("sanitized"))),float(f.get("exploitability",.5)),float(f.get("epss",0)),float(f.get("business_criticality",.5))]

@dataclass
class FalsePositiveModel:
    weights:List[float]=field(default_factory=lambda:[0.0]*len(FEATURES));bias:float=0
    def train(self,examples:Sequence[Tuple[Dict[str,Any],bool]],epochs:int=250,rate:float=.15)->None:
        if not examples:raise ValueError("Treino requer exemplos")
        for _ in range(epochs):
            for finding,is_true_positive in examples:
                x=feature_vector(finding);pred=self.predict_proba(finding);err=(1.0 if is_true_positive else 0.0)-pred
                self.bias+=rate*err
                for i,v in enumerate(x):self.weights[i]+=rate*err*v
    def predict_proba(self,finding:Dict[str,Any])->float:
        z=self.bias+sum(w*x for w,x in zip(self.weights,feature_vector(finding)));return 1/(1+math.exp(-max(-30,min(30,z))))
    def explain(self,finding:Dict[str,Any])->List[Dict[str,Any]]:
        return sorted(({"feature":name,"contribution":round(w*x,4)} for name,w,x in zip(FEATURES,self.weights,feature_vector(finding))),key=lambda a:abs(a["contribution"]),reverse=True)

def risk_rank(finding:Dict[str,Any],model:FalsePositiveModel|None=None)->Dict[str,Any]:
    severity={"critical":100,"high":75,"medium":45,"low":20,"info":5}.get(str(finding.get("severity","")).lower(),30)
    tp=model.predict_proba(finding) if model else {"high":.95,"medium":.7,"low":.4}.get(str(finding.get("confidence","")).lower(),.65)
    reach=1 if finding.get("reachable",True) else .35; exploit=.4+.6*float(finding.get("exploitability",.5))
    epss=.5+.5*float(finding.get("epss",0));business=.5+float(finding.get("business_criticality",.5))/2
    score=round(min(100,severity*tp*reach*exploit*epss*business),2)
    return {"score":score,"true_positive_probability":round(tp,4),"priority":"P0" if score>=75 else "P1" if score>=50 else "P2" if score>=25 else "P3"}

EXPLANATIONS={
 "CWE-89":"Dados não confiáveis podem alterar a estrutura de uma consulta SQL e acessar ou modificar informações.",
 "CWE-78":"Entrada controlada pode modificar o comando executado pelo sistema operacional.",
 "CWE-79":"Conteúdo não escapado pode executar JavaScript no navegador de outra pessoa.",
 "CWE-798":"Uma credencial embutida no código pode ser recuperada por qualquer pessoa com acesso ao artefato.",
}
def explain_finding(f:Dict[str,Any],education:bool=False)->str:
    base=EXPLANATIONS.get(f.get("cwe"),f.get("description",f.get("message","Risco de segurança detectado.")))
    if education:base+=f" Regra {f.get('rule_id','desconhecida')}; valide o fluxo origem→sink e aplique: {f.get('remediation','controle seguro equivalente')}."
    return base

def synthesize_rule(positives:Sequence[str],negatives:Sequence[str],rule_id:str="CUSTOM-GEN-001")->Dict[str,Any]:
    if not positives:raise ValueError("Forneça exemplos positivos")
    tokens=[set(re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}",x)) for x in positives]
    common=set.intersection(*tokens);negative=set().union(*(set(re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}",x)) for x in negatives)) if negatives else set()
    useful=sorted(common-negative,key=len,reverse=True)
    if not useful:raise ValueError("Exemplos não possuem marcador comum discriminante")
    pattern=r"\b(?:"+ "|".join(re.escape(x) for x in useful[:8]) +r")\b"
    return {"id":rule_id,"name":"Regra gerada por exemplos","pattern":pattern,"negative_pattern":"|".join(re.escape(x) for x in sorted(negative)[:8]) or None,
            "confidence":"LOW","requires_review":True,"example_count":{"positive":len(positives),"negative":len(negatives)}}

def token_fingerprint(code:str,n:int=5)->set[str]:
    tokens=re.findall(r"[A-Za-z_]\w*|\d+|[^\s]",re.sub(r"#.*|//.*","",code))
    return {hashlib.sha1("\x1f".join(tokens[i:i+n]).encode()).hexdigest() for i in range(max(0,len(tokens)-n+1))}
def similarity(a:str,b:str)->float:
    x,y=token_fingerprint(a),token_fingerprint(b);return len(x&y)/len(x|y) if x|y else 1.0
def detect_anomalies(files:Dict[str,str])->List[Dict[str,Any]]:
    metrics={}
    for name,code in files.items():
        lines=code.splitlines() or [""]; metrics[name]=(sum(len(x) for x in lines)/len(lines),len(re.findall(r"\b(?:TODO|FIXME|generated|as an ai)\b",code,re.I)))
    means=[sum(v[i] for v in metrics.values())/max(1,len(metrics)) for i in range(2)]
    return [{"file":n,"score":round(abs(v[0]-means[0])/max(1,means[0])+v[1]*.4,3),"signals":{"avg_line_length":v[0],"generation_markers":v[1]}} for n,v in metrics.items() if abs(v[0]-means[0])/max(1,means[0])+v[1]*.4>.8]
