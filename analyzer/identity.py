"""Grafo IAM/AD/Azure AD multi-provedor, escalonamento e least privilege."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

@dataclass
class Principal:
    id:str; kind:str; provider:str; attributes:Dict[str,Any]=field(default_factory=dict)
@dataclass
class PrivilegeEdge:
    source:str; target:str; relation:str; permissions:Set[str]=field(default_factory=set); metadata:Dict[str,Any]=field(default_factory=dict)

class IdentityGraph:
    HIGH_RISK={"dcsync","genericall","writeowner","writedacl","addmember","assumerole","impersonate","owner"}
    def __init__(self):
        self.principals:Dict[str,Principal]={};self.edges:List[PrivilegeEdge]=[]
    def add_principal(self,p:Principal)->None:self.principals[p.id]=p
    def add_edge(self,e:PrivilegeEdge)->None:
        if e.source not in self.principals or e.target not in self.principals: raise KeyError("Aresta referencia principal desconhecido")
        self.edges.append(e)
    def paths(self,start:str,goal:str,max_depth:int=8)->List[List[PrivilegeEdge]]:
        result=[]; queue=[(start,[],{start})]
        while queue:
            node,path,seen=queue.pop(0)
            if len(path)>=max_depth:continue
            for e in self.edges:
                if e.source!=node or e.target in seen:continue
                next_path=path+[e]
                if e.target==goal:result.append(next_path)
                else:queue.append((e.target,next_path,seen|{e.target}))
        return result
    def escalation_paths(self,targets:Optional[Set[str]]=None)->List[Dict[str,Any]]:
        targets=targets or {p.id for p in self.principals.values() if p.attributes.get("tier0") or p.kind in {"domain","account-root"}}
        out=[]
        for source in self.principals:
            if source in targets:continue
            for target in targets:
                for path in self.paths(source,target):
                    score=sum(20 if e.relation.lower() in self.HIGH_RISK else 5 for e in path)
                    out.append({"source":source,"target":target,"score":min(100,score),"path":[asdict(e) for e in path]})
        return sorted(out,key=lambda x:x["score"],reverse=True)
    def simulate_removal(self,source:str,target:str,relation:str)->Dict[str,Any]:
        before=len(self.escalation_paths()); kept=[e for e in self.edges if not(e.source==source and e.target==target and e.relation==relation)]
        old=self.edges;self.edges=kept;after=len(self.escalation_paths());self.edges=old
        return {"before":before,"after":after,"paths_removed":before-after,"safe":after<=before}
    def least_privilege(self,usage:Dict[str,Set[str]])->List[Dict[str,Any]]:
        out=[]
        for edge in self.edges:
            unused=edge.permissions-usage.get(edge.source,set())
            if unused:out.append({"principal":edge.source,"target":edge.target,"remove":sorted(unused),"relation":edge.relation})
        return out
    def to_bloodhound(self)->Dict[str,Any]:
        return {"nodes":[{"id":p.id,"type":p.kind,"provider":p.provider,**p.attributes} for p in self.principals.values()],
                "edges":[{"source":e.source,"target":e.target,"label":e.relation,"permissions":sorted(e.permissions)} for e in self.edges]}

def detect_identity_risks(snapshot:Dict[str,Any])->List[Dict[str,Any]]:
    out=[]
    def hit(rule,severity,principal,message):out.append({"rule_id":rule,"severity":severity,"principal":principal,"message":message})
    for user in snapshot.get("users",[]):
        uid=user.get("id",user.get("name","unknown"))
        if not user.get("mfa",False):hit("IAM-MFA-001","high",uid,"MFA ausente")
        if user.get("preauth_disabled"):hit("AD-KERBEROAST-001","high",uid,"Pré-autenticação Kerberos desabilitada")
        if user.get("admin") and user.get("synced"):hit("IAM-SHADOW-001","critical",uid,"Administrador indireto/sincronizado")
    for sp in snapshot.get("service_principals",[]):
        sid=sp.get("id","unknown")
        if sp.get("secrets"):hit("AAD-SP-SECRET-001","high",sid,"Service principal usa segredo estático")
        if "*" in sp.get("permissions",[]):hit("IAM-WILDCARD-001","critical",sid,"Permissão global")
    ca=snapshot.get("conditional_access",[])
    if ca and not any(p.get("state")=="enabled" and p.get("require_mfa") and p.get("covers_all_users") for p in ca):
        hit("AAD-CA-001","critical","tenant","Conditional Access não exige MFA para todos")
    for grant in snapshot.get("grants",[]):
        perms={x.lower() for x in grant.get("permissions",[])}
        if {"replicating directory changes","replicating directory changes all"}<=perms:
            hit("AD-DCSYNC-001","critical",grant.get("principal","unknown"),"Direitos DCSync concedidos")
    return out

def import_aws_iam(doc:Dict[str,Any])->IdentityGraph:
    g=IdentityGraph()
    for p in doc.get("principals",[]):g.add_principal(Principal(p["arn"],p.get("type","principal"),"aws",p))
    for r in doc.get("roles",[]):
        if r["arn"] not in g.principals:g.add_principal(Principal(r["arn"],"role","aws",r))
        for src in r.get("trusted",[]):
            if src not in g.principals:g.add_principal(Principal(src,"external","aws"))
            g.add_edge(PrivilegeEdge(src,r["arn"],"AssumeRole",set(r.get("actions",[]))))
    return g

def import_directory(doc:Dict[str,Any],provider:str)->IdentityGraph:
    """Normalizador para AD, Azure AD, Okta, Google Workspace e GCP IAM."""
    g=IdentityGraph()
    for item in doc.get("principals",[]):g.add_principal(Principal(item["id"],item.get("kind","user"),provider,item.get("attributes",{})))
    for item in doc.get("relationships",[]):g.add_edge(PrivilegeEdge(item["source"],item["target"],item["relation"],set(item.get("permissions",[])),item.get("metadata",{})))
    return g
