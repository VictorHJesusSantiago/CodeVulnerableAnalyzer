"""Detecção de segredos em patches/históricos fornecidos, sem executar VCS."""
from __future__ import annotations
import hashlib,re
from typing import Any,Dict,Iterable,List
from analyzer.secrets_providers import classify_secret

def scan_patch_history(patch_text:str)->List[Dict[str,Any]]:
    commit="unknown";file="unknown";line=0;out=[];seen=set()
    for raw in patch_text.splitlines():
        if raw.startswith("commit "):commit=raw.split(maxsplit=1)[1]
        elif raw.startswith("+++ b/"):file=raw[6:]
        elif raw.startswith("@@"):
            m=re.search(r'\+(\d+)',raw);line=int(m.group(1)) if m else 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            line+=1;content=raw[1:]
            for provider,kind,matched,revoke in classify_secret(content):
                fingerprint=hashlib.sha256(matched.encode()).hexdigest()
                key=(commit,file,line,fingerprint)
                if key not in seen:
                    seen.add(key);out.append({"commit":commit,"file":file,"line":line,"provider":provider,"secret_type":kind,"fingerprint":fingerprint,"revoke_url":revoke})
        elif not raw.startswith("-"):line+=1
    return out
