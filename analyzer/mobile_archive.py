"""Inspeção estática de APK/IPA e artefatos mobile descompactados."""
from __future__ import annotations
import hashlib,io,re,zipfile,plistlib,subprocess,tempfile
from pathlib import Path
from typing import Any,Dict,List
from analyzer.domain_security import scan_android_manifest,scan_mobile_code

TEXT_EXT={".xml",".plist",".json",".js",".java",".kt",".swift",".m",".properties",".txt"}
def scan_mobile_archive(path:str|Path,max_entry_bytes:int=8*1024*1024)->Dict[str,Any]:
    path=Path(path);kind="apk" if path.suffix.lower()==".apk" else "ipa" if path.suffix.lower()==".ipa" else "archive"
    findings=[];files=[];certificates=[]
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir():continue
            if info.file_size>max_entry_bytes:
                findings.append({"rule_id":"MOBILE-ZIP-001","severity":"medium","file":info.filename,"message":"Entrada excede limite de inspeção"});continue
            normalized=Path(info.filename)
            if normalized.is_absolute() or ".." in normalized.parts:
                findings.append({"rule_id":"MOBILE-ZIP-002","severity":"critical","file":info.filename,"message":"Zip Slip"});continue
            raw=archive.read(info);files.append(info.filename)
            upper=info.filename.upper()
            if upper.startswith("META-INF/") and upper.endswith((".RSA",".DSA",".EC")):
                certificates.append({"file":info.filename,"sha256":hashlib.sha256(raw).hexdigest()})
            suffix=Path(info.filename).suffix.lower()
            if info.filename.endswith("AndroidManifest.xml") and raw.lstrip().startswith(b"<"):
                findings.extend({**x,"file":info.filename} for x in scan_android_manifest(raw.decode("utf-8","replace")))
            if info.filename.endswith("Info.plist"):
                try:
                    plist=plistlib.loads(raw)
                    ats=plist.get("NSAppTransportSecurity",{})
                    if ats.get("NSAllowsArbitraryLoads"):
                        findings.append({"rule_id":"MOBILE-IOS-ATS-001","severity":"high","file":info.filename,"message":"ATS permite cargas arbitrárias"})
                    schemes=plist.get("CFBundleURLTypes",[])
                    if schemes and not plist.get("CFBundleURLName"):
                        findings.append({"rule_id":"MOBILE-IOS-LINK-001","severity":"medium","file":info.filename,"message":"URL scheme deve validar origem"})
                except (plistlib.InvalidFileException,ValueError):pass
            if suffix in TEXT_EXT:
                text=raw.decode("utf-8","replace")
                findings.extend({**x,"file":info.filename} for x in scan_mobile_code(text))
                for rid,pattern,sev,msg in [
                    ("MOBILE-SECRET-001",r'(?:api[_-]?key|secret|token)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}',"critical","Segredo no pacote"),
                    ("MOBILE-DEEPLINK-001",r'(?:scheme|CFBundleURLSchemes).{0,80}(?:http|custom)',"medium","Deep link deve validar origem e parâmetros"),
                ]:
                    if re.search(pattern,text,re.I|re.S):findings.append({"rule_id":rid,"severity":sev,"file":info.filename,"message":msg})
    if kind=="apk" and not certificates:findings.append({"rule_id":"MOBILE-SIGN-001","severity":"high","file":str(path),"message":"Assinatura v1 não encontrada; valide esquemas v2/v3 externamente"})
    return {"type":kind,"file_count":len(files),"certificates":certificates,"findings":findings}

def decompile_apk(path:str|Path,output_dir:str|Path,apktool_binary:str="apktool",timeout:int=120)->Path:
    """Descompila resources/manifest com apktool oficial, sem executar shell."""
    output=Path(output_dir);output.parent.mkdir(parents=True,exist_ok=True)
    try:result=subprocess.run([apktool_binary,"decode","--force","--output",str(output),str(path)],capture_output=True,text=True,timeout=timeout,check=False)
    except FileNotFoundError as exc:raise RuntimeError("apktool não encontrado") from exc
    except subprocess.TimeoutExpired as exc:raise RuntimeError("apktool excedeu o timeout") from exc
    if result.returncode:raise RuntimeError(result.stderr.strip() or "Falha no apktool")
    return output

def scan_decompiled_mobile(root:str|Path)->Dict[str,Any]:
    root=Path(root);findings=[];count=0
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_EXT:continue
        count+=1;text=path.read_text(encoding="utf-8",errors="replace")
        if path.name=="AndroidManifest.xml":findings.extend({**x,"file":str(path)} for x in scan_android_manifest(text))
        findings.extend({**x,"file":str(path)} for x in scan_mobile_code(text))
    return {"type":"decompiled","file_count":count,"findings":findings}
