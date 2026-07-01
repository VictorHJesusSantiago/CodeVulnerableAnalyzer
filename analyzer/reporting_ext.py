"""Relatórios avançados, formatos interoperáveis, integridade, diff e heatmaps."""
from __future__ import annotations
import csv, hashlib, html, io, json, struct, zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

def _jsonable(value:Any)->Any:
    if isinstance(value,dict):return {k:_jsonable(v) for k,v in value.items()}
    if isinstance(value,(list,tuple)):return [_jsonable(v) for v in value]
    if hasattr(value,"name") and hasattr(value,"value"):return value.name.lower()
    if isinstance(value,(str,int,float,bool)) or value is None:return value
    return str(value)

def _findings(report:Any)->List[Dict[str,Any]]:
    if isinstance(report,dict):return _jsonable(list(report.get("findings",report.get("vulnerabilities",[]))))
    out=[]
    for result in getattr(report,"results",[]):
        for v in getattr(result,"vulnerabilities",[]):out.append(_jsonable(v.to_dict() if hasattr(v,"to_dict") else vars(v)))
    return out

def interactive_html(report:Any,title:str="VulnScan Dashboard",language:str="pt-BR")->str:
    data=_findings(report); payload=json.dumps(data,ensure_ascii=False).replace("</","<\\/")
    labels={"pt-BR":("Buscar","Severidade","Achados"),"en":("Search","Severity","Findings")}.get(language,("Buscar","Severidade","Achados"))
    return f"""<!doctype html><html lang="{language}"><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>:root{{--bg:#0b1020;--card:#151d35;--text:#eef2ff;--accent:#65d1ff}}*{{box-sizing:border-box}}body{{font:14px system-ui;background:var(--bg);color:var(--text);margin:0}}header{{padding:24px;background:#101831}}main{{padding:24px}}.toolbar{{display:flex;gap:12px}}input,select{{padding:10px;border-radius:7px;border:1px solid #34405f;background:#111831;color:white}}.chart{{display:flex;gap:6px;align-items:end;height:140px;margin:20px 0}}.bar{{min-width:70px;background:var(--accent);color:#08101f;text-align:center}}article{{background:var(--card);padding:14px;margin:8px 0;border-left:4px solid var(--accent)}}small{{opacity:.7}}</style></head>
<body><header><h1>{html.escape(title)}</h1><div id="summary"></div></header><main><div class="toolbar"><input id="q" placeholder="{labels[0]}"><select id="sev"><option value="">{labels[1]}</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></div><div class="chart" id="chart"></div><section id="list"></section></main>
<script>const DATA={payload};const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c]));function render(){{let q=document.querySelector('#q').value.toLowerCase(),s=document.querySelector('#sev').value;let rows=DATA.filter(x=>(!s||String(x.severity).toLowerCase().includes(s))&&JSON.stringify(x).toLowerCase().includes(q));document.querySelector('#summary').textContent=rows.length+' {labels[2]}';let count={{}};DATA.forEach(x=>{{let s=String(x.severity||'info').toLowerCase();count[s]=(count[s]||0)+1}});document.querySelector('#chart').innerHTML=Object.entries(count).map(([k,v])=>`<div class="bar" style="height:${{30+v*12}}px">${{esc(k)}}<br>${{v}}</div>`).join('');document.querySelector('#list').innerHTML=rows.map(x=>`<article><b>${{esc(x.rule_id||x.name)}}</b> — ${{esc(x.message||x.description)}}<br><small>${{esc(x.file_path||x.file)}}:${{esc(x.line_number||x.line||'')}}</small></article>`).join('')}}q.oninput=sev.onchange=render;render()</script></body></html>"""

def advanced_sarif(report:Any)->Dict[str,Any]:
    findings=_findings(report); rules={};results=[]
    for f in findings:
        rid=f.get("rule_id","UNKNOWN");rules[rid]={"id":rid,"name":f.get("name",rid),"shortDescription":{"text":f.get("description",f.get("message",rid))}}
        loc={"physicalLocation":{"artifactLocation":{"uri":f.get("file_path",f.get("file",""))},"region":{"startLine":max(1,int(f.get("line_number",f.get("line",1))))}}}
        result={"ruleId":rid,"level":{"critical":"error","high":"error","medium":"warning","low":"note"}.get(str(f.get("severity","")).lower(),"note"),"message":{"text":f.get("description",f.get("message",rid))},"locations":[loc]}
        if f.get("code_flow"):result["codeFlows"]=[{"threadFlows":[{"locations":[{"location":{"message":{"text":x.get("message","flow")},"physicalLocation":{"artifactLocation":{"uri":x.get("file","")},"region":{"startLine":x.get("line",1)}}}} for x in f["code_flow"]]}]}]
        if f.get("fix"):result["fixes"]=[{"description":{"text":"Correção sugerida"},"artifactChanges":[{"artifactLocation":{"uri":f.get("file_path","")},"replacements":[{"deletedRegion":{"startLine":f.get("line_number",1)},"insertedContent":{"text":f["fix"]}}]}]}]
        results.append(result)
    return {"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"CodeVulnerableAnalyzer","rules":list(rules.values())}},"results":results}]}

def gitlab_sast(report:Any)->Dict[str,Any]:
    levels={"critical":"Critical","high":"High","medium":"Medium","low":"Low","info":"Info"}
    vulns=[]
    for i,f in enumerate(_findings(report)):
        digest=hashlib.sha256(json.dumps(f,sort_keys=True,default=str).encode()).hexdigest()
        vulns.append({"id":digest,"category":"sast","name":f.get("name",f.get("rule_id","Finding")),"message":f.get("description",f.get("message","")),
         "description":f.get("description",f.get("message","")),"severity":levels.get(str(f.get("severity","info")).lower(),"Unknown"),
         "confidence":"Medium","scanner":{"id":"cva","name":"CodeVulnerableAnalyzer"},"location":{"file":f.get("file_path",""),"start_line":f.get("line_number",1)},
         "identifiers":[{"type":"cva_rule","name":f.get("rule_id","UNKNOWN"),"value":f.get("rule_id","UNKNOWN")}]})
    return {"version":"15.0.6","vulnerabilities":vulns,"scan":{"analyzer":{"id":"cva","name":"CVA","version":"2"},"scanner":{"id":"cva","name":"CVA","version":"2"},"type":"sast","start_time":datetime.now(timezone.utc).isoformat(),"end_time":datetime.now(timezone.utc).isoformat(),"status":"success"}}

def scan_diff(old:Any,new:Any)->Dict[str,List[Dict[str,Any]]]:
    def key(f):return (f.get("rule_id"),f.get("file_path",f.get("file")),f.get("line_number",f.get("line")))
    a={key(f):f for f in _findings(old)};b={key(f):f for f in _findings(new)}
    return {"new":[b[k] for k in b.keys()-a.keys()],"fixed":[a[k] for k in a.keys()-b.keys()],"persistent":[b[k] for k in b.keys()&a.keys()]}

def longitudinal(scans:Iterable[Dict[str,Any]])->Dict[str,Any]:
    rows=[]
    for s in scans:
        c=Counter(str(f.get("severity","info")).lower() for f in _findings(s))
        rows.append({"at":s.get("at"),"total":sum(c.values()),**c})
    return {"series":rows,"delta":(rows[-1]["total"]-rows[0]["total"]) if len(rows)>1 else 0}

def heatmap(report:Any,authors:Optional[Dict[str,str]]=None)->List[Dict[str,Any]]:
    grid=defaultdict(Counter)
    for f in _findings(report):
        file=f.get("file_path",f.get("file","unknown"));grid[file][str(f.get("severity","info")).lower()]+=1
    return [{"file":file,"author":(authors or {}).get(file,"unknown"),"risk":c["critical"]*10+c["high"]*5+c["medium"]*2+c["low"],**c} for file,c in sorted(grid.items())]

def sign_report(data:bytes,key:bytes)->Dict[str,str]:
    import hmac
    return {"sha256":hashlib.sha256(data).hexdigest(),"hmac_sha256":hmac.new(key,data,hashlib.sha256).hexdigest()}

def export_docx(report:Any,path:str,title:str="Relatório Técnico de Segurança")->None:
    """DOCX OOXML autocontido, compatível com Word/LibreOffice."""
    rows=_findings(report)
    def p(text,style=None):
        sty=f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
        return f'<w:p>{sty}<w:r><w:t xml:space="preserve">{html.escape(str(text))}</w:t></w:r></w:p>'
    body=p(title,"Title")+p(f"Gerado em {datetime.now(timezone.utc).isoformat()}")+p(f"Total de achados: {len(rows)}","Heading1")
    for f in rows:body+=p(f'{f.get("rule_id","")} — {f.get("severity","")}','Heading2')+p(f.get("description",f.get("message","")))+p(f'{f.get("file_path","")}:{f.get("line_number","")}')
    document=f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{body}<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr></w:body></w:document>'
    types='<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
    rels='<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(path,"w",zipfile.ZIP_DEFLATED) as z:z.writestr("[Content_Types].xml",types);z.writestr("_rels/.rels",rels);z.writestr("word/document.xml",document)

def export_xlsx(report:Any,path:str)->None:
    rows=[["Regra","Severidade","Arquivo","Linha","Descrição"]]+[[f.get("rule_id",""),f.get("severity",""),f.get("file_path",""),f.get("line_number",""),f.get("description",f.get("message",""))] for f in _findings(report)]
    sheet='<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
    for ri,row in enumerate(rows,1):
        sheet+=f'<row r="{ri}">'+''.join(f'<c r="{chr(65+ci)}{ri}" t="inlineStr"><is><t>{html.escape(str(v))}</t></is></c>' for ci,v in enumerate(row))+"</row>"
    sheet+="</sheetData></worksheet>"
    content='<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'
    root='<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
    wb='<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Achados" sheetId="1" r:id="rId1"/></sheets></workbook>'
    wbr='<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(path,"w",zipfile.ZIP_DEFLATED) as z:
        for n,v in [("[Content_Types].xml",content),("_rels/.rels",root),("xl/workbook.xml",wb),("xl/_rels/workbook.xml.rels",wbr),("xl/worksheets/sheet1.xml",sheet)]:z.writestr(n,v)

def export_pdf(report:Any,path:str)->None:
    lines=["Relatorio de Seguranca",f"Total: {len(_findings(report))}"]+[f'{f.get("rule_id","")} [{f.get("severity","")}] {f.get("file_path","")}' for f in _findings(report)]
    stream="BT /F1 10 Tf 50 780 Td "+". ".join(f"({x[:100].replace('(','[').replace(')',']')}) Tj 0 -14 Td" for x in lines[:50])+" ET"
    objs=[b"<< /Type /Catalog /Pages 2 0 R >>",b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream".encode(),b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    buf=io.BytesIO();buf.write(b"%PDF-1.4\n");offset=[0]
    for i,o in enumerate(objs,1):offset.append(buf.tell());buf.write(f"{i} 0 obj\n".encode()+o+b"\nendobj\n")
    x=buf.tell();buf.write(f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode())
    for o in offset[1:]:buf.write(f"{o:010} 00000 n \n".encode())
    target=Path(path);target.parent.mkdir(parents=True,exist_ok=True)
    buf.write(f"trailer << /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF".encode());target.write_bytes(buf.getvalue())

def confluence_storage(report:Any)->str:
    return "<h1>Relatório de Segurança</h1>"+''.join(f'<h2>{html.escape(str(f.get("rule_id","")))}</h2><p>{html.escape(str(f.get("description",f.get("message",""))))}</p>' for f in _findings(report))
def jira_issues(report:Any,project:str)->List[Dict[str,Any]]:
    return [{"fields":{"project":{"key":project},"summary":f'[{f.get("severity","")}] {f.get("rule_id","Achado")}',"description":f.get("description",f.get("message","")),"issuetype":{"name":"Bug"},"labels":["security","vulnscan"]}} for f in _findings(report)]
