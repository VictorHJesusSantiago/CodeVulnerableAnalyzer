"""Webhooks, notificações, checks, filas e quality gates."""
from __future__ import annotations
import hashlib,hmac,json,smtplib,urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any,Callable,Dict,Iterable,List,Protocol

def signed_webhook(url:str,event:Dict[str,Any],secret:str,timeout:int=10)->int:
    body=json.dumps(event,separators=(",",":"),ensure_ascii=False).encode()
    sig=hmac.new(secret.encode(),body,hashlib.sha256).hexdigest()
    req=urllib.request.Request(url,body,{"Content-Type":"application/json","X-VulnScan-Signature":"sha256="+sig})
    with urllib.request.urlopen(req,timeout=timeout) as response:return response.status
def verify_webhook(body:bytes,signature:str,secret:str)->bool:
    expected="sha256="+hmac.new(secret.encode(),body,hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected,signature)

def slack_payload(summary:str,url:str="")->Dict[str,Any]:
    return {"text":summary,"blocks":[{"type":"section","text":{"type":"mrkdwn","text":summary}},{"type":"actions","elements":[{"type":"button","text":{"type":"plain_text","text":"Abrir relatório"},"url":url}]}] if url else [{"type":"section","text":{"type":"mrkdwn","text":summary}}]}
def teams_payload(summary:str,url:str="")->Dict[str,Any]:
    return {"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{"type":"AdaptiveCard","version":"1.4","body":[{"type":"TextBlock","text":summary,"wrap":True}],"actions":[{"type":"Action.OpenUrl","title":"Abrir relatório","url":url}] if url else []}}]}
def discord_payload(summary:str,url:str="")->Dict[str,Any]:return {"content":summary,"embeds":[{"title":"VulnScan","url":url,"description":summary}]}
def send_email(host:str,port:int,sender:str,to:str,subject:str,body:str,username:str="",password:str="",tls:bool=True)->None:
    msg=EmailMessage();msg["From"]=sender;msg["To"]=to;msg["Subject"]=subject;msg.set_content(body)
    with smtplib.SMTP(host,port) as smtp:
        if tls:smtp.starttls()
        if username:smtp.login(username,password)
        smtp.send_message(msg)

class Queue(Protocol):
    def publish(self,topic:str,payload:Dict[str,Any])->None:...
    def consume(self,topic:str,handler:Callable[[Dict[str,Any]],None])->None:...
class MemoryQueue:
    def __init__(self):self.messages:Dict[str,List[Dict[str,Any]]]={}
    def publish(self,topic:str,payload:Dict[str,Any])->None:self.messages.setdefault(topic,[]).append(payload)
    def consume(self,topic:str,handler:Callable[[Dict[str,Any]],None])->None:
        while self.messages.get(topic):handler(self.messages[topic].pop(0))
class AdapterQueue:
    """Adaptador para produtores/consumidores Kafka ou RabbitMQ injetados."""
    def __init__(self,producer:Callable[[str,bytes],None],consumer:Callable[[str],Iterable[bytes]]):self.producer,self.consumer=producer,consumer
    def publish(self,topic:str,payload:Dict[str,Any])->None:self.producer(topic,json.dumps(payload).encode())
    def consume(self,topic:str,handler:Callable[[Dict[str,Any]],None])->None:
        for raw in self.consumer(topic):handler(json.loads(raw))

@dataclass
class QualityGate:
    max_critical:int=0;max_high:int=0;max_total:int=999999;allow_new:bool=False;min_score:float=0
    def evaluate(self,findings:Iterable[Dict[str,Any]],new_count:int=0,score:float=100)->Dict[str,Any]:
        rows=list(findings);counts={}
        for f in rows:
            key=str(f.get("severity","info")).lower();counts[key]=counts.get(key,0)+1
        failures=[]
        if counts.get("critical",0)>self.max_critical:failures.append("critical")
        if counts.get("high",0)>self.max_high:failures.append("high")
        if len(rows)>self.max_total:failures.append("total")
        if not self.allow_new and new_count:failures.append("new_findings")
        if score<self.min_score:failures.append("score")
        return {"passed":not failures,"failures":failures,"counts":counts,"score":score}

def scm_check(provider:str,sha:str,gate:Dict[str,Any],details_url:str="")->Dict[str,Any]:
    state="success" if gate["passed"] else "failure"
    if provider=="github":return {"name":"VulnScan","head_sha":sha,"status":"completed","conclusion":state,"details_url":details_url}
    if provider=="gitlab":return {"sha":sha,"state":state,"name":"VulnScan","target_url":details_url}
    if provider=="bitbucket":return {"key":"VULNSCAN","state":"SUCCESSFUL" if gate["passed"] else "FAILED","url":details_url}
    return {"name":"VulnScan","state":"succeeded" if gate["passed"] else "failed","sha":sha,"url":details_url}

def inline_comments(findings:Iterable[Dict[str,Any]])->List[Dict[str,Any]]:
    return [{"path":f.get("file_path",""),"line":f.get("line_number",1),"body":f'**{f.get("rule_id","VulnScan")}**: {f.get("description",f.get("message",""))}'} for f in findings]
