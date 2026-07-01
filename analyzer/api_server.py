"""API REST + GraphQL leve e daemon de jobs usando apenas stdlib."""
from __future__ import annotations
import json,threading,uuid
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from typing import Any,Callable,Dict

class ScanService:
    def __init__(self,scanner:Callable[[str],Any]):self.scanner=scanner;self.jobs:Dict[str,Dict[str,Any]]={}
    def submit(self,path:str)->str:
        job=str(uuid.uuid4());self.jobs[job]={"id":job,"status":"queued","path":path}
        threading.Thread(target=self._run,args=(job,),daemon=True).start();return job
    def _run(self,job:str)->None:
        self.jobs[job]["status"]="running"
        try:self.jobs[job].update(status="completed",result=self.scanner(self.jobs[job]["path"]))
        except Exception as e:self.jobs[job].update(status="failed",error=str(e))

def make_handler(service:ScanService,token:str=""):
 class Handler(BaseHTTPRequestHandler):
    def _json(self,status:int,data:Any):
        raw=json.dumps(data,default=str).encode();self.send_response(status);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw)
    def _auth(self)->bool:return not token or self.headers.get("Authorization")==f"Bearer {token}"
    def do_GET(self):
        if not self._auth():return self._json(401,{"error":"unauthorized"})
        if self.path=="/health":return self._json(200,{"status":"ok"})
        if self.path=="/api/v1/jobs":return self._json(200,list(service.jobs.values()))
        if self.path.startswith("/api/v1/jobs/"):return self._json(200,service.jobs.get(self.path.rsplit("/",1)[-1],{"error":"not_found"}))
        return self._json(404,{"error":"not_found"})
    def do_POST(self):
        if not self._auth():return self._json(401,{"error":"unauthorized"})
        length=int(self.headers.get("Content-Length","0"));body=json.loads(self.rfile.read(length) or b"{}")
        if self.path=="/api/v1/scans":return self._json(202,{"job_id":service.submit(body["path"])})
        if self.path=="/graphql":
            query=body.get("query","")
            if "jobs" in query:return self._json(200,{"data":{"jobs":list(service.jobs.values())}})
            if "scan" in query:return self._json(200,{"data":{"scan":{"job_id":service.submit(body.get("variables",{}).get("path","."))}}})
            return self._json(400,{"errors":[{"message":"Campo GraphQL desconhecido"}]})
        return self._json(404,{"error":"not_found"})
    def log_message(self,format,*args):return
 return Handler

def serve(service:ScanService,host:str="127.0.0.1",port:int=8765,token:str="")->None:
    ThreadingHTTPServer((host,port),make_handler(service,token)).serve_forever()
