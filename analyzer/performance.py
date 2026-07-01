"""Execução paralela/distribuída, cache AST, streaming, automato e limites."""
from __future__ import annotations
import ast,concurrent.futures,hashlib,json,multiprocessing,os,re,sqlite3,time,tracemalloc
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any,Callable,Dict,Iterable,Iterator,List,Optional,Sequence,Tuple

def stream_lines(path:str|Path,chunk_size:int=1024*1024)->Iterator[Tuple[int,str]]:
    with open(path,"r",encoding="utf-8",errors="replace",buffering=chunk_size) as f:
        for number,line in enumerate(f,1):yield number,line

def _call_task(task:Tuple[Callable[[str],Any],str])->Tuple[str,Any]:
    fn,path=task
    try:return path,fn(path)
    except Exception as e:return path,{"error":type(e).__name__+": "+str(e)}
def parallel_map(scanner:Callable[[str],Any],paths:Sequence[str],workers:Optional[int]=None,timeout:float=30)->Dict[str,Any]:
    result={}
    with concurrent.futures.ProcessPoolExecutor(max_workers=workers or max(1,(os.cpu_count() or 2)-1)) as pool:
        futures={pool.submit(_call_task,(scanner,p)):p for p in paths}
        for future,p in futures.items():
            try:_,value=future.result(timeout=timeout);result[p]=value
            except concurrent.futures.TimeoutError:future.cancel();result[p]={"error":"timeout"}
    return result

class ASTCache:
    def __init__(self,path:str):
        self.path=path
        with sqlite3.connect(path) as db:db.execute("CREATE TABLE IF NOT EXISTS ast_cache(hash TEXT PRIMARY KEY,dump TEXT NOT NULL,created REAL NOT NULL)")
    def parse(self,source:str)->ast.AST:
        key=hashlib.sha256(source.encode()).hexdigest()
        with sqlite3.connect(self.path) as db:
            row=db.execute("SELECT dump FROM ast_cache WHERE hash=?",(key,)).fetchone()
            if row:return ast.parse(source)  # parser ainda reconstrói nós; hit evita análises derivadas serializadas
            tree=ast.parse(source);db.execute("INSERT OR REPLACE INTO ast_cache VALUES(?,?,?)",(key,ast.dump(tree,include_attributes=True),time.time()));return tree
    def contains(self,source:str)->bool:
        key=hashlib.sha256(source.encode()).hexdigest()
        with sqlite3.connect(self.path) as db:return db.execute("SELECT 1 FROM ast_cache WHERE hash=?",(key,)).fetchone() is not None

class RuleAutomaton:
    """Agrupa regex compatíveis numa única busca, com fallback isolado por regra."""
    def __init__(self,rules:Sequence[Tuple[str,str,int]]):
        self.rules=rules;self.combined=None;self.fallback=[]
        parts=[]
        for i,(rid,pattern,flags) in enumerate(rules):
            if flags&~re.IGNORECASE:self.fallback.append((rid,re.compile(pattern,flags)));continue
            try:re.compile(pattern,flags);parts.append(f"(?P<R{i}>{pattern})")
            except re.error:self.fallback.append((rid,re.compile(r"(?!x)x")))
        if parts:self.combined=re.compile("|".join(parts),re.IGNORECASE if any(x[2]&re.IGNORECASE for x in rules) else 0)
    def scan(self,text:str)->List[Dict[str,Any]]:
        out=[]
        if self.combined:
            for m in self.combined.finditer(text):
                idx=int(m.lastgroup[1:]);out.append({"rule_id":self.rules[idx][0],"start":m.start(),"end":m.end()})
        for rid,pattern in self.fallback:
            out.extend({"rule_id":rid,"start":m.start(),"end":m.end()} for m in pattern.finditer(text))
        return out

@dataclass
class ResourceLimits:
    timeout_seconds:float=30;max_bytes:int=5*1024*1024;max_findings:int=10000
    def validate_file(self,path:str|Path)->None:
        if Path(path).stat().st_size>self.max_bytes:raise ValueError("Arquivo excede o limite configurado")

@contextmanager
def profile(label:str="scan"):
    tracemalloc.start();start=time.perf_counter();cpu=time.process_time()
    result={}
    try:yield result
    finally:
        current,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
        result.update(label=label,wall_seconds=time.perf_counter()-start,cpu_seconds=time.process_time()-cpu,peak_bytes=peak,current_bytes=current)

class DistributedCoordinator:
    def __init__(self,queue:Any,result_queue:Any):self.queue,self.results=queue,result_queue
    def submit(self,paths:Iterable[str])->List[str]:
        ids=[]
        for path in paths:
            job=hashlib.sha256(f"{path}:{time.time_ns()}".encode()).hexdigest()[:16];self.queue.publish("scan.jobs",{"id":job,"path":path});ids.append(job)
        return ids
class DistributedWorker:
    def __init__(self,queue:Any,scanner:Callable[[str],Any]):self.queue,self.scanner=queue,scanner
    def run_once(self)->None:
        def handle(job):self.queue.publish("scan.results",{"id":job["id"],"result":self.scanner(job["path"])})
        self.queue.consume("scan.jobs",handle)
