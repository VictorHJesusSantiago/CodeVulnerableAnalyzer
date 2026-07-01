"""IR semântica, CFG/SSA, dataflow, interpretação abstrata e execução simbólica."""
from __future__ import annotations
import ast,collections,operator
from dataclasses import dataclass,field
from typing import Any,Dict,Iterable,List,Optional,Set,Tuple

@dataclass
class Instruction:
    op:str;target:Optional[str]=None;args:Tuple[Any,...]=();line:int=0
@dataclass
class BasicBlock:
    id:int;instructions:List[Instruction]=field(default_factory=list);successors:Set[int]=field(default_factory=set)
@dataclass
class ControlFlowGraph:
    blocks:Dict[int,BasicBlock];entry:int=0;exit:int=-1
    def predecessors(self)->Dict[int,Set[int]]:
        out={k:set() for k in self.blocks}
        for src,b in self.blocks.items():
            for dst in b.successors:out.setdefault(dst,set()).add(src)
        return out
    def reachable(self)->Set[int]:
        seen=set();stack=[self.entry]
        while stack:
            n=stack.pop()
            if n in seen or n not in self.blocks:continue
            seen.add(n);stack.extend(self.blocks[n].successors)
        return seen

def cfg_from_python(source:str)->ControlFlowGraph:
    tree=ast.parse(source);blocks={0:BasicBlock(0)};next_id=1
    def emit_stmt(stmt:ast.stmt,current:int)->int:
        nonlocal next_id
        b=blocks[current]
        if isinstance(stmt,(ast.Assign,ast.AnnAssign)):
            target=stmt.targets[0] if isinstance(stmt,ast.Assign) else stmt.target
            name=target.id if isinstance(target,ast.Name) else ast.unparse(target)
            value=stmt.value;b.instructions.append(Instruction("assign",name,(ast.unparse(value),),stmt.lineno));return current
        if isinstance(stmt,ast.Expr):
            b.instructions.append(Instruction("expr",args=(ast.unparse(stmt.value),),line=stmt.lineno));return current
        if isinstance(stmt,(ast.Return,ast.Raise)):
            b.instructions.append(Instruction("return" if isinstance(stmt,ast.Return) else "raise",args=(ast.unparse(stmt.value) if getattr(stmt,"value",None) else "",),line=stmt.lineno));return -1
        if isinstance(stmt,ast.If):
            then_id,else_id,join=next_id,next_id+1,next_id+2;next_id+=3
            blocks[then_id]=BasicBlock(then_id);blocks[else_id]=BasicBlock(else_id);blocks[join]=BasicBlock(join)
            b.instructions.append(Instruction("branch",args=(ast.unparse(stmt.test),),line=stmt.lineno));b.successors|={then_id,else_id}
            ends=[]
            for start,body in ((then_id,stmt.body),(else_id,stmt.orelse)):
                cur=start
                for child in body:
                    if cur!=-1:cur=emit_stmt(child,cur)
                if cur!=-1:blocks[cur].successors.add(join);ends.append(cur)
            return join if ends else -1
        b.instructions.append(Instruction("statement",args=(ast.unparse(stmt),),line=getattr(stmt,"lineno",0)));return current
    current=0
    for stmt in tree.body:
        if current==-1:
            blocks[next_id]=BasicBlock(next_id);current=next_id;next_id+=1
        current=emit_stmt(stmt,current)
    exit_id=next_id;blocks[exit_id]=BasicBlock(exit_id)
    for block in blocks.values():
        if block.id!=exit_id and not block.successors and (not block.instructions or block.instructions[-1].op not in ("return","raise")):block.successors.add(exit_id)
    return ControlFlowGraph(blocks,0,exit_id)

def to_ssa(cfg:ControlFlowGraph)->ControlFlowGraph:
    versions:Dict[str,int]=collections.defaultdict(int);renamed={}
    for bid in sorted(cfg.blocks):
        block=cfg.blocks[bid];new=[]
        for ins in block.instructions:
            args=tuple(_rename_expr(str(x),renamed) for x in ins.args)
            target=ins.target
            if target:
                versions[target]+=1;new_name=f"{target}_{versions[target]}";renamed[target]=new_name;target=new_name
            new.append(Instruction(ins.op,target,args,ins.line))
        block.instructions=new
    return cfg
def _rename_expr(expr:str,names:Dict[str,str])->str:
    for old,new in sorted(names.items(),key=lambda x:len(x[0]),reverse=True):
        import re
        expr=re.sub(r"\b"+re.escape(old)+r"\b",new,expr)
    return expr

def reaching_definitions(cfg:ControlFlowGraph)->Dict[int,Set[Tuple[str,int]]]:
    pred=cfg.predecessors();gen={b:{(i.target,i.line) for i in block.instructions if i.target} for b,block in cfg.blocks.items()}
    incoming={b:set() for b in cfg.blocks};out={b:set(gen[b]) for b in cfg.blocks};changed=True
    while changed:
        changed=False
        for b in cfg.blocks:
            new_in=set().union(*(out[p] for p in pred.get(b,set()))) if pred.get(b) else set()
            targets={x[0] for x in gen[b]};new_out={x for x in new_in if x[0] not in targets}|gen[b]
            if new_in!=incoming[b] or new_out!=out[b]:incoming[b],out[b],changed=new_in,new_out,True
    return incoming

def live_variables(cfg:ControlFlowGraph)->Dict[int,Set[str]]:
    use,defs={},{}
    for b,block in cfg.blocks.items():
        defs[b]={i.target for i in block.instructions if i.target}
        use[b]=set()
        for i in block.instructions:
            for expr in i.args:
                try:use[b]|={n.id for n in ast.walk(ast.parse(str(expr),mode="eval")) if isinstance(n,ast.Name)}
                except SyntaxError:pass
    live={b:set() for b in cfg.blocks};changed=True
    while changed:
        changed=False
        for b in reversed(list(cfg.blocks)):
            new=use[b]|(set().union(*(live[s] for s in cfg.blocks[b].successors))-defs[b] if cfg.blocks[b].successors else set())
            if new!=live[b]:live[b]=new;changed=True
    return live

@dataclass(frozen=True)
class Interval:
    low:float=float("-inf");high:float=float("inf")
    def join(self,other:"Interval")->"Interval":return Interval(min(self.low,other.low),max(self.high,other.high))
    def add(self,other:"Interval")->"Interval":return Interval(self.low+other.low,self.high+other.high)
    def mul(self,other:"Interval")->"Interval":
        vals=(self.low*other.low,self.low*other.high,self.high*other.low,self.high*other.high);return Interval(min(vals),max(vals))

def interpret_intervals(instructions:Iterable[Instruction],initial:Optional[Dict[str,Interval]]=None)->Dict[str,Interval]:
    env=dict(initial or {})
    for ins in instructions:
        if ins.op!="assign" or not ins.target:continue
        try:
            node=ast.parse(str(ins.args[0]),mode="eval").body
            env[ins.target]=_eval_interval(node,env)
        except (SyntaxError,ValueError,TypeError):env[ins.target]=Interval()
    return env
def _eval_interval(node:ast.AST,env:Dict[str,Interval])->Interval:
    if isinstance(node,ast.Constant) and isinstance(node.value,(int,float)):return Interval(node.value,node.value)
    if isinstance(node,ast.Name):return env.get(node.id,Interval())
    if isinstance(node,ast.BinOp):
        a,b=_eval_interval(node.left,env),_eval_interval(node.right,env)
        if isinstance(node.op,ast.Add):return a.add(b)
        if isinstance(node.op,ast.Sub):return a.add(Interval(-b.high,-b.low))
        if isinstance(node.op,ast.Mult):return a.mul(b)
    return Interval()

def memory_lifetime_findings(instructions:Iterable[Instruction])->List[Dict[str,Any]]:
    state={};locks=[];out=[]
    for ins in instructions:
        name=str(ins.args[0]) if ins.args else ins.target or ""
        if ins.op=="alloc":state[ins.target]="allocated"
        elif ins.op=="free":
            if state.get(name)=="freed":out.append({"rule_id":"IR-DOUBLE-FREE","line":ins.line,"variable":name})
            state[name]="freed"
        elif ins.op in ("read","write") and state.get(name)=="freed":out.append({"rule_id":"IR-USE-AFTER-FREE","line":ins.line,"variable":name})
        elif ins.op=="lock":
            if name in locks:out.append({"rule_id":"IR-SELF-DEADLOCK","line":ins.line,"lock":name})
            locks.append(name)
        elif ins.op=="unlock" and name in locks:locks.remove(name)
    for name,status in state.items():
        if status=="allocated":out.append({"rule_id":"IR-MEMORY-LEAK","line":0,"variable":name})
    return out

def symbolic_paths(cfg:ControlFlowGraph,max_paths:int=128)->List[Dict[str,Any]]:
    paths=[];stack=[(cfg.entry,[],[])]
    while stack and len(paths)<max_paths:
        bid,constraints,trace=stack.pop()
        if bid==cfg.exit:paths.append({"constraints":constraints,"blocks":trace+[bid]});continue
        block=cfg.blocks[bid];branch=next((i for i in block.instructions if i.op=="branch"),None)
        successors=sorted(block.successors)
        for index,nxt in enumerate(successors):
            extra=list(constraints)
            if branch:extra.append(("" if index==0 else "not ")+str(branch.args[0]))
            stack.append((nxt,extra,trace+[bid]))
    return paths
