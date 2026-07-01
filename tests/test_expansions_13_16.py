from pathlib import Path
import json,re,time
from analyzer.remediation import *
from analyzer.ai_triage import *
from analyzer.performance import *
from analyzer.operations import *
from analyzer.integrations import MemoryQueue

def test_patch_generation_application_and_race(tmp_path):
    source="value = eval(payload)\nprint(value)\n";path=tmp_path/"a.py";path.write_text(source)
    patch=default_engine().plan("a.py",source,[{"rule_id":"PY-001","line_number":1}])
    assert "ast.literal_eval" in patch.diff
    updated=default_engine().apply(patch,tmp_path)
    assert updated.startswith("value = ast.literal_eval")
    try:default_engine().apply(patch,tmp_path)
    except RuntimeError:pass
    else:assert False

def test_lsp_quick_fix_and_llm_provider():
    actions=lsp_code_actions("file:///a.py","x=eval(v)\n",[{"rule_id":"PY-001","line_number":1}])
    assert actions[0]["kind"]=="quickfix"
    class Provider:
        def complete(self,prompt):return json.dumps({"explanation":"risco","replacement":"safe(v)"})
    assert AssistedRemediator(Provider()).suggest({"rule_id":"X"},"bad()")["replacement"]=="safe(v)"

def test_false_positive_training_ranking_and_explanation():
    model=FalsePositiveModel()
    examples=[({"severity":"high","confidence":"high","reachable":True},True),
              ({"severity":"low","confidence":"low","in_comment":True,"test_file":True},False)]
    model.train(examples)
    assert model.predict_proba(examples[0][0])>model.predict_proba(examples[1][0])
    ranked=risk_rank({"severity":"critical","confidence":"high","reachable":True,"exploitability":1,"epss":1,"business_criticality":1},model)
    assert ranked["score"]>50 and model.explain(examples[0][0])
    assert "consulta SQL" in explain_finding({"cwe":"CWE-89"},education=True)

def test_rule_synthesis_similarity_and_anomaly():
    rule=synthesize_rule(["danger.run(user)","danger.run(input)"],["safe.run(user)"])
    assert re.search(rule["pattern"],"danger.run(x)") and rule["requires_review"]
    assert similarity("x = foo(a)\ny=bar(x)","x=foo(a)\ny=bar(x)")>.8
    anomalies=detect_anomalies({"normal.py":"x=1\n","generated.py":"# generated\n# as an ai\n"+"x="+"1"*200})
    assert any(x["file"]=="generated.py" for x in anomalies)

def square_file(path):
    return int(Path(path).read_text())**2

def test_parallel_stream_ast_automaton_profile_and_limits(tmp_path):
    paths=[]
    for i in range(2):
        p=tmp_path/f"{i}.txt";p.write_text(str(i+2));paths.append(str(p))
    assert parallel_map(square_file,paths,workers=2,timeout=10)[paths[0]]==4
    assert list(stream_lines(paths[0]))==[(1,"2")]
    cache=ASTCache(str(tmp_path/"ast.db"));cache.parse("x=1");assert cache.contains("x=1")
    hits=RuleAutomaton([("A",r"eval\(",0),("B",r"password",re.I)]).scan("EVAL(x) password")
    assert {x["rule_id"] for x in hits}=={"A","B"}
    with profile("unit") as stats:sum(range(20))
    assert stats["peak_bytes"]>=0
    ResourceLimits(max_bytes=100).validate_file(paths[0])

def test_distributed_i18n_telemetry_rule_pack(tmp_path):
    q=MemoryQueue();worker=DistributedWorker(q,lambda p:{"path":p});coord=DistributedCoordinator(q,q)
    ids=coord.submit(["a"]);worker.run_once();assert q.messages["scan.results"][0]["id"]==ids[0]
    assert translate("finding.count","pt-BR",count=2)=="2 achados"
    telemetry=Telemetry(False);telemetry.record("scan",{"file_count":1});assert not telemetry.events
    payload=json.dumps({"version":"1.2.0","rules":[]}).encode()
    import hmac,hashlib
    key=b"k";sig=hmac.new(key,payload,hashlib.sha256).hexdigest()
    assert install_rule_pack(payload,sig,key,tmp_path).exists()
