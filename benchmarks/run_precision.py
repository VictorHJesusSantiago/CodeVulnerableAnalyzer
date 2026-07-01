from __future__ import annotations
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from analyzer.engine import ScanEngine
from analyzer.models import Severity

def evaluate(manifest):
    tp=fp=fn=0;details=[]
    engine=ScanEngine(min_severity=Severity.INFO)
    for case in manifest["cases"]:
        result=engine.scan_file(case["path"]);actual={v.rule_id for v in result.vulnerabilities};expected=set(case.get("expected",[]))
        row={"path":case["path"],"tp":sorted(actual&expected),"fp":sorted(actual-expected),"fn":sorted(expected-actual)}
        tp+=len(row["tp"]);fp+=len(row["fp"]);fn+=len(row["fn"]);details.append(row)
    precision=tp/(tp+fp) if tp+fp else 1;recall=tp/(tp+fn) if tp+fn else 1
    return {"precision":precision,"recall":recall,"f1":2*precision*recall/(precision+recall) if precision+recall else 0,"tp":tp,"fp":fp,"fn":fn,"details":details}
if __name__=="__main__":
    print(json.dumps(evaluate(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))),indent=2))
