from analyzer.iac import *
from analyzer.container_security import *
from analyzer.compliance import *
from analyzer.domain_security import *

def test_terraform_graph_drift_and_iam():
    plan={"planned_values":{"root_module":{"resources":[
      {"address":"aws_vpc.main","type":"aws_vpc","values":{"cidr":"10/8"}},
      {"address":"aws_instance.web","type":"aws_instance","depends_on":["aws_vpc.main"],"values":{"size":"small"}}]}}}
    resources=parse_terraform_plan(plan)
    assert ResourceGraph(resources).blast_radius("aws_vpc.main")["score"] == 1
    actual=[Resource("aws_vpc.main","aws_vpc",attributes={"cidr":"192/8"})]
    drift=detect_drift(resources,actual)
    assert drift["drifted"] and drift["missing"] == ["aws_instance.web"]
    assert iam_blast_radius({"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}})["level"] == "critical"

def test_container_scans():
    findings=scan_dockerfile("FROM ubuntu:latest\nCOPY .env /app/.env\nRUN apt-get install curl")
    assert {"DOCKER-BP-001","DOCKER-BP-003","DOCKER-BP-005"} <= {x["rule_id"] for x in findings}
    assert scan_compose({"services":{"web":{"privileged":True}}})[0]["service"] == "web"

def test_compliance_dsl_evidence_and_score():
    finding={"rule_id":"SQL-1","cwe":"CWE-89"}
    assert "A03" in map_finding(finding)["OWASP"]
    report=compliance_report([finding],"PCI-DSS")
    assert report["score"] < 100 and "6.2.4" in report["gaps"]
    assert len(audit_evidence(report)["sha256"]) == 64
    assert PolicyDSL("deny public == true : recurso público").evaluate({"public":True})
    assert maturity_score({"governance":5})["score"] == 1

def test_mobile_web_api_database_chain_ml():
    assert scan_android_manifest('<application android:debuggable="true"/>')
    assert any(x["rule_id"]=="WEB-CORS-001" for x in analyze_http_security(
      {"Access-Control-Allow-Origin":"*","Access-Control-Allow-Credentials":"true"}))
    spec={"openapi":"3.1.0","paths":{"/users/{id}":{"get":{"responses":{"200":{}}}}}}
    assert any(x["rule_id"]=="API-BOLA-001" for x in analyze_api_contract(spec))
    assert len(generate_contract_cases(spec)) == 4
    assert scan_database('cursor.execute(f"SELECT * FROM x WHERE id={x}")')
    assert scan_blockchain("target.call{value: amount}(); balances[msg.sender] = 0;")
    assert scan_ml("model = pickle.load(file)")
    assert generate_mlbom([{"name":"x"}],[{"name":"d","containsPII":True}])["datasets"][0]["containsPII"]
