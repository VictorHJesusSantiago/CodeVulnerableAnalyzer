from pathlib import Path
import json,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from analyzer.operations import rule_catalog
from analyzer.rules import get_all_rules
data=json.dumps(rule_catalog(get_all_rules()),ensure_ascii=False,separators=(",",":"))
Path("site/rules.json").write_text(data,encoding="utf-8")
Path("site/catalog-data.js").write_text("window.VULNSCAN_RULES="+data+";",encoding="utf-8")
