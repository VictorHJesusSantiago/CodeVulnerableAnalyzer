"""
Cache de análise incremental — reaproveita resultados de arquivos cujo
conteúdo (hash SHA-256) não mudou desde o último scan, evitando reprocessar
o conjunto completo de regras. Armazenamento: SQLite (stdlib), mesmo padrão
usado em analyzer/trend.py.
"""
from __future__ import annotations
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import List, Optional, Tuple

from analyzer.models import (
    Language, Severity, Vulnerability, VulnCategory, Confidence
)

DEFAULT_DB = Path.home() / ".vulnscan" / "incremental.db"


def content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def _vuln_to_dict(v: Vulnerability) -> dict:
    return {
        "rule_id": v.rule_id, "name": v.name, "description": v.description,
        "severity": v.severity.name, "category": v.category.name,
        "language": v.language.name, "file_path": v.file_path,
        "line_number": v.line_number, "line_content": v.line_content,
        "remediation": v.remediation, "cwe": v.cwe, "owasp": v.owasp,
        "confidence": v.confidence.name, "snippet": v.snippet,
        "snippet_start_line": v.snippet_start_line, "in_comment": v.in_comment,
        "function_context": v.function_context,
    }


def _dict_to_vuln(d: dict) -> Vulnerability:
    return Vulnerability(
        rule_id=d["rule_id"], name=d["name"], description=d["description"],
        severity=Severity[d["severity"]], category=VulnCategory[d["category"]],
        language=Language[d["language"]], file_path=d["file_path"],
        line_number=d["line_number"], line_content=d["line_content"],
        remediation=d["remediation"], cwe=d.get("cwe"), owasp=d.get("owasp"),
        confidence=Confidence[d["confidence"]], snippet=d.get("snippet", []),
        snippet_start_line=d.get("snippet_start_line", 0),
        in_comment=d.get("in_comment", False),
        function_context=d.get("function_context"),
    )


class IncrementalCache:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        self.hits = 0
        self.misses = 0

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.db_path))

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_cache (
                    file_path   TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    vulns_json  TEXT NOT NULL,
                    lines_scanned INTEGER NOT NULL,
                    scan_time   REAL NOT NULL
                )
            """)
            conn.commit()

    def get(self, file_path: str, content: str) -> Optional[Tuple[List[Vulnerability], int]]:
        """Retorna (vulnerabilidades, lines_scanned) se o hash bater, senão None."""
        h = content_hash(content)
        with self._conn() as conn:
            row = conn.execute(
                "SELECT content_hash, vulns_json, lines_scanned FROM file_cache WHERE file_path = ?",
                (file_path,),
            ).fetchone()
        if row is None or row[0] != h:
            self.misses += 1
            return None
        self.hits += 1
        vulns = [_dict_to_vuln(d) for d in json.loads(row[1])]
        return vulns, row[2]

    def put(self, file_path: str, content: str, vulns: List[Vulnerability],
            lines_scanned: int, scan_time: float) -> None:
        h = content_hash(content)
        payload = json.dumps([_vuln_to_dict(v) for v in vulns])
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO file_cache (file_path, content_hash, vulns_json, lines_scanned, scan_time) "
                "VALUES (?,?,?,?,?) "
                "ON CONFLICT(file_path) DO UPDATE SET content_hash=excluded.content_hash, "
                "vulns_json=excluded.vulns_json, lines_scanned=excluded.lines_scanned, "
                "scan_time=excluded.scan_time",
                (file_path, h, payload, lines_scanned, scan_time),
            )
            conn.commit()

    def clear(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM file_cache")
            conn.commit()

    def stats(self) -> dict:
        return {"hits": self.hits, "misses": self.misses}
