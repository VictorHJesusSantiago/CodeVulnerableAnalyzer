"""Histórico de scans via SQLite + gráfico ASCII de tendência."""
from __future__ import annotations
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from datetime import datetime


DEFAULT_DB = Path.home() / ".vulnscan" / "trend.db"

_SEV_COLORS = {
    "critical": "#ff2244",
    "high":     "#ff6600",
    "medium":   "#ffcc00",
    "low":      "#33aaff",
}


@dataclass
class TrendEntry:
    id: int
    timestamp: float
    target: str
    files_scanned: int
    total_vulns: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    scan_time: float

    @property
    def dt(self) -> str:
        return datetime.fromtimestamp(self.timestamp).strftime("%d/%m %H:%M")


class TrendDB:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.db_path))

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp     REAL    NOT NULL,
                    target        TEXT    NOT NULL,
                    files_scanned INTEGER DEFAULT 0,
                    total_vulns   INTEGER DEFAULT 0,
                    critical      INTEGER DEFAULT 0,
                    high          INTEGER DEFAULT 0,
                    medium        INTEGER DEFAULT 0,
                    low           INTEGER DEFAULT 0,
                    info          INTEGER DEFAULT 0,
                    scan_time     REAL    DEFAULT 0.0
                )
            """)
            conn.commit()

    def record(self, report) -> int:
        """Registra um ScanReport no banco de dados de tendência."""
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO scans (timestamp,target,files_scanned,total_vulns,"
                "critical,high,medium,low,info,scan_time) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (time.time(), report.target, report.files_scanned,
                 report.total_vulnerabilities, report.critical_count,
                 report.high_count, report.medium_count, report.low_count,
                 report.info_count, report.total_time),
            )
            conn.commit()
            return cur.lastrowid

    def history(self, limit: int = 20) -> List[TrendEntry]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id,timestamp,target,files_scanned,total_vulns,"
                "critical,high,medium,low,info,scan_time "
                "FROM scans ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [TrendEntry(*row) for row in rows]

    def delete(self, scan_id: int) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()

    def clear(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM scans")
            conn.commit()


def ascii_trend(entries: List[TrendEntry], width: int = 40, height: int = 8) -> str:
    """Gráfico ASCII de total de vulnerabilidades ao longo do tempo."""
    if not entries:
        return "  (sem histórico de scans)"

    ordered  = list(reversed(entries))
    values   = [e.total_vulns for e in ordered]
    max_val  = max(values) if values else 1
    cols     = min(len(values), width)
    vals     = values[-cols:]
    dates    = [e.dt for e in ordered[-cols:]]

    chart_lines: List[str] = []
    for row in range(height, 0, -1):
        threshold = max_val * row / height
        bar_chars = ""
        for v in vals:
            bar_chars += "█" if v >= threshold else " "
        chart_lines.append(f"{threshold:5.0f}│{bar_chars}")

    chart_lines.append("     └" + "─" * cols)

    # Data labels (apenas início, meio e fim)
    label_line = " " * 6
    if dates:
        label_line += dates[0]
        if len(dates) > 2:
            mid = len(dates) // 2
            pad = mid - len(dates[0])
            if pad > 0:
                label_line += " " * pad + dates[mid]
        end_pad = cols - len(label_line) + 6
        if end_pad > 0 and dates[-1] != dates[0]:
            label_line += " " * max(1, end_pad - len(dates[-1])) + dates[-1]
    chart_lines.append(label_line[:cols + 10])

    return "\n".join(chart_lines)
