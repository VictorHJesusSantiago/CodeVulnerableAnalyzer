"""Detecção de código duplicado (copy-paste) — regras DUP-001..005."""
from __future__ import annotations
import re
import hashlib
from dataclasses import dataclass
from typing import List, Dict, Tuple

BLOCK_MIN_LINES  = 5
LINE_MIN_TOKENS  = 3
MAX_SCAN_LINES   = 3000


@dataclass
class DuplicationFinding:
    file_path: str
    line_start: int
    line_end: int
    duplicate_start: int
    duplicate_end: int
    lines_duplicated: int
    similarity: float = 1.0


def _normalize(line: str) -> str:
    line = re.sub(r'"[^"]*"', '"S"', line)
    line = re.sub(r"'[^']*'", "'S'", line)
    line = re.sub(r"\b\d+\b", "N", line)
    return re.sub(r"\s+", " ", line).strip().lower()


def _hash8(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()[:8]


def _meaningful(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped in ("{", "}", "(", ")", "[", "]", "{}", "[]", "()"):
        return False
    if stripped.startswith(("#", "//", "--", "/*", "*", "'")):
        return False
    return len(re.split(r"\s+", stripped)) >= LINE_MIN_TOKENS


def scan_duplication(file_path: str, content: str) -> List[DuplicationFinding]:
    """Detecta blocos de código duplicados dentro de um único arquivo."""
    lines = content.splitlines()
    if len(lines) > MAX_SCAN_LINES:
        lines = lines[:MAX_SCAN_LINES]

    norms  = [_normalize(l) for l in lines]
    hashes = [_hash8(n) for n in norms]
    valid  = [_meaningful(l) for l in lines]

    findings: List[DuplicationFinding] = []
    seen_pairs: set[Tuple[int, int]] = set()
    n = len(lines)

    for i in range(n - BLOCK_MIN_LINES):
        if not valid[i]:
            continue
        block_fp = tuple(hashes[i : i + BLOCK_MIN_LINES])

        for j in range(i + BLOCK_MIN_LINES, n - BLOCK_MIN_LINES + 1):
            if not valid[j]:
                continue
            if tuple(hashes[j : j + BLOCK_MIN_LINES]) != block_fp:
                continue

            pair = (i, j)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)

            # Estender o bloco
            ext = BLOCK_MIN_LINES
            while (i + ext < n and j + ext < n
                   and hashes[i + ext] == hashes[j + ext]):
                ext += 1

            findings.append(DuplicationFinding(
                file_path=file_path,
                line_start=i + 1,
                line_end=i + ext,
                duplicate_start=j + 1,
                duplicate_end=j + ext,
                lines_duplicated=ext,
                similarity=1.0,
            ))

    return findings
