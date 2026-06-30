"""Parser de git diff — escaneia apenas linhas modificadas."""
from __future__ import annotations
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Set, List, Optional


@dataclass
class DiffChunk:
    file_path: str
    added_lines: Set[int] = field(default_factory=set)
    removed_lines: Set[int] = field(default_factory=set)


def parse_unified_diff(diff_text: str) -> Dict[str, DiffChunk]:
    """Parse saída de unified diff e retorna {file_path: DiffChunk}."""
    chunks: Dict[str, DiffChunk] = {}
    current_file: Optional[str] = None
    current_line: int = 0

    for line in diff_text.splitlines():
        # Cabeçalho de novo arquivo: +++ b/caminho
        m = re.match(r"^\+\+\+ b/(.+)$", line)
        if m:
            current_file = m.group(1)
            if current_file not in chunks:
                chunks[current_file] = DiffChunk(file_path=current_file)
            continue

        # Hunk header: @@ -old +new @@
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if m:
            current_line = int(m.group(1))
            continue

        if current_file is None:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            chunks[current_file].added_lines.add(current_line)
            current_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            chunks[current_file].removed_lines.add(current_line)
        else:
            current_line += 1

    return chunks


def get_git_diff(base_ref: str = "HEAD", cwd: Optional[str] = None) -> str:
    """Executa git diff e retorna o output unified diff."""
    try:
        result = subprocess.run(
            ["git", "diff", base_ref],
            capture_output=True, text=True,
            cwd=cwd or ".", timeout=30,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def get_staged_diff(cwd: Optional[str] = None) -> str:
    """Executa git diff --staged e retorna o output unified diff."""
    try:
        result = subprocess.run(
            ["git", "diff", "--staged"],
            capture_output=True, text=True,
            cwd=cwd or ".", timeout=30,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def diff_only_lines(file_path: str, diff_chunks: Dict[str, DiffChunk]) -> Optional[Set[int]]:
    """Retorna o conjunto de linhas adicionadas para um arquivo, ou None se não está no diff."""
    vpath = Path(file_path)
    for chunk_path, chunk in diff_chunks.items():
        if str(vpath).endswith(chunk_path) or vpath.name == Path(chunk_path).name:
            return chunk.added_lines
    return None


def filter_vulns_to_diff(vulns: list, diff_chunks: Dict[str, DiffChunk]) -> list:
    """Filtra vulnerabilidades para incluir apenas achados em linhas adicionadas no diff."""
    filtered = []
    for v in vulns:
        restricted = diff_only_lines(v.file_path, diff_chunks)
        if restricted is not None and v.line_number in restricted:
            filtered.append(v)
        elif restricted is None:
            filtered.append(v)
    return filtered
