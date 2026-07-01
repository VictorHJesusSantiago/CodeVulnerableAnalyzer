"""
Detecção de segredos em histórico git — real, via `git log -p` (subprocess,
stdlib apenas). Diferente da versão anterior (que só analisava um patch já
fornecido pelo usuário), esta varre efetivamente os commits do repositório.

Escopo: opera em modo leitura — nunca escreve, reseta ou modifica o
repositório. Chama apenas `git log -p` (e `git rev-parse` para validar que
o diretório é um repositório). Se o git não estiver instalado ou o
diretório não for um repositório, falha graciosamente (lista vazia +
mensagem de erro), sem lançar exceção para o chamador.
"""
from __future__ import annotations
import hashlib
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from analyzer.secrets_providers import classify_secret


@dataclass
class GitSecretFinding:
    commit: str
    author: str
    date: str
    file: str
    line: int
    provider: str
    secret_type: str
    matched_preview: str
    fingerprint: str
    revoke_url: str


def _git_available() -> bool:
    return shutil.which("git") is not None


def _is_git_repo(directory: str) -> bool:
    try:
        r = subprocess.run(
            ["git", "-C", directory, "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0 and r.stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


def _run_git_log(directory: str, max_commits: Optional[int] = None,
                  since: Optional[str] = None) -> str:
    cmd = ["git", "-C", directory, "log", "-p", "--no-color",
           "--pretty=format:commit %H%nAuthor: %an <%ae>%nDate: %aI"]
    if max_commits:
        cmd += ["-n", str(max_commits)]
    if since:
        cmd += [f"--since={since}"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                             encoding="utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError(f"git log falhou: {result.stderr.strip()[:200]}")
    return result.stdout


def parse_git_log_output(log_text: str) -> List[GitSecretFinding]:
    """Faz o parsing do texto de `git log -p` e roda a classificação de
    segredos sobre cada linha ADICIONADA (+) em cada commit."""
    findings: List[GitSecretFinding] = []
    seen: set = set()

    commit = author = date = current_file = "unknown"
    line_no = 0

    for raw in log_text.splitlines():
        if raw.startswith("commit "):
            commit = raw.split(maxsplit=1)[1] if len(raw.split(maxsplit=1)) > 1 else "unknown"
            author = date = "unknown"
            continue
        if raw.startswith("Author: "):
            author = raw[len("Author: "):]
            continue
        if raw.startswith("Date: "):
            date = raw[len("Date: "):]
            continue
        if raw.startswith("+++ b/"):
            current_file = raw[len("+++ b/"):]
            continue
        if raw.startswith("@@"):
            m = re.search(r'\+(\d+)', raw)
            line_no = int(m.group(1)) if m else 0
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            content = raw[1:]
            for provider, secret_type, matched, revoke_url in classify_secret(content):
                fp = hashlib.sha256(f"{commit}:{current_file}:{matched}".encode()).hexdigest()
                key = (commit, current_file, matched)
                if key in seen:
                    line_no += 1
                    continue
                seen.add(key)
                findings.append(GitSecretFinding(
                    commit=commit[:12], author=author, date=date,
                    file=current_file, line=line_no, provider=provider,
                    secret_type=secret_type, matched_preview=matched[:40],
                    fingerprint=fp, revoke_url=revoke_url,
                ))
            line_no += 1
        elif not raw.startswith("-"):
            line_no += 1

    return findings


def scan_git_history(directory: str, max_commits: Optional[int] = None,
                      since: Optional[str] = None) -> Dict[str, Any]:
    """Varre o histórico git de `directory` procurando segredos introduzidos
    em qualquer commit (não apenas no working tree atual).

    Retorna {"ok": bool, "error": str|None, "findings": [...], "commits_scanned": int}.
    """
    if not _git_available():
        return {"ok": False, "error": "git não está instalado ou não está no PATH", "findings": [], "commits_scanned": 0}
    if not _is_git_repo(directory):
        return {"ok": False, "error": f"'{directory}' não é um repositório git", "findings": [], "commits_scanned": 0}

    try:
        log_text = _run_git_log(directory, max_commits=max_commits, since=since)
    except (RuntimeError, subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "error": str(e), "findings": [], "commits_scanned": 0}

    findings = parse_git_log_output(log_text)
    commits_scanned = log_text.count("\ncommit ") + (1 if log_text.startswith("commit ") else 0)

    return {"ok": True, "error": None, "findings": findings, "commits_scanned": commits_scanned}


# ── Compatibilidade retroativa: análise de um patch já fornecido ─────────────

def scan_patch_history(patch_text: str) -> List[Dict[str, Any]]:
    """Mantido por compatibilidade: analisa um texto de patch/diff já obtido
    (não invoca git). Útil quando o chamador já tem o patch em mãos (ex.:
    diff de PR recebido via webhook, sem acesso ao repositório completo)."""
    findings = parse_git_log_output(patch_text)
    return [
        {
            "commit": f.commit, "file": f.file, "line": f.line,
            "provider": f.provider, "secret_type": f.secret_type,
            "fingerprint": f.fingerprint, "revoke_url": f.revoke_url,
        }
        for f in findings
    ]
