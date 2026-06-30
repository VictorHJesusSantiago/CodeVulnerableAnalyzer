"""Shannon entropy detector — encontra API keys, tokens e hashes em código-fonte."""
from __future__ import annotations
import re
import math
from dataclasses import dataclass
from typing import List


@dataclass
class EntropyFinding:
    file_path: str
    line_number: int
    line_content: str
    variable_name: str
    secret_value: str
    entropy: float
    charset: str


_ASSIGN_RE = re.compile(
    r'(?:const|let|var|final|private|public|static|readonly|protected)?\s*'
    r'(\w+)\s*(?:=|:=|:)\s*["\']([^"\']{16,})["\']',
    re.IGNORECASE,
)

_SECRET_HINTS = frozenset([
    "key", "token", "secret", "password", "passwd", "pwd", "auth",
    "api", "jwt", "bearer", "credential", "cred", "cert", "private",
    "access", "refresh", "signing", "encryption", "hmac", "salt",
    "nonce", "seed", "hash", "signature", "passphrase",
])


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _has_secret_hint(name: str) -> bool:
    nl = name.lower()
    return any(hint in nl for hint in _SECRET_HINTS)


def _classify(value: str) -> tuple[str, float]:
    """Return (charset_name, entropy_threshold) for the given value."""
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        return "hex", 3.5
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", value) and len(value) >= 20:
        return "base64", 4.5
    return "alnum", 4.0


def scan_entropy(file_path: str, content: str, threshold: float = 4.0) -> List[EntropyFinding]:
    """Scan a file for high-entropy string assignments (possíveis segredos)."""
    findings: List[EntropyFinding] = []
    seen: set[tuple] = set()
    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "--", "'", "*")):
            continue

        for m in _ASSIGN_RE.finditer(line):
            var_name = m.group(1)
            value = m.group(2)
            if len(value) < 16:
                continue

            entropy = _shannon(value)
            charset, ent_threshold = _classify(value)

            is_high_entropy = entropy >= ent_threshold
            is_named_secret = entropy >= 3.0 and _has_secret_hint(var_name)

            if not (is_high_entropy or is_named_secret):
                continue

            dedup = (file_path, line_idx, var_name)
            if dedup in seen:
                continue
            seen.add(dedup)

            masked = value[:8] + "..." + value[-4:] if len(value) > 16 else value
            findings.append(EntropyFinding(
                file_path=file_path,
                line_number=line_idx,
                line_content=line.rstrip(),
                variable_name=var_name,
                secret_value=masked,
                entropy=round(entropy, 3),
                charset=charset,
            ))

    return findings
