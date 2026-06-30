"""PII detector — CPF, CNPJ, cartão de crédito, e-mail, telefone BR em código-fonte."""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List


@dataclass
class PIIFinding:
    file_path: str
    line_number: int
    line_content: str
    pii_type: str
    masked_value: str


_CPF_RE   = re.compile(r'\b(\d{3})[.\s]?(\d{3})[.\s]?(\d{3})[-\s]?(\d{2})\b')
_CNPJ_RE  = re.compile(r'\b(\d{2})[.\s]?(\d{3})[.\s]?(\d{3})[/\s]?(\d{4})[-\s]?(\d{2})\b')
_CARD_RE  = re.compile(r'\b([3-6]\d{3})[\s\-]?(\d{4})[\s\-]?(\d{4})[\s\-]?(\d{4,7})\b')
_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z]{2,}\b', re.IGNORECASE)
_PHONE_RE = re.compile(r'\(?\b(\d{2})\)?[\s.\-]?([9]?\d{4})[\s.\-]?(\d{4})\b')

_SKIP_EMAILS = ("@example.", "@test.", "@domain.", "@foo.", "@bar.", "@email.")


def _luhn(raw: str) -> bool:
    digits = [int(c) for c in raw if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        total += d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2)
    return total % 10 == 0


def _cpf_valid(d1: str, d2: str, d3: str, d4: str) -> bool:
    digits = [int(x) for x in (d1 + d2 + d3)]
    check = [int(x) for x in d4]
    if len(digits) != 9 or len(check) != 2:
        return False
    if len(set(digits)) == 1:
        return False
    s = sum(v * (10 - i) for i, v in enumerate(digits))
    r1 = (s * 10) % 11
    r1 = 0 if r1 >= 10 else r1
    s = sum(v * (11 - i) for i, v in enumerate(digits + [r1]))
    r2 = (s * 10) % 11
    r2 = 0 if r2 >= 10 else r2
    return r1 == check[0] and r2 == check[1]


def _cnpj_valid(p1: str, p2: str, p3: str, p4: str, p5: str) -> bool:
    digits = [int(x) for x in (p1 + p2 + p3 + p4)]
    check = [int(x) for x in p5]
    if len(digits) != 12 or len(check) != 2:
        return False
    weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    s = sum(d * w for d, w in zip(digits, weights1))
    r1 = 0 if (s % 11) < 2 else 11 - (s % 11)
    weights2 = [6] + weights1
    s = sum(d * w for d, w in zip(digits + [r1], weights2))
    r2 = 0 if (s % 11) < 2 else 11 - (s % 11)
    return r1 == check[0] and r2 == check[1]


def _mask(s: str, show_first: int = 4, show_last: int = 4) -> str:
    raw = re.sub(r"\D", "", s)
    if len(raw) <= show_first + show_last:
        return "*" * len(raw)
    return raw[:show_first] + "*" * (len(raw) - show_first - show_last) + raw[-show_last:]


def scan_pii(file_path: str, content: str) -> List[PIIFinding]:
    """Detecta PII em código-fonte: CPF, CNPJ, cartão, e-mail e telefone BR."""
    findings: List[PIIFinding] = []
    seen: set[tuple] = set()
    lines = content.splitlines()

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "--", "*", "'")):
            continue

        def _add(pii_type: str, masked: str) -> None:
            key = (file_path, line_no, pii_type, masked)
            if key not in seen:
                seen.add(key)
                findings.append(PIIFinding(
                    file_path=file_path,
                    line_number=line_no,
                    line_content=line.rstrip(),
                    pii_type=pii_type,
                    masked_value=masked,
                ))

        for m in _CPF_RE.finditer(line):
            if _cpf_valid(*m.groups()):
                _add("CPF", _mask(m.group(0)))

        for m in _CNPJ_RE.finditer(line):
            if _cnpj_valid(*m.groups()):
                _add("CNPJ", _mask(m.group(0)))

        for m in _CARD_RE.finditer(line):
            raw = re.sub(r"\D", "", m.group(0))
            if _luhn(raw):
                _add("CartaoCredito", _mask(raw))

        if re.search(r'(?:print|log|insert|update|values|=|:)\s', line, re.IGNORECASE):
            for m in _EMAIL_RE.finditer(line):
                email = m.group(0)
                if any(skip in email.lower() for skip in _SKIP_EMAILS):
                    continue
                local, domain = email.rsplit("@", 1)
                masked = local[:2] + "*" * max(0, len(local) - 2) + "@" + domain
                _add("Email", masked)

        for m in _PHONE_RE.finditer(line):
            ddd, num1, num2 = m.groups()
            _add("TelefoneBR", f"({ddd}) ****-{num2}")

    return findings
