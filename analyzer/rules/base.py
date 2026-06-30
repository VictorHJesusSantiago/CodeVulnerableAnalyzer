from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional
from analyzer.models import Severity, Confidence, Language, VulnCategory


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: Severity
    category: VulnCategory
    language: Language
    pattern: str
    remediation: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    confidence: Confidence = Confidence.MEDIUM
    flags: int = 0
    negative_pattern: Optional[str] = None
    multiline: bool = False
    depends_on: Optional[str] = None

    _compiled: Optional[re.Pattern] = field(default=None, init=False, repr=False)
    _neg_compiled: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def _ensure_compiled(self) -> None:
        if self._compiled is None:
            ml_flags = (re.MULTILINE | re.DOTALL) if self.multiline else 0
            self._compiled = re.compile(self.pattern, self.flags | ml_flags)
        if self.negative_pattern and self._neg_compiled is None:
            self._neg_compiled = re.compile(self.negative_pattern, self.flags)

    def match(self, line: str) -> bool:
        """Match against a single line. Multiline rules always return False here."""
        if self.multiline:
            return False
        self._ensure_compiled()
        if not self._compiled.search(line):
            return False
        if self._neg_compiled and self._neg_compiled.search(line):
            return False
        return True

    def match_content(self, content: str) -> list[re.Match]:
        """Match against full file content for multiline rules."""
        self._ensure_compiled()
        return list(self._compiled.finditer(content))
