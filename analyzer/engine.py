from __future__ import annotations
import os
import time
from pathlib import Path
from typing import List, Optional, Callable

from analyzer.models import (
    Language, Severity, Vulnerability, ScanResult, ScanReport, Confidence
)
from analyzer.detector import detect_language, is_scannable, get_comment_prefix, SKIP_DIRS
from analyzer.rules import get_rules
from analyzer.complexity import analyze_complexity

CONTEXT_LINES = 3
MAX_FILE_SIZE_MB = 5
MAX_LINE_LENGTH = 2000


class ScanEngine:
    def __init__(
        self,
        min_severity: Severity = Severity.INFO,
        languages: Optional[List[Language]] = None,
        include_comments: bool = True,
        on_file_start: Optional[Callable[[str], None]] = None,
        on_file_done: Optional[Callable[[ScanResult], None]] = None,
    ):
        self.min_severity = min_severity
        self.languages = languages
        self.include_comments = include_comments
        self.on_file_start = on_file_start
        self.on_file_done = on_file_done

    def scan_file(self, file_path: str) -> ScanResult:
        start = time.perf_counter()
        path = Path(file_path)

        if self.on_file_start:
            self.on_file_start(file_path)

        if not path.exists():
            return ScanResult(file_path, Language.UNKNOWN, [], 0, 0.0, "File not found")

        try:
            size_mb = path.stat().st_size / (1024 * 1024)
            if size_mb > MAX_FILE_SIZE_MB:
                return ScanResult(
                    file_path, Language.UNKNOWN, [], 0,
                    time.perf_counter() - start,
                    f"File too large ({size_mb:.1f} MB > {MAX_FILE_SIZE_MB} MB limit)"
                )

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, PermissionError) as e:
                return ScanResult(file_path, Language.UNKNOWN, [], 0, time.perf_counter() - start, str(e))

            language = detect_language(file_path, content)

            if self.languages and language not in self.languages:
                result = ScanResult(file_path, language, [], 0, time.perf_counter() - start)
                if self.on_file_done:
                    self.on_file_done(result)
                return result

            vulnerabilities = self._scan_content(file_path, content, language)
            vulnerabilities += analyze_complexity(file_path, content, language)
            vulnerabilities = [v for v in vulnerabilities if v.severity.value >= self.min_severity.value]

            result = ScanResult(
                file_path=file_path,
                language=language,
                vulnerabilities=sorted(vulnerabilities, key=lambda v: -v.severity.value),
                lines_scanned=len(content.splitlines()),
                scan_time=time.perf_counter() - start,
            )

        except Exception as e:
            result = ScanResult(file_path, Language.UNKNOWN, [], 0, time.perf_counter() - start, f"Scan error: {e}")

        if self.on_file_done:
            self.on_file_done(result)
        return result

    def _scan_content(
        self, file_path: str, content: str, language: Language
    ) -> List[Vulnerability]:
        rules = get_rules(language)
        lines = content.splitlines()
        total = len(lines)
        vulnerabilities: List[Vulnerability] = []
        seen: set[tuple] = set()

        single_prefix, block_start, block_end = get_comment_prefix(language)
        in_block_comment = False

        for line_idx, line in enumerate(lines):
            if len(line) > MAX_LINE_LENGTH:
                continue

            stripped = line.strip()

            # Track block comments
            if block_start and block_end:
                if block_start in stripped:
                    in_block_comment = True
                if block_end in stripped:
                    in_block_comment = False
                    continue

            is_comment = in_block_comment or (
                single_prefix and stripped.startswith(single_prefix)
            )

            for rule in rules:
                if not rule.match(line):
                    continue

                dedup_key = (rule.id, file_path, line_idx + 1)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                confidence = rule.confidence
                if is_comment:
                    if not self.include_comments:
                        continue
                    if confidence == Confidence.HIGH:
                        confidence = Confidence.MEDIUM
                    elif confidence == Confidence.MEDIUM:
                        confidence = Confidence.LOW

                start_ctx = max(0, line_idx - CONTEXT_LINES)
                end_ctx = min(total, line_idx + CONTEXT_LINES + 1)
                snippet = lines[start_ctx:end_ctx]

                vuln = Vulnerability(
                    rule_id=rule.id,
                    name=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    category=rule.category,
                    language=language,
                    file_path=file_path,
                    line_number=line_idx + 1,
                    line_content=line.rstrip(),
                    remediation=rule.remediation,
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    confidence=confidence,
                    snippet=snippet,
                    snippet_start_line=start_ctx + 1,
                    in_comment=is_comment,
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def scan_directory(self, directory: str) -> ScanReport:
        start = time.perf_counter()
        results: List[ScanResult] = []
        dir_path = Path(directory)

        files = self._collect_files(dir_path)
        for file_path in files:
            result = self.scan_file(str(file_path))
            results.append(result)

        return self._build_report(results, directory, time.perf_counter() - start)

    def scan_files(self, files: List[str]) -> ScanReport:
        start = time.perf_counter()
        results: List[ScanResult] = []
        for file_path in files:
            results.append(self.scan_file(file_path))
        return self._build_report(results, f"{len(files)} files", time.perf_counter() - start)

    def _collect_files(self, directory: Path) -> List[Path]:
        collected: List[Path] = []
        try:
            for item in directory.rglob("*"):
                if item.is_file() and is_scannable(str(item)):
                    # Check no parent part is in SKIP_DIRS
                    skip = False
                    for part in item.relative_to(directory).parts[:-1]:
                        if part in SKIP_DIRS:
                            skip = True
                            break
                    if not skip:
                        collected.append(item)
        except PermissionError:
            pass
        return sorted(collected)

    @staticmethod
    def _build_report(results: List[ScanResult], target: str, total_time: float) -> ScanReport:
        all_vulns = [v for r in results for v in r.vulnerabilities]
        files_with_issues = sum(1 for r in results if r.vulnerabilities)

        severity_counts = {s: 0 for s in Severity}
        for v in all_vulns:
            severity_counts[v.severity] += 1

        langs_seen = sorted({r.language.value for r in results if r.language != Language.UNKNOWN})

        return ScanReport(
            results=results,
            total_time=total_time,
            files_scanned=len(results),
            files_with_issues=files_with_issues,
            total_vulnerabilities=len(all_vulns),
            critical_count=severity_counts[Severity.CRITICAL],
            high_count=severity_counts[Severity.HIGH],
            medium_count=severity_counts[Severity.MEDIUM],
            low_count=severity_counts[Severity.LOW],
            info_count=severity_counts[Severity.INFO],
            target=target,
            languages_found=langs_seen,
        )
