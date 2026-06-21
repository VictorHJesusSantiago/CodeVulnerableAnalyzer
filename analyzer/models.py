from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List


class Severity(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

    def color(self) -> str:
        return {
            Severity.CRITICAL: "bold bright_red",
            Severity.HIGH: "bold red",
            Severity.MEDIUM: "bold yellow",
            Severity.LOW: "bold cyan",
            Severity.INFO: "dim white",
        }[self]

    def badge(self) -> str:
        return {
            Severity.CRITICAL: "[bold white on bright_red] CRITICAL [/]",
            Severity.HIGH:     "[bold white on red]         HIGH    [/]",
            Severity.MEDIUM:   "[bold black on yellow]      MEDIUM  [/]",
            Severity.LOW:      "[bold white on blue]         LOW     [/]",
            Severity.INFO:     "[bold black on white]        INFO    [/]",
        }[self]

    def icon(self) -> str:
        return {
            Severity.CRITICAL: "⬛",
            Severity.HIGH:     "🔴",
            Severity.MEDIUM:   "🟡",
            Severity.LOW:      "🔵",
            Severity.INFO:     "⚪",
        }[self]

    def bar_color(self) -> str:
        return {
            Severity.CRITICAL: "bright_red",
            Severity.HIGH:     "red",
            Severity.MEDIUM:   "yellow",
            Severity.LOW:      "cyan",
            Severity.INFO:     "white",
        }[self]


class Confidence(Enum):
    HIGH = 3
    MEDIUM = 2
    LOW = 1

    def label(self) -> str:
        return {
            Confidence.HIGH:   "[green]HIGH[/green]",
            Confidence.MEDIUM: "[yellow]MED[/yellow]",
            Confidence.LOW:    "[dim]LOW[/dim]",
        }[self]


class Language(Enum):
    PYTHON     = "Python"
    JAVASCRIPT = "JavaScript"
    TYPESCRIPT = "TypeScript"
    JAVA       = "Java"
    CSHARP     = "C#"
    PHP        = "PHP"
    GO         = "Go"
    RUBY       = "Ruby"
    C          = "C"
    CPP        = "C++"
    SQL        = "SQL"
    COBOL      = "COBOL"
    SHELL      = "Shell"
    KOTLIN     = "Kotlin"
    SWIFT      = "Swift"
    RUST       = "Rust"
    SCALA      = "Scala"
    PERL       = "Perl"
    GENERIC    = "Generic"
    UNKNOWN    = "Unknown"

    def color(self) -> str:
        return {
            Language.PYTHON:     "bright_blue",
            Language.JAVASCRIPT: "yellow",
            Language.TYPESCRIPT: "blue",
            Language.JAVA:       "red",
            Language.CSHARP:     "magenta",
            Language.PHP:        "bright_magenta",
            Language.GO:         "cyan",
            Language.RUBY:       "bright_red",
            Language.C:          "green",
            Language.CPP:        "bright_green",
            Language.SQL:        "bright_cyan",
            Language.COBOL:      "white",
            Language.SHELL:      "green",
            Language.KOTLIN:     "bright_magenta",
            Language.SWIFT:      "bright_red",
            Language.RUST:       "bright_yellow",
            Language.SCALA:      "red",
            Language.PERL:       "bright_blue",
            Language.GENERIC:    "white",
            Language.UNKNOWN:    "dim",
        }.get(self, "white")


class VulnCategory(Enum):
    # ── Segurança (OWASP / CWE) ───────────────────────────────────────────────
    SQL_INJECTION         = "SQL Injection"
    COMMAND_INJECTION     = "Command Injection"
    CODE_INJECTION        = "Code Injection"
    LDAP_INJECTION        = "LDAP Injection"
    XPATH_INJECTION       = "XPath Injection"
    XSS                   = "Cross-Site Scripting"
    BROKEN_AUTH           = "Broken Authentication"
    SENSITIVE_DATA        = "Sensitive Data Exposure"
    XXE                   = "XML External Entity"
    BROKEN_ACCESS         = "Broken Access Control"
    SECURITY_MISCONFIG    = "Security Misconfiguration"
    INSECURE_DESER        = "Insecure Deserialization"
    CRYPTO                = "Cryptographic Failures"
    PATH_TRAVERSAL        = "Path Traversal"
    SSRF                  = "Server-Side Request Forgery"
    MEMORY_SAFETY         = "Memory Safety"
    RACE_CONDITION        = "Race Condition"
    HARDCODED_SECRETS     = "Hardcoded Secrets"
    WEAK_RANDOMNESS       = "Weak Randomness"
    OPEN_REDIRECT         = "Open Redirect"
    PROTOTYPE_POLLUTION   = "Prototype Pollution"
    MASS_ASSIGNMENT       = "Mass Assignment"
    IMPROPER_VALIDATION   = "Improper Input Validation"
    INFO_DISCLOSURE       = "Information Disclosure"
    CSRF                  = "Cross-Site Request Forgery"
    SUPPLY_CHAIN          = "Supply Chain Risk"
    # ── Qualidade de Código (Clean Code) ─────────────────────────────────────
    CODE_QUALITY          = "Code Quality"
    NAMING                = "Naming Convention"
    COMPLEXITY            = "Excessive Complexity"
    MAINTAINABILITY       = "Maintainability"
    DEAD_CODE             = "Dead Code"
    TECHNICAL_DEBT        = "Technical Debt"
    DRY_PRINCIPLE         = "DRY Principle Violation"
    # ── Princípios SOLID ─────────────────────────────────────────────────────
    SOLID_SRP             = "SOLID: Single Responsibility"
    SOLID_OCP             = "SOLID: Open/Closed Principle"
    SOLID_LSP             = "SOLID: Liskov Substitution"
    SOLID_ISP             = "SOLID: Interface Segregation"
    SOLID_DIP             = "SOLID: Dependency Inversion"
    # ── Anti-patterns de Design ───────────────────────────────────────────────
    ANTI_PATTERN          = "Design Anti-pattern"
    GOD_OBJECT            = "God Object / God Class"
    PRIMITIVE_OBSESSION   = "Primitive Obsession"
    FEATURE_ENVY          = "Feature Envy"
    DATA_CLUMP            = "Data Clump"
    # ── Performance ──────────────────────────────────────────────────────────
    PERFORMANCE           = "Performance Anti-pattern"
    DATABASE_PERF         = "Database Performance"
    MEMORY_LEAK           = "Memory Leak"
    # ── Tratamento de Erros ───────────────────────────────────────────────────
    ERROR_HANDLING        = "Error Handling"
    EXCEPTION_ABUSE       = "Exception Abuse"
    # ── Concorrência ─────────────────────────────────────────────────────────
    CONCURRENCY           = "Concurrency Issue"
    DEADLOCK              = "Deadlock Risk"
    # ── Arquitetura ──────────────────────────────────────────────────────────
    ARCHITECTURE          = "Architecture Violation"
    COUPLING              = "High Coupling"
    COHESION              = "Low Cohesion"
    LAYER_VIOLATION       = "Layer Violation"
    # ── Documentação e Logging ────────────────────────────────────────────────
    DOCUMENTATION         = "Documentation Issue"
    LOGGING               = "Logging Issue"
    # ── API e Banco de Dados ──────────────────────────────────────────────────
    API_DESIGN            = "API Design Issue"
    DATABASE              = "Database Anti-pattern"
    # ── Testes ───────────────────────────────────────────────────────────────
    TESTING               = "Testing Quality"
    # ── Outros ───────────────────────────────────────────────────────────────
    OTHER                 = "Other"


@dataclass
class Vulnerability:
    rule_id: str
    name: str
    description: str
    severity: Severity
    category: VulnCategory
    language: Language
    file_path: str
    line_number: int
    line_content: str
    remediation: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    confidence: Confidence = Confidence.MEDIUM
    snippet: List[str] = field(default_factory=list)
    snippet_start_line: int = 0
    in_comment: bool = False


@dataclass
class ScanResult:
    file_path: str
    language: Language
    vulnerabilities: List[Vulnerability]
    lines_scanned: int
    scan_time: float
    error: Optional[str] = None


@dataclass
class ScanReport:
    results: List[ScanResult]
    total_time: float
    files_scanned: int
    files_with_issues: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    target: str
    languages_found: List[str] = field(default_factory=list)
