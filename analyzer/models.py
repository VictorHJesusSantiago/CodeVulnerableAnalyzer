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
            Severity.HIGH:     "bold red",
            Severity.MEDIUM:   "bold yellow",
            Severity.LOW:      "bold cyan",
            Severity.INFO:     "dim white",
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
            Severity.HIGH:     "●",
            Severity.MEDIUM:   "●",
            Severity.LOW:      "●",
            Severity.INFO:     "○",
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
    # ── Linguagens principais ─────────────────────────────────────────────────
    PYTHON      = "Python"
    JAVASCRIPT  = "JavaScript"
    TYPESCRIPT  = "TypeScript"
    JAVA        = "Java"
    CSHARP      = "C#"
    PHP         = "PHP"
    GO          = "Go"
    RUBY        = "Ruby"
    C           = "C"
    CPP         = "C++"
    SQL         = "SQL"
    COBOL       = "COBOL"
    SHELL       = "Shell"
    KOTLIN      = "Kotlin"
    SWIFT       = "Swift"
    RUST        = "Rust"
    SCALA       = "Scala"
    PERL        = "Perl"

    # ── Sistemas / Low-level ──────────────────────────────────────────────────
    ASSEMBLY    = "Assembly"
    FORTRAN     = "Fortran"
    ADA         = "Ada"
    ZIG         = "Zig"
    NIM         = "Nim"
    CRYSTAL     = "Crystal"
    VLANG       = "V"

    # ── Web / Frontend ────────────────────────────────────────────────────────
    HTML        = "HTML"
    CSS         = "CSS"
    SCSS        = "SCSS"
    SASS        = "Sass"
    LESS        = "LESS"
    STYLUS      = "Stylus"
    SVG         = "SVG"
    WEBASSEMBLY = "WebAssembly"

    # ── Engines de Template ───────────────────────────────────────────────────
    PUG         = "Pug"
    HANDLEBARS  = "Handlebars"
    EJS         = "EJS"
    LIQUID      = "Liquid"

    # ── Dados / Configuração ──────────────────────────────────────────────────
    JSON        = "JSON"
    YAML        = "YAML"
    TOML        = "TOML"
    XML         = "XML"
    INI         = "INI"
    PROTOBUF    = "Protobuf"
    MARKDOWN    = "Markdown"

    # ── Query / APIs ──────────────────────────────────────────────────────────
    GRAPHQL     = "GraphQL"
    SPARQL      = "SPARQL"
    PLSQL       = "PL/SQL"
    TSQL        = "T-SQL"
    MQL         = "MQL"

    # ── Scripting / Shell Avançado ────────────────────────────────────────────
    POWERSHELL  = "PowerShell"
    BASH        = "Bash"
    AWK         = "Awk"
    BATCH       = "Batch"
    LUA         = "Lua"
    TCL         = "Tcl"

    # ── Funcionais / Acadêmicas ───────────────────────────────────────────────
    HASKELL     = "Haskell"
    ERLANG      = "Erlang"
    ELIXIR      = "Elixir"
    CLOJURE     = "Clojure"
    FSHARP      = "F#"
    OCAML       = "OCaml"
    SCHEME      = "Scheme"
    LISP        = "Lisp"
    PROLOG      = "Prolog"
    JULIA       = "Julia"
    ELM         = "Elm"
    COFFEESCRIPT = "CoffeeScript"

    # ── Mobile ────────────────────────────────────────────────────────────────
    DART        = "Dart"
    OBJECTIVEC  = "Objective-C"

    # ── JVM / .NET / Desktop ─────────────────────────────────────────────────
    GROOVY      = "Groovy"
    VBNET       = "VB.NET"
    COLDFUSION  = "ColdFusion"

    # ── Legado / Enterprise ───────────────────────────────────────────────────
    PASCAL      = "Pascal"
    PLI         = "PL/I"
    ABAP        = "ABAP"
    RPG         = "RPG"
    MODULA2     = "Modula-2"
    SMALLTALK   = "Smalltalk"
    ACTIONSCRIPT = "ActionScript"
    APEX        = "Apex"

    # ── IaC / DevOps ──────────────────────────────────────────────────────────
    TERRAFORM   = "Terraform"
    DOCKERFILE  = "Dockerfile"

    # ── Blockchain ────────────────────────────────────────────────────────────
    SOLIDITY    = "Solidity"
    VYPER       = "Vyper"
    MOVE        = "Move"
    CAIRO       = "Cairo"

    # ── Científicas / Acadêmicas ──────────────────────────────────────────────
    MATLAB      = "MATLAB"
    R           = "R"
    SCRATCH     = "Scratch"

    # ── Hardware Description ──────────────────────────────────────────────────
    VHDL        = "VHDL"
    VERILOG     = "Verilog/SystemVerilog"

    # ── Build / Automação de Build ────────────────────────────────────────────
    MAKEFILE    = "Makefile"
    CMAKE       = "CMake"
    BAZEL       = "Bazel/Starlark"
    GRADLE      = "Gradle"
    SED         = "sed"

    # ── Lisp family / Lógica ──────────────────────────────────────────────────
    RACKET      = "Racket"
    FORTH       = "Forth"
    APL         = "APL/J/K"

    # ── Scripting de Automação ────────────────────────────────────────────────
    AUTOHOTKEY  = "AutoHotkey"
    APPLESCRIPT = "AppleScript"
    FISH        = "Fish"
    ZSH         = "Zsh"

    # ── IaC / Config avançada ─────────────────────────────────────────────────
    BICEP       = "Bicep"
    JSONNET     = "Jsonnet"
    DHALL       = "Dhall"
    CUE         = "CUE"
    NIX         = "Nix"
    PUPPET      = "Puppet"
    CHEF        = "Chef"
    SALTSTACK   = "SaltStack"

    # ── Blockchain / Smart Contracts (extensão) ───────────────────────────────
    YUL         = "Yul"
    HUFF        = "Huff"
    CADENCE     = "Cadence"
    CLARITY     = "Clarity"
    MICHELSON   = "Michelson"
    INK         = "Ink!"
    SWAY        = "Sway"
    RIDE        = "Ride"
    TEAL        = "TEAL"

    # ── GPU / Shaders ──────────────────────────────────────────────────────────
    GLSL        = "GLSL"
    HLSL        = "HLSL"
    WGSL        = "WGSL"
    CUDA        = "CUDA"
    OPENCL      = "OpenCL"
    METAL       = "Metal"

    # ── Sistemas modernos / Funcionais novas ──────────────────────────────────
    MOJO        = "Mojo"
    CARBON      = "Carbon"
    VALE        = "Vale"
    ODIN        = "Odin"
    HARE        = "Hare"
    GLEAM       = "Gleam"
    ROC         = "Roc"
    UNISON      = "Unison"
    RESCRIPT    = "ReScript"
    PURESCRIPT  = "PureScript"

    # ── Provas / Dependently-typed ─────────────────────────────────────────────
    IDRIS       = "Idris"
    LEAN        = "Lean"
    COQ         = "Coq"
    AGDA        = "Agda"

    # ── Quântica ──────────────────────────────────────────────────────────────
    QSHARP      = "Q#"
    OPENQASM    = "OpenQASM"

    # ── Meta ──────────────────────────────────────────────────────────────────
    GENERIC     = "Generic"
    UNKNOWN     = "Unknown"

    def color(self) -> str:
        return {
            # Existentes
            Language.PYTHON:      "bright_blue",
            Language.JAVASCRIPT:  "yellow",
            Language.TYPESCRIPT:  "blue",
            Language.JAVA:        "red",
            Language.CSHARP:      "magenta",
            Language.PHP:         "bright_magenta",
            Language.GO:          "cyan",
            Language.RUBY:        "bright_red",
            Language.C:           "green",
            Language.CPP:         "bright_green",
            Language.SQL:         "bright_cyan",
            Language.COBOL:       "white",
            Language.SHELL:       "green",
            Language.KOTLIN:      "bright_magenta",
            Language.SWIFT:       "bright_red",
            Language.RUST:        "bright_yellow",
            Language.SCALA:       "red",
            Language.PERL:        "bright_blue",
            # Sistemas
            Language.ASSEMBLY:    "dim green",
            Language.FORTRAN:     "dim cyan",
            Language.ADA:         "blue",
            Language.ZIG:         "bright_yellow",
            Language.NIM:         "bright_yellow",
            Language.CRYSTAL:     "bright_white",
            Language.VLANG:       "bright_blue",
            # Web / Frontend
            Language.HTML:        "bright_red",
            Language.CSS:         "bright_blue",
            Language.SCSS:        "bright_magenta",
            Language.SASS:        "magenta",
            Language.LESS:        "blue",
            Language.STYLUS:      "green",
            Language.SVG:         "yellow",
            Language.WEBASSEMBLY: "bright_magenta",
            # Templates
            Language.PUG:         "green",
            Language.HANDLEBARS:  "bright_yellow",
            Language.EJS:         "yellow",
            Language.LIQUID:      "cyan",
            # Dados / Config
            Language.JSON:        "bright_yellow",
            Language.YAML:        "cyan",
            Language.TOML:        "bright_red",
            Language.XML:         "bright_cyan",
            Language.INI:         "white",
            Language.PROTOBUF:    "bright_blue",
            Language.MARKDOWN:    "bright_white",
            # Query
            Language.GRAPHQL:     "bright_magenta",
            Language.SPARQL:      "bright_blue",
            Language.PLSQL:       "bright_cyan",
            Language.TSQL:        "bright_cyan",
            Language.MQL:         "bright_yellow",
            # Shell avançado
            Language.POWERSHELL:  "bright_blue",
            Language.BASH:        "green",
            Language.AWK:         "dim green",
            Language.BATCH:       "dim white",
            Language.LUA:         "bright_blue",
            Language.TCL:         "red",
            # Funcionais
            Language.HASKELL:     "bright_magenta",
            Language.ERLANG:      "bright_red",
            Language.ELIXIR:      "magenta",
            Language.CLOJURE:     "green",
            Language.FSHARP:      "blue",
            Language.OCAML:       "bright_yellow",
            Language.SCHEME:      "dim white",
            Language.LISP:        "dim white",
            Language.PROLOG:      "bright_red",
            Language.JULIA:       "bright_magenta",
            Language.ELM:         "bright_blue",
            Language.COFFEESCRIPT: "bright_yellow",
            # Mobile
            Language.DART:        "bright_cyan",
            Language.OBJECTIVEC:  "bright_blue",
            # JVM / .NET
            Language.GROOVY:      "bright_blue",
            Language.VBNET:       "blue",
            Language.COLDFUSION:  "bright_red",
            # Legado
            Language.PASCAL:      "dim cyan",
            Language.PLI:         "dim white",
            Language.ABAP:        "bright_white",
            Language.RPG:         "dim white",
            Language.MODULA2:     "dim white",
            Language.SMALLTALK:   "bright_blue",
            Language.ACTIONSCRIPT: "bright_red",
            Language.APEX:        "bright_blue",
            # IaC
            Language.TERRAFORM:   "bright_magenta",
            Language.DOCKERFILE:  "bright_cyan",
            # Blockchain
            Language.SOLIDITY:    "bright_yellow",
            Language.VYPER:       "bright_green",
            Language.MOVE:        "bright_cyan",
            Language.CAIRO:       "bright_magenta",
            # Científicas
            Language.MATLAB:      "bright_red",
            Language.R:           "bright_blue",
            Language.SCRATCH:     "bright_yellow",
            # Meta
            Language.GENERIC:     "white",
            Language.UNKNOWN:     "dim",
        }.get(self, "white")

    @classmethod
    def by_category(cls) -> dict[str, list["Language"]]:
        return {
            "Sistemas / Low-level":    [cls.C, cls.CPP, cls.RUST, cls.GO, cls.ASSEMBLY, cls.ADA, cls.FORTRAN, cls.ZIG, cls.NIM, cls.CRYSTAL, cls.VLANG],
            "JVM / .NET / Desktop":    [cls.JAVA, cls.KOTLIN, cls.SCALA, cls.CSHARP, cls.VBNET, cls.FSHARP, cls.GROOVY, cls.COLDFUSION],
            "Scripting / Web Backend": [cls.PYTHON, cls.PHP, cls.RUBY, cls.PERL, cls.LUA, cls.TCL, cls.AWK],
            "Mobile":                  [cls.SWIFT, cls.KOTLIN, cls.DART, cls.OBJECTIVEC],
            "Web / Frontend":          [cls.JAVASCRIPT, cls.TYPESCRIPT, cls.HTML, cls.CSS, cls.SCSS, cls.SASS, cls.LESS, cls.STYLUS, cls.SVG, cls.WEBASSEMBLY],
            "Templates":               [cls.PUG, cls.HANDLEBARS, cls.EJS, cls.LIQUID],
            "Shell / Automação":       [cls.SHELL, cls.BASH, cls.POWERSHELL, cls.BATCH],
            "Funcionais":              [cls.HASKELL, cls.ERLANG, cls.ELIXIR, cls.CLOJURE, cls.OCAML, cls.FSHARP, cls.SCHEME, cls.LISP, cls.PROLOG, cls.JULIA, cls.ELM, cls.COFFEESCRIPT],
            "Dados / Config":          [cls.SQL, cls.PLSQL, cls.TSQL, cls.JSON, cls.YAML, cls.TOML, cls.XML, cls.INI, cls.PROTOBUF, cls.GRAPHQL, cls.SPARQL, cls.MQL, cls.MARKDOWN],
            "IaC / DevOps":            [cls.TERRAFORM, cls.DOCKERFILE],
            "Blockchain":              [cls.SOLIDITY, cls.VYPER, cls.MOVE, cls.CAIRO],
            "Enterprise / Legado":     [cls.COBOL, cls.ABAP, cls.APEX, cls.PASCAL, cls.PLI, cls.RPG, cls.MODULA2, cls.SMALLTALK, cls.ACTIONSCRIPT, cls.COLDFUSION],
            "Científicas":             [cls.MATLAB, cls.R, cls.JULIA, cls.SCRATCH],
        }


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
    # ── Qualidade de Código ───────────────────────────────────────────────────
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
    # ── Anti-patterns de Design ────────────────────────────────────────────────
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
    # ── Arquitetura ───────────────────────────────────────────────────────────
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
    # ── IaC / DevOps / Infraestrutura ─────────────────────────────────────────
    IAC_SECURITY          = "IaC Security"
    CONTAINER_SECURITY    = "Container Security"
    # ── Blockchain ────────────────────────────────────────────────────────────
    SMART_CONTRACT        = "Smart Contract Vulnerability"
    # ── Outros ────────────────────────────────────────────────────────────────
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
    function_context: Optional[str] = None


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
