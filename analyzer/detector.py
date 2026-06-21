from __future__ import annotations
import re
from pathlib import Path
from analyzer.models import Language

EXTENSION_MAP: dict[str, Language] = {
    ".py": Language.PYTHON, ".pyw": Language.PYTHON,
    ".js": Language.JAVASCRIPT, ".jsx": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT, ".cjs": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT, ".tsx": Language.TYPESCRIPT,
    ".java": Language.JAVA,
    ".cs": Language.CSHARP,
    ".php": Language.PHP, ".php3": Language.PHP, ".php4": Language.PHP,
    ".php5": Language.PHP, ".phtml": Language.PHP,
    ".go": Language.GO,
    ".rb": Language.RUBY, ".rake": Language.RUBY,
    ".c": Language.C, ".h": Language.C,
    ".cpp": Language.CPP, ".cxx": Language.CPP, ".cc": Language.CPP,
    ".hpp": Language.CPP, ".hxx": Language.CPP,
    ".sql": Language.SQL, ".ddl": Language.SQL, ".dml": Language.SQL,
    ".cbl": Language.COBOL, ".cob": Language.COBOL, ".cpy": Language.COBOL,
    ".sh": Language.SHELL, ".bash": Language.SHELL, ".zsh": Language.SHELL,
    ".ksh": Language.SHELL, ".fish": Language.SHELL,
    ".kt": Language.KOTLIN, ".kts": Language.KOTLIN,
    ".swift": Language.SWIFT,
    ".rs": Language.RUST,
    ".scala": Language.SCALA, ".sc": Language.SCALA,
    ".pl": Language.PERL, ".pm": Language.PERL,
}

CONTENT_SIGNATURES: list[tuple[Language, re.Pattern]] = [
    (Language.PYTHON,     re.compile(r'^\s*(?:import\s+\w+|from\s+\w+\s+import|def\s+\w+\s*\(|class\s+\w+.*:)|^#!/usr/bin/(?:env\s+)?python')),
    (Language.JAVASCRIPT, re.compile(r'\b(?:const|let|var)\s+\w+\s*=|require\s*\(|module\.exports\s*=|=>\s*\{')),
    (Language.TYPESCRIPT, re.compile(r':\s*(?:string|number|boolean|any|void)\s*[;=,\)]|interface\s+\w+\s*\{')),
    (Language.JAVA,       re.compile(r'\bpublic\s+(?:class|interface|enum|record)\s+\w+|import\s+java\.')),
    (Language.CSHARP,     re.compile(r'\busing\s+System|namespace\s+\w+|public\s+(?:class|interface|enum|struct)\s+\w+')),
    (Language.PHP,        re.compile(r'<\?php|\$[a-zA-Z_]\w*\s*=')),
    (Language.GO,         re.compile(r'^package\s+\w+|^import\s*\(|^func\s+\w+')),
    (Language.RUBY,       re.compile(r'^\s*(?:require|require_relative)\s+["\']|^\s*def\s+\w+|^\s*class\s+\w+')),
    (Language.COBOL,      re.compile(r'\bIDENTIFICATION\s+DIVISION\b|\bPROGRAM-ID\b', re.IGNORECASE)),
    (Language.SHELL,      re.compile(r'^#!/(?:bin|usr/bin)/(?:ba)?sh|^#!/usr/bin/env\s+(?:ba)?sh')),
    (Language.SQL,        re.compile(r'^\s*(?:SELECT|INSERT\s+INTO|CREATE\s+TABLE|UPDATE\s+\w+\s+SET|DELETE\s+FROM)', re.IGNORECASE)),
    (Language.KOTLIN,     re.compile(r'\bfun\s+\w+\s*\(|^\s*val\s+\w+\s*=|^\s*var\s+\w+\s*=')),
    (Language.RUST,       re.compile(r'\bfn\s+\w+\s*\(|^\s*let\s+(?:mut\s+)?\w+\s*=|use\s+std::')),
]

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".obj", ".o",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".tar",
    ".gz", ".7z", ".rar", ".pyc", ".pyo", ".class", ".jar",
    ".war", ".ear", ".whl", ".egg",
}

SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__",
    ".pytest_cache", ".mypy_cache", "venv", ".venv", "env",
    "dist", "build", "target", "out", ".idea", ".vscode",
    "vendor", "third_party", "Pods",
}


def detect_language(file_path: str, content: str = "") -> Language:
    path = Path(file_path)
    ext = path.suffix.lower()

    if ext in BINARY_EXTENSIONS:
        return Language.UNKNOWN

    if ext in EXTENSION_MAP:
        return EXTENSION_MAP[ext]

    if content:
        sample = "\n".join(content.splitlines()[:30])
        for lang, pattern in CONTENT_SIGNATURES:
            if pattern.search(sample):
                return lang

    return Language.UNKNOWN


def is_scannable(file_path: str) -> bool:
    path = Path(file_path)
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return False
    for part in path.parts:
        if part in SKIP_DIRS:
            return False
    return True


def get_comment_prefix(language: Language) -> tuple[str, str, str]:
    """Returns (single_line_prefix, block_start, block_end)."""
    c_style = ("//", "/*", "*/")
    hash_style = ("#", "", "")
    sql_style = ("--", "/*", "*/")
    return {
        Language.PYTHON:     hash_style,
        Language.RUBY:       hash_style,
        Language.SHELL:      hash_style,
        Language.PERL:       hash_style,
        Language.JAVASCRIPT: c_style,
        Language.TYPESCRIPT: c_style,
        Language.JAVA:       c_style,
        Language.CSHARP:     c_style,
        Language.GO:         c_style,
        Language.KOTLIN:     c_style,
        Language.SWIFT:      c_style,
        Language.RUST:       c_style,
        Language.SCALA:      c_style,
        Language.CPP:        c_style,
        Language.C:          c_style,
        Language.PHP:        c_style,
        Language.SQL:        sql_style,
        Language.COBOL:      ("*", "", ""),
    }.get(language, ("//", "/*", "*/"))
