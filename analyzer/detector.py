from __future__ import annotations
import re
from pathlib import Path
from analyzer.models import Language

EXTENSION_MAP: dict[str, Language] = {
    # ── Python ────────────────────────────────────────────────────────────────
    ".py": Language.PYTHON, ".pyw": Language.PYTHON, ".pyi": Language.PYTHON,
    # ── JavaScript ────────────────────────────────────────────────────────────
    ".js": Language.JAVASCRIPT, ".jsx": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT, ".cjs": Language.JAVASCRIPT,
    # ── TypeScript ────────────────────────────────────────────────────────────
    ".ts": Language.TYPESCRIPT, ".tsx": Language.TYPESCRIPT, ".cts": Language.TYPESCRIPT,
    # ── Java ──────────────────────────────────────────────────────────────────
    ".java": Language.JAVA,
    # ── C# ────────────────────────────────────────────────────────────────────
    ".cs": Language.CSHARP, ".csx": Language.CSHARP,
    # ── PHP ───────────────────────────────────────────────────────────────────
    ".php": Language.PHP, ".php3": Language.PHP, ".php4": Language.PHP,
    ".php5": Language.PHP, ".php7": Language.PHP, ".phtml": Language.PHP, ".phps": Language.PHP,
    # ── Go ────────────────────────────────────────────────────────────────────
    ".go": Language.GO,
    # ── Ruby ──────────────────────────────────────────────────────────────────
    ".rb": Language.RUBY, ".rake": Language.RUBY, ".gemspec": Language.RUBY, ".rbw": Language.RUBY,
    # ── C ─────────────────────────────────────────────────────────────────────
    ".c": Language.C, ".h": Language.C,
    # ── C++ ───────────────────────────────────────────────────────────────────
    ".cpp": Language.CPP, ".cxx": Language.CPP, ".cc": Language.CPP,
    ".hpp": Language.CPP, ".hxx": Language.CPP, ".hh": Language.CPP, ".inl": Language.CPP,
    # ── SQL ───────────────────────────────────────────────────────────────────
    ".sql": Language.SQL, ".ddl": Language.SQL, ".dml": Language.SQL,
    # ── PL/SQL ────────────────────────────────────────────────────────────────
    ".pls": Language.PLSQL, ".pck": Language.PLSQL, ".pkb": Language.PLSQL,
    ".pks": Language.PLSQL, ".fnc": Language.PLSQL, ".prc": Language.PLSQL,
    # ── T-SQL ─────────────────────────────────────────────────────────────────
    ".tsql": Language.TSQL,
    # ── COBOL ─────────────────────────────────────────────────────────────────
    ".cbl": Language.COBOL, ".cob": Language.COBOL, ".cpy": Language.COBOL,
    ".cobol": Language.COBOL, ".cbl": Language.COBOL,
    # ── Shell ─────────────────────────────────────────────────────────────────
    ".sh": Language.SHELL, ".bash": Language.BASH, ".zsh": Language.SHELL,
    ".ksh": Language.SHELL, ".fish": Language.SHELL, ".bashrc": Language.BASH,
    ".profile": Language.BASH, ".bash_profile": Language.BASH,
    # ── PowerShell ────────────────────────────────────────────────────────────
    ".ps1": Language.POWERSHELL, ".psm1": Language.POWERSHELL,
    ".psd1": Language.POWERSHELL, ".ps1xml": Language.POWERSHELL,
    # ── Batch / MS-DOS ────────────────────────────────────────────────────────
    ".bat": Language.BATCH, ".cmd": Language.BATCH,
    # ── Kotlin ────────────────────────────────────────────────────────────────
    ".kt": Language.KOTLIN, ".kts": Language.KOTLIN,
    # ── Swift ─────────────────────────────────────────────────────────────────
    ".swift": Language.SWIFT,
    # ── Rust ──────────────────────────────────────────────────────────────────
    ".rs": Language.RUST,
    # ── Scala ─────────────────────────────────────────────────────────────────
    ".scala": Language.SCALA, ".sc": Language.SCALA, ".sbt": Language.SCALA,
    # ── Perl ──────────────────────────────────────────────────────────────────
    ".pl": Language.PERL, ".pm": Language.PERL, ".pod": Language.PERL, ".t": Language.PERL,
    # ── Dart ──────────────────────────────────────────────────────────────────
    ".dart": Language.DART,
    # ── Objective-C ───────────────────────────────────────────────────────────
    ".m": Language.OBJECTIVEC, ".mm": Language.OBJECTIVEC,
    # ── Assembly ──────────────────────────────────────────────────────────────
    ".asm": Language.ASSEMBLY, ".s": Language.ASSEMBLY, ".nasm": Language.ASSEMBLY,
    ".masm": Language.ASSEMBLY, ".S": Language.ASSEMBLY,
    # ── Fortran ───────────────────────────────────────────────────────────────
    ".f": Language.FORTRAN, ".f90": Language.FORTRAN, ".f95": Language.FORTRAN,
    ".f03": Language.FORTRAN, ".f08": Language.FORTRAN, ".for": Language.FORTRAN,
    ".fpp": Language.FORTRAN, ".f77": Language.FORTRAN,
    # ── Ada ───────────────────────────────────────────────────────────────────
    ".ada": Language.ADA, ".adb": Language.ADA, ".ads": Language.ADA,
    # ── Zig ───────────────────────────────────────────────────────────────────
    ".zig": Language.ZIG,
    # ── Nim ───────────────────────────────────────────────────────────────────
    ".nim": Language.NIM, ".nims": Language.NIM, ".nimble": Language.NIM,
    # ── Crystal ───────────────────────────────────────────────────────────────
    ".cr": Language.CRYSTAL,
    # ── V (Vlang) ─────────────────────────────────────────────────────────────
    ".v": Language.VLANG, ".vv": Language.VLANG,
    # ── HTML ──────────────────────────────────────────────────────────────────
    ".html": Language.HTML, ".htm": Language.HTML, ".xhtml": Language.HTML,
    ".html5": Language.HTML, ".shtml": Language.HTML,
    # ── CSS ───────────────────────────────────────────────────────────────────
    ".css": Language.CSS,
    # ── SCSS / Sass ───────────────────────────────────────────────────────────
    ".scss": Language.SCSS, ".sass": Language.SASS,
    # ── LESS ──────────────────────────────────────────────────────────────────
    ".less": Language.LESS,
    # ── Stylus ────────────────────────────────────────────────────────────────
    ".styl": Language.STYLUS, ".stylus": Language.STYLUS,
    # ── SVG ───────────────────────────────────────────────────────────────────
    ".svg": Language.SVG, ".svgz": Language.SVG,
    # ── WebAssembly ───────────────────────────────────────────────────────────
    ".wasm": Language.WEBASSEMBLY, ".wat": Language.WEBASSEMBLY,
    # ── Pug / Jade ────────────────────────────────────────────────────────────
    ".pug": Language.PUG, ".jade": Language.PUG,
    # ── Handlebars ────────────────────────────────────────────────────────────
    ".hbs": Language.HANDLEBARS, ".handlebars": Language.HANDLEBARS, ".mustache": Language.HANDLEBARS,
    # ── EJS ───────────────────────────────────────────────────────────────────
    ".ejs": Language.EJS,
    # ── Liquid ────────────────────────────────────────────────────────────────
    ".liquid": Language.LIQUID,
    # ── JSON ──────────────────────────────────────────────────────────────────
    ".json": Language.JSON, ".jsonc": Language.JSON, ".json5": Language.JSON,
    ".geojson": Language.JSON, ".webmanifest": Language.JSON,
    # ── YAML ──────────────────────────────────────────────────────────────────
    ".yaml": Language.YAML, ".yml": Language.YAML,
    # ── TOML ──────────────────────────────────────────────────────────────────
    ".toml": Language.TOML,
    # ── XML ───────────────────────────────────────────────────────────────────
    ".xml": Language.XML, ".xsl": Language.XML, ".xslt": Language.XML,
    ".wsdl": Language.XML, ".xsd": Language.XML, ".pom": Language.XML,
    ".resx": Language.XML, ".csproj": Language.XML, ".vbproj": Language.XML,
    # ── INI / Config ──────────────────────────────────────────────────────────
    ".ini": Language.INI, ".cfg": Language.INI, ".conf": Language.INI,
    ".config": Language.INI, ".env": Language.INI, ".properties": Language.INI,
    # ── Protobuf ──────────────────────────────────────────────────────────────
    ".proto": Language.PROTOBUF,
    # ── Markdown ──────────────────────────────────────────────────────────────
    ".md": Language.MARKDOWN, ".markdown": Language.MARKDOWN, ".mdx": Language.MARKDOWN,
    # ── GraphQL ───────────────────────────────────────────────────────────────
    ".graphql": Language.GRAPHQL, ".gql": Language.GRAPHQL,
    # ── SPARQL ────────────────────────────────────────────────────────────────
    ".sparql": Language.SPARQL, ".rq": Language.SPARQL,
    # ── Awk ───────────────────────────────────────────────────────────────────
    ".awk": Language.AWK,
    # ── Lua ───────────────────────────────────────────────────────────────────
    ".lua": Language.LUA,
    # ── Tcl ───────────────────────────────────────────────────────────────────
    ".tcl": Language.TCL, ".tk": Language.TCL,
    # ── Haskell ───────────────────────────────────────────────────────────────
    ".hs": Language.HASKELL, ".lhs": Language.HASKELL,
    # ── Erlang ────────────────────────────────────────────────────────────────
    ".erl": Language.ERLANG, ".hrl": Language.ERLANG,
    # ── Elixir ────────────────────────────────────────────────────────────────
    ".ex": Language.ELIXIR, ".exs": Language.ELIXIR, ".heex": Language.ELIXIR,
    # ── Clojure ───────────────────────────────────────────────────────────────
    ".clj": Language.CLOJURE, ".cljs": Language.CLOJURE,
    ".cljc": Language.CLOJURE, ".edn": Language.CLOJURE,
    # ── F# ────────────────────────────────────────────────────────────────────
    ".fs": Language.FSHARP, ".fsi": Language.FSHARP, ".fsx": Language.FSHARP, ".fsproj": Language.FSHARP,
    # ── OCaml ─────────────────────────────────────────────────────────────────
    ".ml": Language.OCAML, ".mli": Language.OCAML, ".mll": Language.OCAML, ".mly": Language.OCAML,
    # ── Scheme ────────────────────────────────────────────────────────────────
    ".scm": Language.SCHEME, ".ss": Language.SCHEME, ".sls": Language.SCHEME, ".sld": Language.SCHEME,
    # ── Lisp ──────────────────────────────────────────────────────────────────
    ".lisp": Language.LISP, ".lsp": Language.LISP, ".cl": Language.LISP, ".asd": Language.LISP,
    # ── Prolog ────────────────────────────────────────────────────────────────
    ".pro": Language.PROLOG, ".prolog": Language.PROLOG, ".pl": Language.PERL,  # .pl → Perl (more common)
    # ── Julia ─────────────────────────────────────────────────────────────────
    ".jl": Language.JULIA,
    # ── Elm ───────────────────────────────────────────────────────────────────
    ".elm": Language.ELM,
    # ── CoffeeScript ──────────────────────────────────────────────────────────
    ".coffee": Language.COFFEESCRIPT, ".litcoffee": Language.COFFEESCRIPT,
    # ── Groovy ────────────────────────────────────────────────────────────────
    ".groovy": Language.GROOVY, ".gvy": Language.GROOVY, ".gy": Language.GROOVY,
    ".gradle": Language.GROOVY, ".jenkinsfile": Language.GROOVY,
    # ── VB.NET ────────────────────────────────────────────────────────────────
    ".vb": Language.VBNET, ".vbs": Language.VBNET, ".vba": Language.VBNET,
    # ── ColdFusion ────────────────────────────────────────────────────────────
    ".cfm": Language.COLDFUSION, ".cfc": Language.COLDFUSION, ".cfml": Language.COLDFUSION,
    # ── Pascal / Delphi ───────────────────────────────────────────────────────
    ".pas": Language.PASCAL, ".pp": Language.PASCAL, ".dpr": Language.PASCAL,
    ".dfm": Language.PASCAL, ".dpk": Language.PASCAL, ".lpr": Language.PASCAL,
    # ── PL/I ──────────────────────────────────────────────────────────────────
    ".pli": Language.PLI, ".pl1": Language.PLI,
    # ── RPG ───────────────────────────────────────────────────────────────────
    ".rpg": Language.RPG, ".rpgle": Language.RPG, ".sqlrpgle": Language.RPG,
    # ── Modula-2 ──────────────────────────────────────────────────────────────
    ".mod": Language.MODULA2, ".def": Language.MODULA2,
    # ── Smalltalk ─────────────────────────────────────────────────────────────
    ".st": Language.SMALLTALK, ".gst": Language.SMALLTALK,
    # ── ActionScript ──────────────────────────────────────────────────────────
    ".as": Language.ACTIONSCRIPT, ".mxml": Language.ACTIONSCRIPT,
    # ── Apex (Salesforce) ─────────────────────────────────────────────────────
    ".cls": Language.APEX, ".trigger": Language.APEX, ".apex": Language.APEX,
    # ── Terraform / HCL ───────────────────────────────────────────────────────
    ".tf": Language.TERRAFORM, ".tfvars": Language.TERRAFORM, ".hcl": Language.TERRAFORM,
    # ── Solidity ──────────────────────────────────────────────────────────────
    ".sol": Language.SOLIDITY,
    # ── Blockchain adicionais ──────────────────────────────────────────────────
    ".vy": Language.VYPER, ".vyi": Language.VYPER,
    ".move": Language.MOVE,
    ".cairo": Language.CAIRO,
    # ── MATLAB ────────────────────────────────────────────────────────────────
    ".mat": Language.MATLAB, ".mlx": Language.MATLAB, ".mlapp": Language.MATLAB,
    # ── R ─────────────────────────────────────────────────────────────────────
    ".r": Language.R, ".R": Language.R, ".rmd": Language.R, ".Rmd": Language.R,

    # ══════════════════════════════════════════════════════════════════════════
    #  EXPANSÃO — novas linguagens (chaves duplicadas sobrescrevem as anteriores)
    # ══════════════════════════════════════════════════════════════════════════
    # ── Hardware Description ──────────────────────────────────────────────────
    ".vhd": Language.VHDL, ".vhdl": Language.VHDL,
    ".sv": Language.VERILOG, ".svh": Language.VERILOG, ".vh": Language.VERILOG,
    # ── Build ─────────────────────────────────────────────────────────────────
    ".cmake": Language.CMAKE,
    ".bzl": Language.BAZEL, ".bazel": Language.BAZEL, ".star": Language.BAZEL, ".starlark": Language.BAZEL,
    ".sed": Language.SED,
    # ── Lisp family / Lógica ──────────────────────────────────────────────────
    ".rkt": Language.RACKET, ".rktl": Language.RACKET,
    ".fth": Language.FORTH, ".4th": Language.FORTH, ".forth": Language.FORTH,
    ".apl": Language.APL, ".ijs": Language.APL, ".k": Language.APL,
    # ── Scripting de automação ────────────────────────────────────────────────
    ".ahk": Language.AUTOHOTKEY,
    ".applescript": Language.APPLESCRIPT, ".scpt": Language.APPLESCRIPT,
    ".fish": Language.FISH,                       # sobrescreve SHELL
    ".zsh": Language.ZSH,                          # sobrescreve SHELL
    # ── IaC / Config avançada ─────────────────────────────────────────────────
    ".bicep": Language.BICEP,
    ".jsonnet": Language.JSONNET, ".libsonnet": Language.JSONNET,
    ".dhall": Language.DHALL,
    ".cue": Language.CUE,
    ".nix": Language.NIX,
    ".pp": Language.PUPPET,                        # sobrescreve PASCAL (Pascal usa .pas/.dpr)
    ".sls": Language.SALTSTACK,                    # sobrescreve SCHEME (Scheme usa .scm/.ss)
    # ── Blockchain (extensão) ──────────────────────────────────────────────────
    ".yul": Language.YUL,
    ".huff": Language.HUFF,
    ".cdc": Language.CADENCE,
    ".clar": Language.CLARITY,
    ".tz": Language.MICHELSON,
    ".sw": Language.SWAY,
    ".ride": Language.RIDE,
    ".teal": Language.TEAL,
    # ── GPU / Shaders ──────────────────────────────────────────────────────────
    ".glsl": Language.GLSL, ".vert": Language.GLSL, ".frag": Language.GLSL,
    ".comp": Language.GLSL, ".geom": Language.GLSL, ".tesc": Language.GLSL, ".tese": Language.GLSL,
    ".hlsl": Language.HLSL, ".fx": Language.HLSL, ".hlsli": Language.HLSL,
    ".wgsl": Language.WGSL,
    ".cu": Language.CUDA, ".cuh": Language.CUDA,
    ".cl": Language.OPENCL,                        # sobrescreve LISP (Lisp usa .lisp/.lsp)
    ".metal": Language.METAL,
    # ── Sistemas modernos / Funcionais novas ──────────────────────────────────
    ".mojo": Language.MOJO,
    ".carbon": Language.CARBON,
    ".vale": Language.VALE,
    ".odin": Language.ODIN,
    ".ha": Language.HARE,
    ".gleam": Language.GLEAM,
    ".roc": Language.ROC,
    ".u": Language.UNISON,
    ".res": Language.RESCRIPT, ".resi": Language.RESCRIPT,
    ".purs": Language.PURESCRIPT,
    # ── Provas / Dependently-typed ─────────────────────────────────────────────
    ".idr": Language.IDRIS, ".lidr": Language.IDRIS,
    ".lean": Language.LEAN,
    ".agda": Language.AGDA,
    # ── Quântica ────────────────────────────────────────────────────────────────
    ".qs": Language.QSHARP,
    ".qasm": Language.OPENQASM,
}

CONTENT_SIGNATURES: list[tuple[Language, re.Pattern]] = [
    (Language.PYTHON,     re.compile(r'^\s*(?:import\s+\w+|from\s+\w+\s+import|def\s+\w+\s*\(|class\s+\w+.*:)|^#!/usr/bin/(?:env\s+)?python')),
    (Language.JAVASCRIPT, re.compile(r'\b(?:const|let|var)\s+\w+\s*=|require\s*\(|module\.exports\s*=|=>\s*\{')),
    (Language.TYPESCRIPT, re.compile(r':\s*(?:string|number|boolean|any|void)\s*[;=,\)]|interface\s+\w+\s*\{|<T\b')),
    (Language.JAVA,       re.compile(r'\bpublic\s+(?:class|interface|enum|record)\s+\w+|import\s+java\.')),
    (Language.CSHARP,     re.compile(r'\busing\s+System|namespace\s+\w+|public\s+(?:class|interface|enum|struct)\s+\w+')),
    (Language.PHP,        re.compile(r'<\?php|\$[a-zA-Z_]\w*\s*=')),
    (Language.GO,         re.compile(r'^package\s+\w+|^import\s*\(|^func\s+\w+')),
    (Language.RUBY,       re.compile(r'^\s*(?:require|require_relative)\s+["\']|^\s*def\s+\w+|^\s*class\s+\w+')),
    (Language.COBOL,      re.compile(r'\bIDENTIFICATION\s+DIVISION\b|\bPROGRAM-ID\b', re.IGNORECASE)),
    (Language.SHELL,      re.compile(r'^#!/(?:bin|usr/bin)/(?:ba)?sh|^#!/usr/bin/env\s+(?:ba)?sh')),
    (Language.BASH,       re.compile(r'^#!/usr/bin/env\s+bash|^#!/bin/bash')),
    (Language.POWERSHELL, re.compile(r'(?:Write-Host|Get-\w+|Set-\w+|Invoke-\w+|param\s*\(|\$PSVersion)', re.IGNORECASE)),
    (Language.SQL,        re.compile(r'^\s*(?:SELECT|INSERT\s+INTO|CREATE\s+TABLE|UPDATE\s+\w+\s+SET|DELETE\s+FROM)', re.IGNORECASE)),
    (Language.KOTLIN,     re.compile(r'\bfun\s+\w+\s*\(|^\s*val\s+\w+\s*=|^\s*var\s+\w+\s*=')),
    (Language.RUST,       re.compile(r'\bfn\s+\w+\s*\(|^\s*let\s+(?:mut\s+)?\w+\s*=|use\s+std::')),
    (Language.DART,       re.compile(r'\bvoid\s+main\s*\(|import\s+["\']package:|@override\b')),
    (Language.SWIFT,      re.compile(r'\bvar\s+\w+\s*:\s*\w+|import\s+Foundation|import\s+UIKit|func\s+\w+\s*\(')),
    (Language.DOCKERFILE, re.compile(r'^FROM\s+\S+|^RUN\s+|^CMD\s+\[|^ENTRYPOINT\s+\[|^EXPOSE\s+\d', re.MULTILINE)),
    (Language.TERRAFORM,  re.compile(r'^\s*(?:resource|provider|variable|module|output|data)\s+"', re.MULTILINE)),
    (Language.YAML,       re.compile(r'^---\s*$|^\s{2,}\w+:\s|\w+:\s+\|')),
    (Language.HTML,       re.compile(r'<!DOCTYPE\s+html|<html|<body|<head\s*>', re.IGNORECASE)),
    (Language.XML,        re.compile(r'<\?xml\s+version|<[a-zA-Z][\w:]*\s+[a-zA-Z][\w:]*=')),
    (Language.SOLIDITY,   re.compile(r'pragma\s+solidity|contract\s+\w+\s*\{|^import\s+["\'].*\.sol')),
    (Language.R,          re.compile(r'<-\s*function\s*\(|library\s*\(|require\s*\(\s*\w+\s*\)|ggplot\s*\(')),
    (Language.MATLAB,     re.compile(r'^function\s+\[?[\w,\s]+\]?\s*=\s*\w+\s*\(|^%\s+\w+')),
    (Language.LUA,        re.compile(r'^local\s+\w+|^function\s+\w+\s*\(|require\s*\s*["\']')),
    (Language.ELIXIR,     re.compile(r'^defmodule\s+\w+|^def\s+\w+\s*\(|^\s*use\s+\w+')),
    (Language.HASKELL,    re.compile(r'^module\s+\w+|^import\s+(?:qualified\s+)?\w+|^data\s+\w+')),
    (Language.ERLANG,     re.compile(r'^-module\s*\(|^-export\s*\(\[|^\s*->|:-\s*\w+')),
    (Language.GROOVY,     re.compile(r'^\s*def\s+\w+\s*\(|import\s+groovy\.|@\w+\s+class\s+')),
    (Language.GRAPHQL,    re.compile(r'^\s*(?:type|query|mutation|subscription|fragment|schema)\s+\w+\s*[\{(]', re.MULTILINE)),
    (Language.INK,        re.compile(r'#\[ink::contract\]|use\s+ink_lang|#\[ink\(')),
    (Language.COQ,        re.compile(r'^\s*(?:Theorem|Lemma|Definition|Inductive|Fixpoint)\s+\w+|^\s*Qed\.', re.MULTILINE)),
    (Language.NIX,        re.compile(r'\bwith\s+import\b|\bpkgs\.\w+|\{\s*stdenv|mkDerivation\b')),
    (Language.PUPPET,     re.compile(r'^\s*(?:class|define|node)\s+[\w:]+\s*[\({]|\bensure\s*=>', re.MULTILINE)),
]

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".obj", ".o",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".tar",
    ".gz", ".7z", ".rar", ".pyc", ".pyo", ".class", ".jar",
    ".war", ".ear", ".whl", ".egg", ".sb3", ".sb2",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".psd", ".ai", ".sketch",
}

SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__",
    ".pytest_cache", ".mypy_cache", "venv", ".venv", "env",
    "dist", "build", "target", "out", ".idea", ".vscode",
    "vendor", "third_party", "Pods", ".terraform",
    "coverage", ".coverage", "htmlcov", "site-packages",
    ".eggs", "bower_components", ".cache", "tmp", ".tmp",
}


def detect_language(file_path: str, content: str = "") -> Language:
    path = Path(file_path)
    name = path.name.lower()
    ext = path.suffix.lower()

    if ext in BINARY_EXTENSIONS:
        return Language.UNKNOWN

    # Arquivos sem extensão reconhecidos por nome
    if name in ("dockerfile", "containerfile"):
        return Language.DOCKERFILE
    if name in ("makefile", "gnumakefile", "bsdmakefile") or name.endswith(".mk") or name.endswith(".mak"):
        return Language.MAKEFILE
    if name == "cmakelists.txt":
        return Language.CMAKE
    if name in ("build", "build.bazel", "workspace", "workspace.bazel", ".bazelrc"):
        return Language.BAZEL
    if name.endswith(".gradle.kts") or name.endswith(".gradle"):
        return Language.GRADLE
    if name in ("berksfile", "metadata.rb") or name == "policyfile.rb":
        return Language.CHEF
    if name in ("jenkinsfile", "groovyfile"):
        return Language.GROOVY
    if name in (".bashrc", ".bash_profile", ".profile", ".zshrc"):
        return Language.BASH
    if name in ("gemfile", "rakefile", "guardfile", "vagrantfile"):
        return Language.RUBY
    if name in ("pipfile", "pyproject.toml"):
        return Language.PYTHON if name == "pyproject.toml" else Language.TOML
    if name in ("cargo.toml", "cargo.lock"):
        return Language.RUST if name == "cargo.toml" else Language.TOML
    if name in ("package.json", "tsconfig.json", "jsconfig.json", "package-lock.json"):
        return Language.JSON
    if name in ("go.mod", "go.sum"):
        return Language.GO
    if name == ".env" or name.startswith(".env."):
        return Language.INI

    if ext in EXTENSION_MAP:
        return EXTENSION_MAP[ext]

    if content:
        sample = "\n".join(content.splitlines()[:40])
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
    """Retorna (prefixo_linha_única, início_bloco, fim_bloco)."""
    c_style    = ("//", "/*", "*/")
    hash_style = ("#", "", "")
    sql_style  = ("--", "/*", "*/")
    html_style = ("", "<!--", "-->")

    return {
        Language.PYTHON:      hash_style,
        Language.RUBY:        hash_style,
        Language.SHELL:       hash_style,
        Language.BASH:        hash_style,
        Language.PERL:        hash_style,
        Language.R:           hash_style,
        Language.COFFEESCRIPT: hash_style,
        Language.POWERSHELL:  ("#", "<#", "#>"),
        Language.JAVASCRIPT:  c_style,
        Language.TYPESCRIPT:  c_style,
        Language.JAVA:        c_style,
        Language.CSHARP:      c_style,
        Language.GO:          c_style,
        Language.KOTLIN:      c_style,
        Language.SWIFT:       c_style,
        Language.RUST:        c_style,
        Language.SCALA:       c_style,
        Language.CPP:         c_style,
        Language.C:           c_style,
        Language.PHP:         c_style,
        Language.DART:        c_style,
        Language.GROOVY:      c_style,
        Language.VBNET:       ("'", "", ""),
        Language.HASKELL:     ("--", "{-", "-}"),
        Language.ERLANG:      ("%", "", ""),
        Language.ELIXIR:      ("#", "", ""),
        Language.LUA:         ("--", "--[[", "]]"),
        Language.MATLAB:      ("%", "%{", "%}"),
        Language.SQL:         sql_style,
        Language.PLSQL:       sql_style,
        Language.TSQL:        sql_style,
        Language.COBOL:       ("*", "", ""),
        Language.HTML:        html_style,
        Language.XML:         html_style,
        Language.SVG:         html_style,
        Language.CSS:         ("", "/*", "*/"),
        Language.SCSS:        ("//", "/*", "*/"),
        Language.SASS:        ("//", "", ""),
        Language.LESS:        ("//", "/*", "*/"),
        Language.YAML:        hash_style,
        Language.TOML:        hash_style,
        Language.INI:         (";", "", ""),
        Language.TERRAFORM:   ("//", "/*", "*/"),
        Language.SOLIDITY:    c_style,
        Language.VYPER:       hash_style,
        Language.MOVE:        ("//", "/*", "*/"),
        Language.CAIRO:       ("//", "/*", "*/"),
        Language.ASSEMBLY:    (";", "", ""),
        Language.FORTRAN:     ("!", "", ""),
        Language.ADA:         ("--", "", ""),
        Language.PASCAL:      ("//", "{", "}"),
        Language.SMALLTALK:   ("", '"', '"'),
    }.get(language, ("//", "/*", "*/"))
