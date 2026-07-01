"""
Pré-processador de macros C/C++ — real, mas com escopo declarado:
  - #define NAME VALUE                (macro objeto)
  - #define NAME(a,b,...) BODY        (macro função, substituição textual
    simples de parâmetros, uma linha)
  - #undef NAME
  - #ifdef / #ifndef / #else / #endif (avaliação de nomes definidos)
  - #if defined(X) / #if 0 / #if 1    (casos comuns)

Preserva a contagem de linhas do arquivo original (troca linhas removidas
por linhas em branco) para que os números de linha reportados pelo engine
continuem corretos após a expansão.

Limitações declaradas: não implementa token pasting (##), stringizing (#),
macros recursivas, nem expansão de macro função que se espalha por várias
linhas — essas ficam sem expansão (documentado, não fingido).
"""
from __future__ import annotations
import re
from typing import Dict, List, Optional, Tuple

_DEFINE_OBJ_RE  = re.compile(r'^\s*#\s*define\s+(\w+)\s+(.+?)\s*$')
_DEFINE_FUNC_RE = re.compile(r'^\s*#\s*define\s+(\w+)\s*\(([^)]*)\)\s+(.+?)\s*$')
_UNDEF_RE       = re.compile(r'^\s*#\s*undef\s+(\w+)\s*$')
_IFDEF_RE       = re.compile(r'^\s*#\s*ifdef\s+(\w+)\s*$')
_IFNDEF_RE      = re.compile(r'^\s*#\s*ifndef\s+(\w+)\s*$')
_IF_DEFINED_RE  = re.compile(r'^\s*#\s*if\s+defined\s*\(\s*(\w+)\s*\)\s*$')
_IF_LITERAL_RE  = re.compile(r'^\s*#\s*if\s+([01])\s*$')
_ELSE_RE        = re.compile(r'^\s*#\s*else\s*$')
_ENDIF_RE       = re.compile(r'^\s*#\s*endif\s*$')

_MAX_EXPAND_DEPTH = 5


class Macro:
    __slots__ = ("name", "params", "body")

    def __init__(self, name: str, params: Optional[List[str]], body: str):
        self.name = name
        self.params = params  # None = macro objeto; [] ou [p1,...] = macro função
        self.body = body


def _split_args(s: str) -> List[str]:
    """Divide argumentos de uma chamada de macro respeitando parênteses aninhados."""
    args: List[str] = []
    depth = 0
    current = ""
    for ch in s:
        if ch == "(" :
            depth += 1
            current += ch
        elif ch == ")":
            depth -= 1
            current += ch
        elif ch == "," and depth == 0:
            args.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        args.append(current.strip())
    return args


def _expand_line(line: str, macros: Dict[str, Macro], depth: int = 0) -> str:
    if depth >= _MAX_EXPAND_DEPTH:
        return line

    changed = False
    for name, macro in macros.items():
        if macro.params is None:
            pattern = re.compile(r'\b' + re.escape(name) + r'\b')
            if pattern.search(line):
                line = pattern.sub(macro.body, line)
                changed = True
        else:
            pattern = re.compile(r'\b' + re.escape(name) + r'\s*\(')
            m = pattern.search(line)
            if not m:
                continue
            start = m.end()
            depth_paren = 1
            i = start
            while i < len(line) and depth_paren > 0:
                if line[i] == "(":
                    depth_paren += 1
                elif line[i] == ")":
                    depth_paren -= 1
                i += 1
            if depth_paren != 0:
                continue  # chamada multi-linha: não suportado, deixa como está
            call_args_str = line[start:i - 1]
            call_args = _split_args(call_args_str)
            body = macro.body
            for pname, pval in zip(macro.params, call_args):
                body = re.sub(r'\b' + re.escape(pname) + r'\b', pval, body)
            line = line[:m.start()] + body + line[i:]
            changed = True

    if changed:
        return _expand_line(line, macros, depth + 1)
    return line


def expand_macros(content: str) -> str:
    """Expande macros #define e resolve blocos #ifdef/#ifndef/#if, preservando
    a contagem de linhas (linhas de diretiva e blocos não incluídos viram
    linhas em branco)."""
    lines = content.splitlines()
    macros: Dict[str, Macro] = {}
    out: List[str] = []

    # Pilha de condicionais: cada item é (currently_active, branch_taken_before)
    cond_stack: List[Tuple[bool, bool]] = []

    def _active() -> bool:
        return all(c[0] for c in cond_stack)

    for line in lines:
        stripped = line.strip()

        m = _IFDEF_RE.match(stripped)
        if m:
            active = _active() and (m.group(1) in macros)
            cond_stack.append((active, active))
            out.append("")
            continue
        m = _IFNDEF_RE.match(stripped)
        if m:
            active = _active() and (m.group(1) not in macros)
            cond_stack.append((active, active))
            out.append("")
            continue
        m = _IF_DEFINED_RE.match(stripped)
        if m:
            active = _active() and (m.group(1) in macros)
            cond_stack.append((active, active))
            out.append("")
            continue
        m = _IF_LITERAL_RE.match(stripped)
        if m:
            active = _active() and (m.group(1) == "1")
            cond_stack.append((active, active))
            out.append("")
            continue
        if _ELSE_RE.match(stripped):
            if cond_stack:
                parent_active = all(c[0] for c in cond_stack[:-1]) if len(cond_stack) > 1 else True
                was_taken = cond_stack[-1][1]
                new_active = parent_active and not was_taken
                cond_stack[-1] = (new_active, was_taken or new_active)
            out.append("")
            continue
        if _ENDIF_RE.match(stripped):
            if cond_stack:
                cond_stack.pop()
            out.append("")
            continue

        if not _active():
            out.append("")
            continue

        m = _UNDEF_RE.match(stripped)
        if m:
            macros.pop(m.group(1), None)
            out.append("")
            continue

        m = _DEFINE_FUNC_RE.match(stripped)
        if m:
            name, params_str, body = m.groups()
            params = [p.strip() for p in params_str.split(",") if p.strip()]
            macros[name] = Macro(name, params, body)
            out.append("")
            continue

        m = _DEFINE_OBJ_RE.match(stripped)
        if m:
            name, value = m.groups()
            macros[name] = Macro(name, None, value)
            out.append("")
            continue

        out.append(_expand_line(line, macros) if macros else line)

    return "\n".join(out)
