"""Estado persistível de UX: temas, bookmarks, supressões reversíveis e playground."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class UXState:
    theme: str = "dark"
    bookmarks: set[str] = field(default_factory=set)
    suppressions: list[dict[str, Any]] = field(default_factory=list)
    undo_stack: list[dict[str, Any]] = field(default_factory=list)

    def bookmark(self, finding_id: str) -> None:
        self.bookmarks.add(finding_id)

    def suppress(self, rule: str, file: str, reason: str) -> None:
        item = {"rule": rule, "file": file, "reason": reason}
        self.suppressions.append(item)
        self.undo_stack.append(item)

    def undo_suppression(self) -> dict[str, Any] | None:
        if not self.undo_stack:
            return None
        item = self.undo_stack.pop()
        if item in self.suppressions:
            self.suppressions.remove(item)
        return item

    def serialize(self) -> dict[str, Any]:
        return {"theme": self.theme, "bookmarks": sorted(self.bookmarks), "suppressions": self.suppressions}


def regex_playground(pattern: str, text: str, flags: int = 0) -> list[dict[str, Any]]:
    return [
        {"match": m.group(0), "start": m.start(), "end": m.end(), "groups": m.groups()}
        for m in re.finditer(pattern, text, flags)
    ]


def ast_playground(source: str) -> dict[str, Any]:
    tree = ast.parse(source)
    return {
        "nodes": sum(1 for _ in ast.walk(tree)),
        "functions": [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))],
        "dump": ast.dump(tree, indent=2),
    }
