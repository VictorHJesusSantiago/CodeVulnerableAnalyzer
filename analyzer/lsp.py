"""Language Server Protocol (LSP) JSON-RPC 2.0 sobre stdio."""
from __future__ import annotations
import json
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional


_SEV_MAP = {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class LSPServer:
    """Servidor LSP mínimo: initialize, didOpen, didChange, publishDiagnostics."""

    def __init__(self):
        self._running    = True
        self._open_docs: Dict[str, str] = {}
        self._lock       = threading.Lock()

    # ── Transport ────────────────────────────────────────────────────────────

    def _read_message(self) -> Optional[dict]:
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = sys.stdin.buffer.read(1)
            if not chunk:
                return None
            header += chunk
        length = 0
        for line in header.decode("utf-8", errors="replace").split("\r\n"):
            if line.lower().startswith("content-length:"):
                try:
                    length = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
        if length == 0:
            return None
        body = sys.stdin.buffer.read(length)
        try:
            return json.loads(body.decode("utf-8"))
        except Exception:
            return None

    def _send(self, obj: dict) -> None:
        body   = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        with self._lock:
            sys.stdout.buffer.write(header + body)
            sys.stdout.buffer.flush()

    def _reply(self, req_id: Any, result: Any) -> None:
        self._send({"jsonrpc": "2.0", "id": req_id, "result": result})

    def _notify(self, method: str, params: Any) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def _error(self, req_id: Any, code: int, message: str) -> None:
        self._send({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})

    # ── Diagnósticos ─────────────────────────────────────────────────────────

    def _publish_diagnostics(self, uri: str, _content: str) -> None:
        file_path = uri.replace("file:///", "/").replace("file://", "/")
        if sys.platform == "win32":
            file_path = file_path.lstrip("/")

        try:
            from analyzer.engine import ScanEngine
            from analyzer.models import Severity
            engine = ScanEngine(min_severity=Severity.INFO)
            result = engine.scan_file(file_path)
        except Exception:
            self._notify("textDocument/publishDiagnostics", {"uri": uri, "diagnostics": []})
            return

        diagnostics = []
        for v in result.vulnerabilities:
            ln = max(0, v.line_number - 1)
            diagnostics.append({
                "range": {
                    "start": {"line": ln, "character": 0},
                    "end":   {"line": ln, "character": 999},
                },
                "severity": _SEV_MAP.get(v.severity.name, 3),
                "code":     v.rule_id,
                "source":   "vulnscan",
                "message":  f"[{v.rule_id}] {v.name}: {v.description[:150]}",
                "tags":     [1] if v.in_comment else [],
            })
        self._notify("textDocument/publishDiagnostics", {"uri": uri, "diagnostics": diagnostics})

    # ── Handler de mensagens ──────────────────────────────────────────────────

    def _handle(self, msg: dict) -> None:
        method = msg.get("method", "")
        params = msg.get("params") or {}
        req_id = msg.get("id")

        if method == "initialize":
            self._reply(req_id, {
                "capabilities": {
                    "textDocumentSync": 1,
                    "codeActionProvider": {
                        "codeActionKinds": ["quickfix"],
                        "resolveProvider": False,
                    },
                    "diagnosticProvider": {
                        "interFileDependencies": False,
                        "workspaceDiagnostics": False,
                    },
                },
                "serverInfo": {"name": "vulnscan-lsp", "version": "1.0.0"},
            })
        elif method == "initialized":
            pass
        elif method == "shutdown":
            self._reply(req_id, None)
            self._running = False
        elif method == "exit":
            self._running = False
        elif method == "textDocument/didOpen":
            doc  = params.get("textDocument", {})
            uri  = doc.get("uri", "")
            text = doc.get("text", "")
            self._open_docs[uri] = text
            threading.Thread(
                target=self._publish_diagnostics, args=(uri, text), daemon=True
            ).start()
        elif method == "textDocument/didChange":
            doc     = params.get("textDocument", {})
            uri     = doc.get("uri", "")
            changes = params.get("contentChanges", [])
            if changes:
                text = changes[-1].get("text", "")
                self._open_docs[uri] = text
                threading.Thread(
                    target=self._publish_diagnostics, args=(uri, text), daemon=True
                ).start()
        elif method == "textDocument/didSave":
            doc  = params.get("textDocument", {})
            uri  = doc.get("uri", "")
            text = self._open_docs.get(uri, "")
            threading.Thread(
                target=self._publish_diagnostics, args=(uri, text), daemon=True
            ).start()
        elif method == "textDocument/didClose":
            uri = (params.get("textDocument") or {}).get("uri", "")
            self._open_docs.pop(uri, None)
            self._notify("textDocument/publishDiagnostics", {"uri": uri, "diagnostics": []})
        elif method == "textDocument/codeAction":
            uri = (params.get("textDocument") or {}).get("uri", "")
            source = self._open_docs.get(uri, "")
            findings = []
            for diagnostic in (params.get("context") or {}).get("diagnostics", []):
                start = (diagnostic.get("range") or {}).get("start", {})
                findings.append({
                    "rule_id": str(diagnostic.get("code", "")),
                    "line_number": int(start.get("line", 0)) + 1,
                })
            try:
                from analyzer.remediation import lsp_code_actions
                self._reply(req_id, lsp_code_actions(uri, source, findings))
            except Exception:
                self._reply(req_id, [])
        elif req_id is not None:
            self._reply(req_id, None)

    # ── Loop principal ────────────────────────────────────────────────────────

    def run(self) -> None:
        while self._running:
            msg = self._read_message()
            if msg is None:
                break
            try:
                self._handle(msg)
            except Exception:
                pass


def run_lsp() -> None:
    """Ponto de entrada para o servidor LSP."""
    LSPServer().run()
