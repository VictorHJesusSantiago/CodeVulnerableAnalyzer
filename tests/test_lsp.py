"""Testes do servidor LSP (analyzer.lsp)."""

from __future__ import annotations

import io

from analyzer.lsp import LSPServer


def _server_capturing():
    """Servidor com _send substituído por captura em lista."""
    srv = LSPServer()
    sent: list[dict] = []
    srv._send = sent.append  # type: ignore[assignment]
    return srv, sent


def test_initialize_reports_capabilities():
    srv, sent = _server_capturing()
    srv._handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert len(sent) == 1
    result = sent[0]["result"]
    assert result["serverInfo"]["name"] == "vulnscan-lsp"
    assert "textDocumentSync" in result["capabilities"]


def test_shutdown_and_exit_stop_running():
    srv, sent = _server_capturing()
    srv._handle({"id": 2, "method": "shutdown"})
    assert srv._running is False
    assert sent[-1] == {"jsonrpc": "2.0", "id": 2, "result": None}
    srv._running = True
    srv._handle({"method": "exit"})
    assert srv._running is False


def test_did_open_stores_document():
    srv, _ = _server_capturing()
    srv._publish_diagnostics = lambda uri, text: None  # type: ignore[assignment]
    srv._handle(
        {
            "method": "textDocument/didOpen",
            "params": {"textDocument": {"uri": "file:///x.py", "text": "print(1)"}},
        }
    )
    assert srv._open_docs["file:///x.py"] == "print(1)"


def test_did_change_and_close():
    srv, sent = _server_capturing()
    srv._publish_diagnostics = lambda uri, text: None  # type: ignore[assignment]
    srv._open_docs["file:///x.py"] = "old"
    srv._handle(
        {
            "method": "textDocument/didChange",
            "params": {"textDocument": {"uri": "file:///x.py"}, "contentChanges": [{"text": "new content"}]},
        }
    )
    assert srv._open_docs["file:///x.py"] == "new content"

    srv._handle(
        {
            "method": "textDocument/didClose",
            "params": {"textDocument": {"uri": "file:///x.py"}},
        }
    )
    assert "file:///x.py" not in srv._open_docs
    assert sent[-1]["params"] == {"uri": "file:///x.py", "diagnostics": []}


def test_unknown_method_with_id_replies_null():
    srv, sent = _server_capturing()
    srv._handle({"id": 9, "method": "textDocument/hover", "params": {}})
    assert sent[-1] == {"jsonrpc": "2.0", "id": 9, "result": None}


def test_code_action_returns_list():
    srv, sent = _server_capturing()
    srv._open_docs["file:///x.py"] = "eval(user_input)"
    srv._handle(
        {
            "id": 5,
            "method": "textDocument/codeAction",
            "params": {
                "textDocument": {"uri": "file:///x.py"},
                "context": {"diagnostics": [{"code": "PY-EVAL-001", "range": {"start": {"line": 0, "character": 0}}}]},
            },
        }
    )
    assert isinstance(sent[-1]["result"], list)


def test_publish_diagnostics_maps_vulnerabilities(tmp_path):
    srv, sent = _server_capturing()
    f = tmp_path / "vuln.py"
    f.write_text("import os\nos.system('rm ' + input())\n", encoding="utf-8")
    uri = "file:///" + str(f).replace("\\", "/")
    srv._publish_diagnostics(uri, f.read_text(encoding="utf-8"))
    assert sent, "deveria emitir uma notificação publishDiagnostics"
    note = sent[-1]
    assert note["method"] == "textDocument/publishDiagnostics"
    diags = note["params"]["diagnostics"]
    assert diags, "arquivo vulnerável deveria gerar diagnósticos"
    assert all("range" in d and "message" in d for d in diags)


def test_read_message_parses_framed_content():
    srv = LSPServer()
    payload = b'{"jsonrpc":"2.0","id":1,"method":"initialize"}'
    framed = b"Content-Length: %d\r\n\r\n%s" % (len(payload), payload)
    srv_stdin = io.BytesIO(framed)

    class _Stdin:
        buffer = srv_stdin

    import analyzer.lsp as lsp_mod

    orig = lsp_mod.sys.stdin
    lsp_mod.sys.stdin = _Stdin()  # type: ignore[assignment]
    try:
        msg = srv._read_message()
    finally:
        lsp_mod.sys.stdin = orig
    assert msg == {"jsonrpc": "2.0", "id": 1, "method": "initialize"}


def test_run_loop_processes_then_stops():
    srv, sent = _server_capturing()
    msgs = iter([{"id": 1, "method": "initialize", "params": {}}, None])
    srv._read_message = lambda: next(msgs)  # type: ignore[assignment]
    srv.run()
    assert any("result" in m and "capabilities" in m.get("result", {}) for m in sent)
