"""
Interface de linha de comando e API REST para o cofre de segredos (vault.py).

Senha mestre: lida da variável de ambiente VULNVAULT_PASSWORD; se ausente,
solicitada interativamente via getpass (não ecoa no terminal).
"""
from __future__ import annotations
import os
import sys
import json
import getpass
from typing import Optional

from analyzer.vault import SecretVault, VaultError

try:
    from analyzer.reporter import console
except Exception:  # fallback mínimo
    class _C:
        def print(self, *a, **k):
            print(*[str(x) for x in a])
    console = _C()


# ── Helpers ────────────────────────────────────────────────────────────────

def _master_password(confirm: bool = False, prompt: str = "Senha mestre: ") -> str:
    env = os.environ.get("VULNVAULT_PASSWORD")
    if env:
        return env
    if not sys.stdin.isatty():
        raise VaultError(
            "Senha mestre necessária: defina VULNVAULT_PASSWORD ou execute em terminal interativo."
        )
    pwd = getpass.getpass(prompt)
    if confirm:
        if pwd != getpass.getpass("Confirme a senha: "):
            raise VaultError("As senhas não conferem.")
    return pwd


# ── CLI ──────────────────────────────────────────────────────────────────────

def run_vault_cli(args) -> int:
    """Despacha as ações de vault da CLI. Retorna o código de saída."""
    path = args.vault
    try:
        if args.vault_init:
            pwd = _master_password(confirm=True, prompt="Nova senha mestre: ")
            SecretVault.create(path, pwd)
            console.print(f"[bold bright_green]✔[/] Cofre criado em [cyan]{path}[/cyan]")
            return 0

        if args.vault_set:
            pwd   = _master_password()
            vault = SecretVault.open(path, pwd)
            value = args.vault_value
            if value is None:
                if not sys.stdin.isatty():
                    value = sys.stdin.read().rstrip("\n")
                else:
                    value = getpass.getpass(f"Valor de '{args.vault_set}': ")
            vault.set_secret(args.vault_set, value)
            vault.save()
            console.print(f"[bold bright_green]✔[/] Segredo '[cyan]{args.vault_set}[/cyan]' armazenado.")
            return 0

        if args.vault_get:
            pwd   = _master_password()
            vault = SecretVault.open(path, pwd)
            # Valor puro no stdout (para uso em scripts/pipes)
            sys.stdout.write(vault.get_secret(args.vault_get) + "\n")
            return 0

        if args.vault_list:
            pwd   = _master_password()
            vault = SecretVault.open(path, pwd)
            names = vault.list_secrets()
            if not names:
                console.print("[dim](cofre vazio)[/]")
            else:
                console.print(f"[bold bright_white]{len(names)} segredo(s):[/]")
                for n in names:
                    console.print(f"  [bright_green]•[/] {n}")
            return 0

        if args.vault_delete:
            pwd   = _master_password()
            vault = SecretVault.open(path, pwd)
            vault.delete_secret(args.vault_delete)
            vault.save()
            console.print(f"[bold bright_yellow]✔[/] Segredo '[cyan]{args.vault_delete}[/cyan]' removido.")
            return 0

        if args.vault_passwd:
            pwd   = _master_password(prompt="Senha mestre atual: ")
            vault = SecretVault.open(path, pwd)
            new   = _master_password(confirm=True, prompt="Nova senha mestre: ") \
                    if not os.environ.get("VULNVAULT_NEW_PASSWORD") \
                    else os.environ["VULNVAULT_NEW_PASSWORD"]
            vault.change_password(new)
            vault.save()
            console.print("[bold bright_green]✔[/] Senha mestre alterada.")
            return 0

        if args.vault_serve:
            return run_vault_server(path, args.vault_serve)

        console.print(
            "[yellow]Nenhuma ação de vault especificada.[/] Use uma de: "
            "--vault-init, --vault-set, --vault-get, --vault-list, --vault-delete, "
            "--vault-passwd, --vault-serve."
        )
        return 2

    except VaultError as e:
        console.print(f"[bold red]Erro de cofre:[/] {e}")
        return 2


# ── API REST ───────────────────────────────────────────────────────────────

def run_vault_server(path: str, port: int) -> int:
    """
    Sobe uma API REST mínima (stdlib http.server) sobre um cofre aberto em memória.

    Autenticação: header `X-Vault-Token` deve conter a senha mestre.
    Endpoints:
        GET    /health                 → status
        GET    /secrets                → lista de nomes
        GET    /secrets/<nome>         → valor do segredo
        POST   /secrets/<nome>  {"value": "..."}  → cria/atualiza
        DELETE /secrets/<nome>         → remove
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer

    master = os.environ.get("VULNVAULT_PASSWORD")
    if not master:
        if sys.stdin.isatty():
            master = getpass.getpass("Senha mestre (para abrir o cofre): ")
        else:
            console.print("[bold red]Erro:[/] defina VULNVAULT_PASSWORD para o modo servidor.")
            return 2
    try:
        vault = SecretVault.open(path, master)
    except VaultError as e:
        console.print(f"[bold red]Erro ao abrir cofre:[/] {e}")
        return 2

    console.print(f"[bold bright_cyan]🔐 Vault REST API → http://0.0.0.0:{port}[/]")
    console.print("[dim]Auth: header X-Vault-Token: <senha mestre>  •  Ctrl+C para sair[/dim]")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silencia log padrão
            pass

        def _send(self, code: int, data: dict) -> None:
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authed(self) -> bool:
            import hmac as _hmac
            token = self.headers.get("X-Vault-Token", "")
            return _hmac.compare_digest(token, master)

        def _name(self) -> Optional[str]:
            parts = self.path.strip("/").split("/")
            if len(parts) == 2 and parts[0] == "secrets":
                from urllib.parse import unquote
                return unquote(parts[1])
            return None

        def do_GET(self):
            if self.path == "/health":
                self._send(200, {"status": "ok", "secrets": len(vault.list_secrets())})
                return
            if not self._authed():
                self._send(401, {"error": "Token inválido"})
                return
            if self.path == "/secrets":
                self._send(200, {"names": vault.list_secrets()})
                return
            name = self._name()
            if name is not None:
                try:
                    self._send(200, {"name": name, "value": vault.get_secret(name)})
                except VaultError as e:
                    self._send(404, {"error": str(e)})
                return
            self._send(404, {"error": "Not found"})

        def do_POST(self):
            if not self._authed():
                self._send(401, {"error": "Token inválido"})
                return
            name = self._name()
            if name is None:
                self._send(404, {"error": "Not found"})
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                value = body["value"]
            except Exception:
                self._send(400, {"error": "Corpo JSON inválido; esperado {\"value\": ...}"})
                return
            vault.set_secret(name, str(value))
            vault.save()
            self._send(200, {"ok": True, "name": name})

        def do_DELETE(self):
            if not self._authed():
                self._send(401, {"error": "Token inválido"})
                return
            name = self._name()
            if name is None:
                self._send(404, {"error": "Not found"})
                return
            try:
                vault.delete_secret(name)
                vault.save()
                self._send(200, {"ok": True, "deleted": name})
            except VaultError as e:
                self._send(404, {"error": str(e)})

    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
    return 0
