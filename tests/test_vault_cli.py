"""Testes da CLI do cofre e da API REST (analyzer.vault_cli)."""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest

from analyzer.vault_cli import run_vault_cli, run_vault_server

_PWD = "senha-mestre-forte-123"


def _args(path, **over):
    base = dict(
        vault=str(path),
        vault_init=False,
        vault_set=None,
        vault_get=None,
        vault_list=False,
        vault_delete=None,
        vault_passwd=False,
        vault_serve=None,
        vault_value=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


@pytest.fixture
def vault_env(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNVAULT_PASSWORD", _PWD)
    return tmp_path / "cofre.vault"


def test_cli_full_lifecycle(vault_env, capsys):
    path = vault_env
    assert run_vault_cli(_args(path, vault_init=True)) == 0
    assert path.exists()

    assert run_vault_cli(_args(path, vault_set="api_key", vault_value="s3cr3t-value")) == 0
    assert run_vault_cli(_args(path, vault_list=True)) == 0

    capsys.readouterr()  # limpa
    assert run_vault_cli(_args(path, vault_get="api_key")) == 0
    out = capsys.readouterr().out
    assert "s3cr3t-value" in out

    assert run_vault_cli(_args(path, vault_delete="api_key")) == 0
    assert run_vault_cli(_args(path, vault_list=True)) == 0


def test_cli_no_action_returns_2(vault_env):
    run_vault_cli(_args(vault_env, vault_init=True))
    assert run_vault_cli(_args(vault_env)) == 2


def test_cli_get_missing_secret_returns_2(vault_env):
    run_vault_cli(_args(vault_env, vault_init=True))
    assert run_vault_cli(_args(vault_env, vault_get="inexistente")) == 2


def test_cli_change_password(vault_env, monkeypatch):
    run_vault_cli(_args(vault_env, vault_init=True))
    run_vault_cli(_args(vault_env, vault_set="k", vault_value="v"))
    monkeypatch.setenv("VULNVAULT_NEW_PASSWORD", "nova-senha-mestre-456")
    assert run_vault_cli(_args(vault_env, vault_passwd=True)) == 0
    # Reabrir com a nova senha deve funcionar
    monkeypatch.setenv("VULNVAULT_PASSWORD", "nova-senha-mestre-456")
    assert run_vault_cli(_args(vault_env, vault_get="k")) == 0


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _req(method, url, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if token:
        r.add_header("X-Vault-Token", token)
    if data:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=3) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_rest_server_roundtrip(vault_env, monkeypatch):
    # Cofre precisa existir para o servidor abrir
    run_vault_cli(_args(vault_env, vault_init=True))
    port = _free_port()
    t = threading.Thread(target=run_vault_server, args=(str(vault_env), port), daemon=True)
    t.start()

    base = f"http://127.0.0.1:{port}"
    # Espera o servidor subir
    up = False
    for _ in range(40):
        try:
            code, _ = _req("GET", base + "/health")
            up = code == 200
            break
        except Exception:
            time.sleep(0.05)
    assert up, "servidor REST não subiu"

    # Sem token → 401
    code, _ = _req("GET", base + "/secrets")
    assert code == 401

    # POST autenticado cria segredo
    code, body = _req("POST", base + "/secrets/db", token=_PWD, body={"value": "p@ss"})
    assert code == 200 and body["ok"] is True

    # GET recupera
    code, body = _req("GET", base + "/secrets/db", token=_PWD)
    assert code == 200 and body["value"] == "p@ss"

    # Lista
    code, body = _req("GET", base + "/secrets", token=_PWD)
    assert "db" in body["names"]

    # DELETE remove
    code, body = _req("DELETE", base + "/secrets/db", token=_PWD)
    assert code == 200 and body["deleted"] == "db"

    # GET inexistente → 404
    code, _ = _req("GET", base + "/secrets/db", token=_PWD)
    assert code == 404
