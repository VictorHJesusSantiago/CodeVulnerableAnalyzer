"""
Validação ATIVA de credenciais — opt-in, requer rede, NUNCA executado por
padrão. Faz uma chamada mínima e não-destrutiva à API do provedor para
confirmar se a credencial ainda está viva (retorna VALID/INVALID/UNKNOWN em
caso de erro de rede — nunca assume "válido" silenciosamente).

Implementações via stdlib apenas (urllib + hmac + hashlib para AWS SigV4 —
não há chamada a boto3/requests, nada de dependência nova).

Aviso ético: só use isto em credenciais que você tem autorização para testar
(seu próprio ambiente / engajamento de pentest autorizado). Uma chamada de
validação é, por definição, uma tentativa de autenticação real no provedor.
"""
from __future__ import annotations
import datetime
import hashlib
import hmac
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

_TIMEOUT = 8.0


@dataclass
class ValidationResult:
    provider: str
    status: str        # VALID | INVALID | UNKNOWN
    detail: str


def _get(url: str, headers: dict) -> ValidationResult:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return ValidationResult("", "VALID", f"HTTP {resp.status}")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return ValidationResult("", "INVALID", f"HTTP {e.code}")
        return ValidationResult("", "UNKNOWN", f"HTTP {e.code}")
    except Exception as e:
        return ValidationResult("", "UNKNOWN", f"Erro de rede: {e}")


def validate_github_token(token: str) -> ValidationResult:
    r = _get("https://api.github.com/user", {"Authorization": f"Bearer {token}", "User-Agent": "vulnscan"})
    r.provider = "GitHub"
    return r


def validate_slack_token(token: str) -> ValidationResult:
    req = urllib.request.Request(
        "https://slack.com/api/auth.test", method="POST",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            ok = bool(body.get("ok"))
            return ValidationResult("Slack", "VALID" if ok else "INVALID", body.get("error", "ok"))
    except Exception as e:
        return ValidationResult("Slack", "UNKNOWN", f"Erro de rede: {e}")


def validate_stripe_key(secret_key: str) -> ValidationResult:
    import base64
    auth = base64.b64encode(f"{secret_key}:".encode()).decode()
    r = _get("https://api.stripe.com/v1/balance", {"Authorization": f"Basic {auth}"})
    r.provider = "Stripe"
    return r


def validate_twilio_credentials(account_sid: str, auth_token: str) -> ValidationResult:
    import base64
    auth = base64.b64encode(f"{account_sid}:{auth_token}".encode()).decode()
    url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}.json"
    r = _get(url, {"Authorization": f"Basic {auth}"})
    r.provider = "Twilio"
    return r


def validate_sendgrid_key(api_key: str) -> ValidationResult:
    r = _get("https://api.sendgrid.com/v3/scopes", {"Authorization": f"Bearer {api_key}"})
    r.provider = "SendGrid"
    return r


def validate_npm_token(token: str) -> ValidationResult:
    r = _get("https://registry.npmjs.org/-/whoami", {"Authorization": f"Bearer {token}"})
    r.provider = "npm"
    return r


def validate_openai_key(api_key: str) -> ValidationResult:
    r = _get("https://api.openai.com/v1/models", {"Authorization": f"Bearer {api_key}"})
    r.provider = "OpenAI"
    return r


def validate_anthropic_key(api_key: str) -> ValidationResult:
    r = _get("https://api.anthropic.com/v1/models", {
        "x-api-key": api_key, "anthropic-version": "2023-06-01",
    })
    r.provider = "Anthropic"
    return r


# ════════════════════════════════════════════════════════════════════════════
#  AWS Signature Version 4 (implementação real via hmac/hashlib, sem boto3)
#  Usada para chamar sts:GetCallerIdentity — a forma padrão e não-destrutiva
#  de verificar se uma credencial AWS é válida.
# ════════════════════════════════════════════════════════════════════════════

def _sigv4_sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _sigv4_signing_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _sigv4_sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _sigv4_sign(k_date, region)
    k_service = _sigv4_sign(k_region, service)
    k_signing = _sigv4_sign(k_service, "aws4_request")
    return k_signing


def build_sigv4_headers(
    access_key: str, secret_key: str, region: str = "us-east-1",
    service: str = "sts", session_token: Optional[str] = None,
) -> dict:
    """Constrói os headers assinados (Signature V4) para uma requisição
    GET https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15
    Implementação fiel ao algoritmo documentado pela AWS (canonical request →
    string to sign → signing key → assinatura HMAC-SHA256 em cadeia)."""
    method = "GET"
    host = f"{service}.amazonaws.com"
    endpoint_path = "/"
    query_string = "Action=GetCallerIdentity&Version=2011-06-15"

    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    payload_hash = hashlib.sha256(b"").hexdigest()

    # Nomes de headers assinados devem estar em ordem alfabética (exigência SigV4)
    if session_token:
        canonical_headers = (
            f"host:{host}\n"
            f"x-amz-date:{amz_date}\n"
            f"x-amz-security-token:{session_token}\n"
        )
        signed_headers = "host;x-amz-date;x-amz-security-token"
    else:
        canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
        signed_headers = "host;x-amz-date"

    canonical_request = "\n".join([
        method, endpoint_path, query_string,
        canonical_headers, signed_headers, payload_hash,
    ])

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        algorithm, amz_date, credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])

    signing_key = _sigv4_signing_key(secret_key, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization_header = (
        f"{algorithm} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "x-amz-date": amz_date,
        "Authorization": authorization_header,
        "Host": host,
    }
    if session_token:
        headers["x-amz-security-token"] = session_token
    return headers


def validate_aws_credentials(
    access_key: str, secret_key: str, region: str = "us-east-1",
    session_token: Optional[str] = None,
) -> ValidationResult:
    """Valida credenciais AWS via sts:GetCallerIdentity (não-destrutivo,
    não requer permissões IAM além do princípio básico de autenticação)."""
    headers = build_sigv4_headers(access_key, secret_key, region, "sts", session_token)
    url = "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
            return ValidationResult("AWS", "VALID", body[:200])
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        if e.code in (401, 403) or "InvalidClientTokenId" in body or "SignatureDoesNotMatch" in body:
            return ValidationResult("AWS", "INVALID", body[:200])
        return ValidationResult("AWS", "UNKNOWN", f"HTTP {e.code}: {body[:150]}")
    except Exception as e:
        return ValidationResult("AWS", "UNKNOWN", f"Erro de rede: {e}")


# ── Dispatcher genérico ────────────────────────────────────────────────────────

_VALIDATORS = {
    "GitHub": lambda v: validate_github_token(v),
    "Slack": lambda v: validate_slack_token(v),
    "Stripe": lambda v: validate_stripe_key(v),
    "SendGrid": lambda v: validate_sendgrid_key(v),
    "npm": lambda v: validate_npm_token(v),
    "OpenAI": lambda v: validate_openai_key(v),
    "Anthropic": lambda v: validate_anthropic_key(v),
}


def validate_by_provider(provider: str, matched_value: str) -> Optional[ValidationResult]:
    """Roteia para o validador apropriado, se existir suporte para o provedor."""
    fn = _VALIDATORS.get(provider)
    if fn is None:
        return None
    return fn(matched_value)
