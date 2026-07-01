"""
Detecção de material de chave privada (RSA/EC/Ed25519/DSA/PGP/SSH) via
estrutura real PEM + parser DER mínimo (stdlib puro: base64 + struct).

Diferente de apenas casar "-----BEGIN ... PRIVATE KEY-----" por regex, aqui
o conteúdo base64 do bloco PEM é decodificado e parseado como DER (formato
TLV — Tag/Length/Value) para confirmar que é uma SEQUENCE ASN.1 válida,
reduzindo falsos positivos de blocos PEM corrompidos/truncados e permitindo
extrair metadados reais (ex.: tamanho do módulo RSA em bits).

Escopo declarado: implementa um parser DER simplificado o bastante para
navegar SEQUENCE/INTEGER/OCTET STRING/BIT STRING/OBJECT IDENTIFIER — não é
um parser ASN.1 genérico completo (não cobre todos os tipos/tags exóticos).
"""
from __future__ import annotations
import base64
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class KeyFinding:
    file_path: str
    line_number: int
    key_type: str            # RSA | EC | Ed25519 | DSA | OPENSSH | PGP | SSH_PUBLIC | UNKNOWN
    is_encrypted: bool
    bits: Optional[int]       # tamanho estimado em bits (quando aplicável, ex. RSA)
    valid_der: bool
    header: str


_PEM_BLOCK_RE = re.compile(
    r'-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----\s*(.*?)\s*-----END \1-----',
    re.DOTALL,
)
_PGP_BLOCK_RE = re.compile(
    r'-----BEGIN PGP PRIVATE KEY BLOCK-----\s*(.*?)\s*-----END PGP PRIVATE KEY BLOCK-----',
    re.DOTALL,
)
_SSH_PUB_RE = re.compile(r'\bssh-(?:rsa|ed25519|dss) [A-Za-z0-9+/=]{50,}(?: \S+)?')

_ENCRYPTED_MARKERS = ("ENCRYPTED", "Proc-Type: 4,ENCRYPTED", "DEK-Info")


# ── Parser DER mínimo (TLV) ────────────────────────────────────────────────────

def _parse_der_length(data: bytes, offset: int) -> Tuple[int, int]:
    """Retorna (length, novo_offset) para o campo de comprimento DER em offset."""
    first = data[offset]
    if first & 0x80 == 0:
        return first, offset + 1
    num_bytes = first & 0x7F
    length = int.from_bytes(data[offset + 1: offset + 1 + num_bytes], "big")
    return length, offset + 1 + num_bytes


def _parse_der_tlv(data: bytes, offset: int = 0) -> Optional[Tuple[int, bytes, int]]:
    """Retorna (tag, value_bytes, next_offset) do primeiro TLV a partir de offset."""
    if offset >= len(data):
        return None
    tag = data[offset]
    try:
        length, value_start = _parse_der_length(data, offset + 1)
    except (IndexError, ValueError):
        return None
    value_end = value_start + length
    if value_end > len(data):
        return None
    return tag, data[value_start:value_end], value_end


def _der_int_bit_length(value: bytes) -> int:
    """Tamanho em bits de um INTEGER DER (ignora zero-padding de sinal)."""
    v = value.lstrip(b"\x00")
    if not v:
        return 0
    return (len(v) - 1) * 8 + (8 - (bin(v[0])[2:].zfill(8).find("1") if v[0] else 8))


def analyze_der_structure(der_bytes: bytes) -> Tuple[bool, Optional[int]]:
    """Valida que der_bytes começa com uma SEQUENCE (tag 0x30) bem formada e,
    se for uma chave RSA (primeiro INTEGER pequeno = versão, segundo INTEGER
    grande = módulo), estima o tamanho em bits do módulo."""
    top = _parse_der_tlv(der_bytes, 0)
    if top is None:
        return False, None
    tag, value, _ = top
    if tag != 0x30:  # SEQUENCE
        return False, None

    # Tenta navegar como RSAPrivateKey: SEQUENCE { version INTEGER, n INTEGER, ... }
    inner_offset = 0
    ints_found: List[bytes] = []
    while True:
        item = _parse_der_tlv(value, inner_offset)
        if item is None:
            break
        itag, ivalue, inext = item
        if itag == 0x02:  # INTEGER
            ints_found.append(ivalue)
        inner_offset = inext
        if len(ints_found) >= 2:
            break

    bits = None
    if len(ints_found) >= 2:
        modulus_candidate = ints_found[1]
        bit_len = _der_int_bit_length(modulus_candidate)
        if bit_len >= 512:  # descarta o 'version' int pequeno sendo lido como módulo
            bits = bit_len

    return True, bits


# ── Extração e classificação ───────────────────────────────────────────────────

def _key_type_from_header(header: str) -> str:
    h = header.upper()
    if "RSA" in h:
        return "RSA"
    if "EC" in h and "ENCRYPTED" not in h.split():
        return "EC"
    if "OPENSSH" in h:
        return "OPENSSH"
    if "DSA" in h:
        return "DSA"
    if h.strip() == "PRIVATE KEY":
        return "PKCS8 (RSA/EC/Ed25519 genérico)"
    return "UNKNOWN"


def scan_key_material(file_path: str, content: str) -> List[KeyFinding]:
    findings: List[KeyFinding] = []

    for m in _PEM_BLOCK_RE.finditer(content):
        header = m.group(1)
        body = m.group(2)
        line_number = content[:m.start()].count("\n") + 1
        is_encrypted = any(marker in body or marker in m.group(0) for marker in _ENCRYPTED_MARKERS)

        b64_clean = re.sub(r'\s+', '', body)
        # Remove possíveis linhas de cabeçalho de criptografia (Proc-Type/DEK-Info)
        b64_clean = re.sub(r'(?:Proc-Type|DEK-Info)[^,]*,[^\n]*', '', b64_clean)

        valid_der = False
        bits = None
        if not is_encrypted and header != "OPENSSH PRIVATE KEY":
            try:
                der_bytes = base64.b64decode(b64_clean, validate=False)
                valid_der, bits = analyze_der_structure(der_bytes)
            except Exception:
                valid_der = False
        elif header == "OPENSSH PRIVATE KEY":
            # Formato OpenSSH tem magic "openssh-key-v1" em vez de DER puro
            try:
                der_bytes = base64.b64decode(b64_clean, validate=False)
                valid_der = der_bytes.startswith(b"openssh-key-v1\x00")
            except Exception:
                valid_der = False

        findings.append(KeyFinding(
            file_path=file_path, line_number=line_number,
            key_type=_key_type_from_header(header),
            is_encrypted=is_encrypted, bits=bits, valid_der=valid_der,
            header=header,
        ))

    for m in _PGP_BLOCK_RE.finditer(content):
        line_number = content[:m.start()].count("\n") + 1
        findings.append(KeyFinding(
            file_path=file_path, line_number=line_number, key_type="PGP",
            is_encrypted=("ENCRYPTED" in m.group(1).upper()), bits=None,
            valid_der=True,  # PGP usa OpenPGP packet format, não DER — assume presente
            header="PGP PRIVATE KEY BLOCK",
        ))

    return findings


def scan_ssh_public_keys(file_path: str, content: str) -> List[KeyFinding]:
    """Chaves públicas SSH não são segredo, mas sua presença pode indicar
    'authorized_keys' versionado indevidamente ou testar pareamento com a
    chave privada correspondente."""
    findings = []
    for m in _SSH_PUB_RE.finditer(content):
        line_number = content[:m.start()].count("\n") + 1
        findings.append(KeyFinding(
            file_path=file_path, line_number=line_number, key_type="SSH_PUBLIC",
            is_encrypted=False, bits=None, valid_der=True, header="SSH PUBLIC KEY",
        ))
    return findings
